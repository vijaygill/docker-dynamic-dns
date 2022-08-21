#!/usr/bin/env python3

import json
import logging
import os
import signal
import datetime
from pathlib import Path
from textwrap import wrap
import time
import socket

from dnslib import DNSLabel, QTYPE, RR, dns, DNSRecord
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer, DNSHandler

import argparse
import docker
import csv
import threading
import copy

lock = threading.Lock()

SERIAL_NO = int((datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)).total_seconds())

log_handler = logging.StreamHandler()
log_handler.setLevel(logging.INFO)
log_handler.setFormatter(logging.Formatter("%(asctime)s: %(message)s", datefmt="%H:%M:%S"))

logger = logging.getLogger(__name__)
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)

TYPE_LOOKUP = {
    "A": (dns.A, QTYPE.A),
    "AAAA": (dns.AAAA, QTYPE.AAAA),
    "CAA": (dns.CAA, QTYPE.CAA),
    "CNAME": (dns.CNAME, QTYPE.CNAME),
    "DNSKEY": (dns.DNSKEY, QTYPE.DNSKEY),
    "MX": (dns.MX, QTYPE.MX),
    "NAPTR": (dns.NAPTR, QTYPE.NAPTR),
    "NS": (dns.NS, QTYPE.NS),
    "PTR": (dns.PTR, QTYPE.PTR),
    "RRSIG": (dns.RRSIG, QTYPE.RRSIG),
    "SOA": (dns.SOA, QTYPE.SOA),
    "SRV": (dns.SRV, QTYPE.SRV),
    "TXT": (dns.TXT, QTYPE.TXT),
    "SPF": (dns.TXT, QTYPE.TXT),
}

class Record:
    def __init__(self, rr):
        self.rr = rr
        self._rname = rr.rname
        self.rname = str(rr.rname)

        rtype = QTYPE.get(rr.rtype)

        rd_cls, self._rtype = TYPE_LOOKUP[rtype]


    def match(self, q):
        return q.qname == self._rname and (q.qtype == QTYPE.ANY or q.qtype == self._rtype)

    def sub_match(self, q):
        return self._rtype == QTYPE.SOA and q.qname.matchSuffix(self._rname)

    def __str__(self):
        return "{0}[{1}] - {2}".format(self._rname, self._rtype, self.rr) 


class Resolver(ProxyResolver):
    def __init__(self, domains, upstream, docker_socket, zones_file = None):
        super().__init__(upstream, 53, 5)
        self.records = {}
        self.docker_socket = None
        self.zones_file = None
        self.last_load_time_zones = None
        self.last_load_time_docker = None

        self.domains = domains
        for domain in self.domains:
            logger.info("Local domain: {0}".format(domain))

        if docker_socket:
            logger.info("Docker socket: {0}".format(docker_socket))
            self.docker_socket = docker_socket
            self.docker_client = docker.DockerClient(base_url = docker_socket)
        if zones_file:
            self.zones_file = Path(zones_file)
            logger.info("Zones file: {0}".format(zones_file))

    def load_records(self):
        if not self.needs_update():
            return
        records = []
        if self.zones_file:
            dt, recs = self.load_zones()
            if recs:
                records.extend(recs)
                self.last_load_time_zones = dt
        
        if self.docker_socket:
            dt, recs = self.load_docker_ips()
            if recs:
                records.extend(recs)
                self.last_load_time_docker = dt
        
        if records:
            for rec in records:
                self.records[rec.rname] = rec
                logger.info("{0}".format(rec))
            logger.info("{0} zone resource records generated.".format(len(self.records)))

    def create_record(self, source, zone_line):
        res = None
        try:
            ttl = 300
            rrs = RR.fromZone(zone_line)
            res = Record(rrs[0])
            logger.debug("{0}: {1} - {2}".format(source, len(self.records), res))
        except Exception as e:
            logger.error("{0}: name: {1} ip_address: {2} -> {3}".format(e.__class__.__name__, name, ip_address, e))
        return res

    def needs_update(self):
        res = False
        if self.zones_file:
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(self.zones_file))
            res = res or (self.last_load_time_zones is None) or (mtime > self.last_load_time_zones)
            if res:
                logger.info("Zones file changed since {0}. Records need to be updated.".format(self.last_load_time_zones))

        has_docker_events = False
        if self.last_load_time_docker:
            docker_events = self.docker_client.events(decode = True, since = self.last_load_time_docker)
            for docker_event in docker_events:
                if docker_event["Action"] == "start":
                    has_docker_events = True
                    break
                if docker_event["Action"] == "stop":
                    has_docker_events = True
                    break
        
        res = res or (self.last_load_time_docker is None) or ( has_docker_events )
        if res:
            logger.info("Docker events changed since {0}. Records need to be updated.".format(self.last_load_time_docker))
        return res

    def zone_lines(self):
        current_line = ''
        for line in open(self.zones_file, "r"):
            if line.startswith('#'):
                continue
            line = line.rstrip('\r\n\t ')
            if not line.startswith(' ') and current_line:
                yield current_line
                current_line = ''
            current_line += line.lstrip('\r\n\t ')
        if current_line:
            yield current_line
        
    def load_zones(self):
        assert self.zones_file.exists(), "file {0} does not exist".format(self.zones_file)
        logger.info("Loading zones data from file - {0}".format(self.zones_file))
        res = []

        for zone_line in self.zone_lines():
            try:
                rec = self.create_record("file", zone_line)
                if rec:
                    res.append(rec)
            except Exception as e:
                logger.error("{0}: {1}".format(e.__class__.__name__, e))
                pass
        records_time = datetime.datetime.utcnow()
        return (records_time, res)

    def load_docker_ips(self):
        res = []
        logger.info("Loading ip addresses docker client - {0}".format(self.docker_socket))
        for container in self.docker_client.containers.list():
            name = container.name
            hostname = container.attrs["Config"]["Hostname"]
            networkmode = container.attrs["HostConfig"]["NetworkMode"]
            if networkmode == "default":
                continue
            ip_address = container.attrs["NetworkSettings"]["Networks"][networkmode]["IPAddress"]
            if ip_address:
                #logger.info("{0:<30} {1:<30} - {2:<18}".format(name + ":" + networkmode, hostname, ip_address))
                names = []
                names += [ name ] 
                names += [ name + "." + x for x in self.domains]
                for name in names:
                    try:
                        zone_line = "{0} 300 IN A {1}".format(name, ip_address)
                        rec = self.create_record("docker", zone_line)
                        if rec:
                            res.append(rec)
                    except Exception as e:
                        logger.error("{0}: {1}".format(e.__class__.__name__, e))
                        pass
        records_time = datetime.datetime.utcnow()
        return (records_time, res)

    def resolve(self, request, handler):
        rname = str(request.q.qname)
        type_name = QTYPE[request.q.qtype]
        reply = request.reply()

        if rname in self.records.keys():
            record = self.records[rname]
            reply.add_answer(record.rr)
            logger.info("***** {0}[{1}]: resolved data ({2} replies).".format(request.q.qname, type_name, len(reply.rr)))
            return reply
        
        upstream_data = super().resolve(request, handler)
        logger.info("***** {0}[{1}]: upstream data: {2}.".format(request.q.qname, type_name, upstream_data))
        return upstream_data

def handle_sig(signum, frame):
    logger.info("pid={0}, got signal: {1}, stopping...".format(os.getpid(), signal.Signals(signum).name))
    exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_sig)

    parser = argparse.ArgumentParser(description = "DNS Server to help resolving IP addresses of docker containers")
    parser.add_argument("--tcp", default = os.getenv("TCP_PORT",0), help="Listen to TCP connections on specified port.", type = int)
    parser.add_argument("--udp", default = os.getenv("UDP_PORT",0),  help="Listen to UDP datagrams on specified port.", type = int )
    parser.add_argument("--upstream", default = os.getenv("UPSTREAM_DNS", "8.8.8.8"), help = "Upstream DNS server.")
    parser.add_argument("--zones-file", default = os.getenv("ZONES_FILE", None), help = "File containing list of DNS zones.")
    parser.add_argument("--docker-socket", default = os.getenv("DOCKER_SOCKET", "unix://var/run/docker.sock" ), help = "Docker socket for getting events.")
    parser.add_argument("--domain", default = os.getenv("DOMAIN", None), help = "Local domain.")

    args = parser.parse_args()

    if ((args.tcp == 0) and (args.udp == 0)):
        parser.error("Please select at least one of --udp or --tcp.")

    domains = []
    if args.domain:
        domains.append(args.domain)
    resolver = Resolver(domains, args.upstream, args.docker_socket, args.zones_file)


    servers = []
    if args.udp > 0:
        logger.info("Starting DNS server on port {0} (UDP).".format(args.udp))
        servers.append(DNSServer(resolver, port = args.udp))
    if args.tcp > 0:
        logger.info("Starting DNS server on port {0} (TCP).".format(args.tcp))
        servers.append(DNSServer(resolver, port = args.tcp, tcp = True))

    logger.info("Upstream DNS server {0}".format(args.upstream))
    

    if servers:
        resolver.load_records()
        
        for server in servers:
            server.start_thread()
        
        try:
            while True:
                for server in servers:
                    if not server.isAlive():
                        break
                resolver.load_records()
                time.sleep(1)
        except KeyboardInterrupt:
            pass

