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

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

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

class Record:
    def __init__(self, rr):
        self.rr = rr
        self.rname = str(rr.rname)
        self.rtype = QTYPE.get(rr.rtype)
        self._rname = rr.rname
        self._rtype = rr.rtype

    def match(self, q):
        return q.qname == self._rname and (q.qtype == QTYPE.ANY or q.qtype == self._rtype)

    def sub_match(self, q):
        return self._rtype == QTYPE.SOA and q.qname.matchSuffix(self._rname)

    def __str__(self):
        return "{0}[{1}] - {2}".format(self.rname, self.rtype, self.rr) 


class Resolver(ProxyResolver):
    def __init__(self, domains, upstream, docker_socket, zones_file = None):
        super().__init__(upstream, 53, 5)
        self.dns_table = []
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
            records = list(sorted(records, key=lambda x: x.rname))
            self.dns_table = []
            self.dns_table.extend(records)
            max_col_len = max([ len(x.rname) for x in records])
            log_fmt="{0:<" + str(max_col_len) + "} {1:<6} {2}"
            for rec in records:
                logger.info(log_fmt.format(rec.rname, rec.rtype, rec.rr))
            logger.info("zone resource records generated: {0}.".format(len(records)))
            logger.info("local dns table has {0} entries.".format(len(self.dns_table)))

    def needs_update(self):
        res = False
        if self.zones_file:
            if self.last_load_time_zones:
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(self.zones_file))
                res = mtime > self.last_load_time_zones
                if res:
                    logger.info("Zones file changed since {0}. Records need to be updated.".format(self.last_load_time_zones))
        else:
            res = True
            logger.info("Zones file was never loaded. Records need to be updated.")

        if self.last_load_time_docker:
            docker_events = self.docker_client.events(decode = True, since = self.last_load_time_docker)
            for docker_event in docker_events:
                if docker_event["Action"] == "start":
                    res = True
                    break
                if docker_event["Action"] == "stop":
                    res = True
                    break
            if res:
                logger.info("Data from docker changed since {0}. Records need to be updated.".format(self.last_load_time_docker))
        else:
            res = True
            logger.info("Data from docker was never fetched. Records need to be updated.")
        return res

    def create_record(self, source, zone_line):
        res = None
        try:
            rrs = RR.fromZone(zone_line)
            res = Record(rrs[0])
        except Exception as e:
            logger.error("{0}: error in zone line {1}: {2}".format(e.__class__.__name__, zone_line, e))
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

        try:
            reply = request.reply()
            matches = list(filter(lambda rec: rec.match(request.q) or rec.sub_match(request.q) , self.dns_table))
            if matches:
                for record in matches:
                    reply.add_answer(record.rr)
                logger.info("{0}[{1}]: resolved from local dns table.".format(request.q.qname, type_name))
                return reply
        except:
            pass
        
        upstream_data = super().resolve(request, handler)
        logger.info("{0}[{1}]: resolved from upstream DNS server".format(request.q.qname, type_name))
        return upstream_data


class DNSHandlerWithoutLogger(socketserver.BaseRequestHandler):
    udplen = 0                  # Max udp packet length (0 = ignore)

    def handle(self):
        if self.server.socket_type == socket.SOCK_STREAM:
            self.protocol = 'tcp'
            data = self.request.recv(8192)
            if len(data) < 2:
                return
            length = struct.unpack("!H",bytes(data[:2]))[0]
            while len(data) - 2 < length:
                new_data = self.request.recv(8192)
                if not new_data:
                    break
                data += new_data
            data = data[2:]
        else:
            self.protocol = 'udp'
            data,connection = self.request

        try:
            rdata = self.get_reply(data)

            if self.protocol == 'tcp':
                rdata = struct.pack("!H",len(rdata)) + rdata
                self.request.sendall(rdata)
            else:
                connection.sendto(rdata,self.client_address)

        except DNSError as e:
            logger.log_error("{0}".format(e))

    def get_reply(self,data):
        request = DNSRecord.parse(data)

        resolver = self.server.resolver
        reply = resolver.resolve(request,self)

        if self.protocol == 'udp':
            rdata = reply.pack()
            if self.udplen and len(rdata) > self.udplen:
                truncated_reply = reply.truncate()
                rdata = truncated_reply.pack()
        else:
            rdata = reply.pack()

        return rdata

def handle_sig(signum, frame):
    logger.info("pid={0}, got signal: {1}, stopping...".format(os.getpid(), signal.Signals(signum).name))
    exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_sig)

    parser = argparse.ArgumentParser(description = "DNS Server to help resolving IP addresses of docker containers", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--tcp-port", default = os.getenv("TCP_PORT", 0), help="Listen to TCP connections on specified port. 0 to disable.", type = int)
    parser.add_argument("--udp-port", default = os.getenv("UDP_PORT", 53),  help="Listen to UDP datagrams on specified port. 0 to disable.", type = int )
    parser.add_argument("--upstream-dns-server", default = os.getenv("UPSTREAM_DNS_SERVER", "8.8.8.8"), help = "Upstream DNS server.")
    parser.add_argument("--zones-file", default = os.getenv("ZONES_FILE", None), help = "File containing list of DNS zones. Disabled if no file provided.")
    parser.add_argument("--docker-socket", default = os.getenv("DOCKER_SOCKET", "unix://var/run/docker.sock" ), help = "Docker socket for getting events.")
    parser.add_argument("--domain", default = os.getenv("DOMAIN", None), help = "Local domain.")

    args = parser.parse_args()

    if ((args.tcp_port == 0) and (args.udp_port == 0)):
        parser.error("Please select at least one of --udp or --tcp.")

    domains = []
    if args.domain:
        domains.append(args.domain)
    resolver = Resolver(domains, args.upstream_dns_server, args.docker_socket, args.zones_file)


    servers = []
    if args.udp_port > 0:
        logger.info("Starting DNS server on port {0} (UDP).".format(args.udp_port))
        servers.append(DNSServer(resolver, port = args.udp_port, handler = DNSHandlerWithoutLogger))
    if args.tcp_port > 0:
        logger.info("Starting DNS server on port {0} (TCP).".format(args.tcp))
        servers.append(DNSServer(resolver, port = args.tcp_port, tcp = True, handler = DNSHandlerWithoutLogger))

    logger.info("Upstream DNS server {0}".format(args.upstream_dns_server))
    
    if servers:
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

