# docker-dynamic-dns
DNS server written in python.

It can be used to resolve IP addresses of the containers running in your docker instance.

It can also run in a container.

Uses the fantastic library [dnslib](https://github.com/paulc/dnslib).

While searching for an existing project my requirement, I came across [this DNS server project](https://github.com/samuelcolvin/dnserver), which proved to be very helpful and I also liked the idea of using a zones file for some static data.

## Features ##
* Uses docker events during run-time to make sure the list of containers and their IP addresses is up-to-date.
* Forwards DNS request to upstream DNS server if a request cannot be served locally
* User defined port
* Can be run in docker container and configured using enviornment variables

## Usage ##

```
usage: docker-dynamic-dns.py [-h] [--tcp-port TCP_PORT] [--udp-port UDP_PORT] [--upstream-dns-server UPSTREAM_DNS_SERVER]
                             [--zones-file ZONES_FILE] [--docker-socket DOCKER_SOCKET] [--domain DOMAIN]

DNS Server to help resolving IP addresses of docker containers

optional arguments:
  -h, --help            show this help message and exit
  --tcp-port TCP_PORT   Listen to TCP connections on specified port. 0 to disable. (default: 0)
  --udp-port UDP_PORT   Listen to UDP datagrams on specified port. 0 to disable. (default: 53)
  --upstream-dns-server UPSTREAM_DNS_SERVER
                        Upstream DNS server. (default: 8.8.8.8)
  --zones-file ZONES_FILE
                        File containing list of DNS zones. Disabled if no file provided. (default: None)
  --docker-socket DOCKER_SOCKET
                        Docker socket for getting events. (default: unix://var/run/docker.sock)
  --domain DOMAIN       Local domain. (default: None)

```

## Docker ##
### Environment variables ###
Following environment variables can be set to eliminate passing values via command-line parameters
* TCP_PORT
* UDP_PORT
* UPSTREAM_DNS
* ZONES_FILE
* DOCKER_SOCKET
* DOMAIN

### Docker-compose ###
Sample docker-compose file is provided. it can be tested by running following command in the directory where the docker-compose.yml is located.
Be default port 53 is used. You might need to change it if you are already running another DNS server locally.
```
docker-compose up
```

Then you can try following commands to see if it is working
```
dig @127.0.0.1 -t a example.com
dig @127.0.0.1 -t txt example.com
```

The above commands should show the DNS responses taken from the sample file.

