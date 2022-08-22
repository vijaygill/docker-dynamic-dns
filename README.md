# docker-dynamic-dns
DNS server written in python.

It can be used to resolve IP addresses of the containers running in your docker instance.

It can also run in a container.

Uses the fantastic library [dnslib](https://github.com/paulc/dnslib).

Some ideas were taken from [this DNS server project](https://github.com/samuelcolvin/dnserver), especially around reading static IP addresses from a file.

It uses docker events during run-time to make sure the list of containers and their IP addresses is up-to-date.



