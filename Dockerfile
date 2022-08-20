FROM python:latest

RUN pip3 install --no-cache-dir dnslib docker

RUN mkdir /app /config

COPY app/* /app/

RUN chmod +x /app/docker-dynamic-dns.py

VOLUME /config

WORKDIR /app

CMD [ "/app/docker-dynamic-dns.py" ]
