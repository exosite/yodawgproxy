FROM alpine:latest

MAINTAINER Alex Wauck "alexwauck@exosite.com"
EXPOSE 8080

ENV GIN_MODE release

RUN apk add --no-cache curl

COPY build/linux-amd64/yodawgproxy /usr/bin/yodawgproxy
RUN chmod 0755 /usr/bin/yodawgproxy

CMD ["/usr/bin/yodawgproxy", "--config", "/etc/yodawgproxy/config.yaml"]
