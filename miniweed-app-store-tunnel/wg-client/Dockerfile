FROM alpine:3.19

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    ip6tables \
    iproute2 \
    bash \
    python3

COPY entrypoint.sh /entrypoint.sh
COPY wg-api.py /wg-api.py
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
