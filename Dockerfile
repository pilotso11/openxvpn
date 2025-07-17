FROM alpine:latest

RUN apk add --update --no-cache openvpn bash curl mini_httpd

ARG TARGETPLATFORM
RUN echo "Building for ${TARGETPLATFORM}"

# ExpressVPN user credentials.
ENV OPEN_VPN_USER=""
ENV OPEN_VPN_PASSWORD=""

# Preferred ExpressVPN Server.  Used to pick the configuration file via a glob expression.
ENV SERVER=""

# Local network cidr
ENV LAN="192.168.2.0/24"

WORKDIR /vpn
RUN mkdir -p /vpn/config
RUN mkdir -p /vpn/templates
RUN mkdir -p /vpn/web
COPY ./expressvpn/*.ovpn /vpn/config/
COPY scripts/*.sh /vpn/
COPY web/* /vpn/templates/

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=10s \
    --start-period=5s --retries=3 CMD [ "/bin/bash", "/vpn/check.sh" ]

ENTRYPOINT [ "/bin/bash", "/vpn/vpn.sh" ]
