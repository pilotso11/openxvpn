FROM alpine:latest

LABEL maintainer="pilotso11"
LABEL org.opencontainers.image.source="https://github.com/pilotso11/openxvpn"
LABEL description="Lightweight OpenVPN + ExpressVPN Docker image for proxying other services"

RUN apk add --update --no-cache openvpn bash curl mini_httpd \
    && mkdir -p /vpn/config /vpn/templates /vpn/web

WORKDIR /vpn

# Copy ExpressVPN config files
COPY expressvpn/ /vpn/config/
# Copy scripts and ensure they are executable
COPY scripts/ /vpn/
RUN chmod +x /vpn/*.sh
# Copy web templates
COPY web/ /vpn/templates/

# Environment variables (set at runtime)
ENV OPEN_VPN_USER=""
ENV OPEN_VPN_PASSWORD=""
ENV OPEN_VPN_USER_PASS_PATH=""
ENV SERVER=""
ENV LAN="192.168.0.0/16"
ENV IP2LOCATION_IO_KEY=""

# Expose status web UI port (mapped to host as needed)
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=10s \
    --start-period=5s --retries=3 CMD [ "/bin/bash", "/vpn/check.sh" ]

ENTRYPOINT [ "/bin/bash", "/vpn/vpn.sh" ]
