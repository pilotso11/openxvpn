FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go module files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY pkg/ ./pkg/
COPY main.go ./

# Build the Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o openxvpn .

# Final stage
FROM alpine:latest

LABEL maintainer="pilotso11"
LABEL org.opencontainers.image.source="https://github.com/pilotso11/openxvpn"
LABEL description="Lightweight OpenVPN + ExpressVPN Docker image for proxying other services"

# Install required packages
RUN apk add --update --no-cache openvpn bash curl mini_httpd \
    && mkdir -p /vpn/config /vpn/templates /vpn/web

WORKDIR /vpn

# Copy the Go binary from builder stage
COPY --from=builder /app/openxvpn /vpn/openxvpn

# Copy ExpressVPN config files
COPY expressvpn/ /vpn/config/

# Copy shell scripts (for fallback mode)
COPY scripts/ /vpn/scripts/
RUN chmod +x /vpn/scripts/*.sh

# Copy web templates (for shell script compatibility)
COPY web/ /vpn/templates/

# Copy Go configuration
COPY config.yaml /vpn/config.yaml

# Environment variables (set at runtime)
ENV OPEN_VPN_USER=""
ENV OPEN_VPN_PASSWORD=""
ENV OPEN_VPN_USER_PASS_PATH=""
ENV SERVER=""
ENV LAN="192.168.0.0/16"
ENV IP2LOCATION_IO_KEY=""
ENV IP2LOCATION_IO_KEY_FILE=""

# Expose status web UI port
EXPOSE 80

# Health check - curl to health endpoint (works for Go mode, shell mode needs override)
HEALTHCHECK --interval=30s --timeout=10s \
    --start-period=10s --retries=3 CMD [ "curl", "-f", "http://localhost/health" ]

# Default to Go implementation
ENTRYPOINT [ "/vpn/openxvpn" ]

# ============================================================================
# USAGE - How to switch between implementations:
# ============================================================================
#
# Build the image (includes both implementations):
#   docker build -t openxvpn .
#
# 1. RUN WITH GO IMPLEMENTATION (default):
#   docker run --cap-add=NET_ADMIN --device=/dev/net/tun:/dev/net/tun --privileged \
#     -e OPEN_VPN_USER=your_user -e OPEN_VPN_PASSWORD=your_pass \
#     -e IP2LOCATION_IO_KEY=your_api_key \
#     -p 8080:80 openxvpn
#
#   Or with API key from file:
#   docker run --cap-add=NET_ADMIN --device=/dev/net/tun:/dev/net/tun --privileged \
#     -e OPEN_VPN_USER=your_user -e OPEN_VPN_PASSWORD=your_pass \
#     -v ./ip2location.key:/config/ip2location.key:ro \
#     -e IP2LOCATION_IO_KEY_FILE=/config/ip2location.key \
#     -p 8080:80 openxvpn
#
# 2. RUN WITH SHELL IMPLEMENTATION (override entrypoint):
#   docker run --cap-add=NET_ADMIN --device=/dev/net/tun:/dev/net/tun --privileged \
#     --entrypoint "/bin/bash" \
#     --health-cmd="/vpn/scripts/check.sh" \
#     -e OPEN_VPN_USER=your_user -e OPEN_VPN_PASSWORD=your_pass \
#     -p 8080:80 openxvpn /vpn/scripts/vpn.sh
#
# 3. DOCKER COMPOSE - Go implementation:
#   services:
#     xvpn:
#       image: openxvpn
#       # Uses default entrypoint (/vpn/openxvpn)
#
# 4. DOCKER COMPOSE - Shell implementation:
#   services:
#     xvpn:
#       image: openxvpn
#       entrypoint: ["/bin/bash", "/vpn/scripts/vpn.sh"]
#       healthcheck:
#         test: ["/vpn/scripts/check.sh"]
#
# 5. HEALTH CHECKS:
#   - Go mode: curl http://localhost/health (default healthcheck)
#   - Shell mode: Override healthcheck to use /vpn/scripts/check.sh
#   - Both modes: Compatible with existing /status endpoints
#
# 6. API ENDPOINTS:
#   - Go mode: /health, /api/v1/status, /api/v1/reconnect, /
#   - Shell mode: /status.json, / (via mini_httpd + templates)
#   - Both modes: Backward compatible status endpoints
#
# ============================================================================