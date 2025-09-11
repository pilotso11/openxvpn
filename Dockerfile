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

# Health check using Go implementation health endpoint
HEALTHCHECK --interval=30s --timeout=10s \
    --start-period=10s --retries=3 CMD [ "curl", "-f", "http://localhost/health" ]

# Run Go implementation
ENTRYPOINT [ "/vpn/openxvpn" ]

# ============================================================================
# USAGE:
# ============================================================================
#
# Build the image:
#   docker build -t openxvpn .
#
# Run with environment variables:
#   docker run --cap-add=NET_ADMIN --device=/dev/net/tun:/dev/net/tun --privileged \
#     -e OPEN_VPN_USER=your_user -e OPEN_VPN_PASSWORD=your_pass \
#     -e IP2LOCATION_IO_KEY=your_api_key \
#     -p 8080:80 openxvpn
#
# Run with API key from file:
#   docker run --cap-add=NET_ADMIN --device=/dev/net/tun:/dev/net/tun --privileged \
#     -e OPEN_VPN_USER=your_user -e OPEN_VPN_PASSWORD=your_pass \
#     -v ./ip2location.key:/config/ip2location.key:ro \
#     -e IP2LOCATION_IO_KEY_FILE=/config/ip2location.key \
#     -p 8080:80 openxvpn
#
# Docker Compose:
#   services:
#     xvpn:
#       image: openxvpn
#       cap_add:
#         - NET_ADMIN
#       devices:
#         - /dev/net/tun:/dev/net/tun
#       privileged: true
#       environment:
#         - OPEN_VPN_USER=your_user
#         - OPEN_VPN_PASSWORD=your_pass
#         - IP2LOCATION_IO_KEY=your_api_key
#       ports:
#         - "8080:80"
#
# API ENDPOINTS:
#   - /health - Health check endpoint
#   - /api/v1/status - Detailed VPN status
#   - /api/v1/reconnect - Restart VPN connection
#   - / - Web dashboard
#   - /status - Legacy status endpoint (backward compatibility)
#
# ============================================================================
