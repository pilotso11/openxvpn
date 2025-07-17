# openxvpn
Very lightweight OpenVPN with Express VPN Docker Image for proxying other services.

## Usage

Use this image with docker compose.
Status is reported on port 80 of the container.

To allow other containers to use the VPN, add the following to your docker-compose.yml:

```yaml
networks:
  vpn:
    external: true

services:
  xvpn:
    image: pilotso11/openxvpn
    container_name: xvpn
    networks:
      - vpn
    restart: unless-stopped
    environment:
      - OPEN_VPN_USER=[your user]
      - OPEN_VPN_PASSWORD=[your password]
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    privileged: true
    ports:
      - "8000:80"   # VPN Status
      - "9000:9000" # Aother service - exposed here because it uses the VPN service as its network.

  another_service:
    network_mode: "service:xvpn"
    depends_on:
      xvpn:
        condition: service_healthy  # only start with healthy VPN
        restart: true
```
