# openxvpn

[![Actions Status](https://github.com/pilotso11/openxvpn/actions/workflows/docker.yml/badge.svg)](https://github.com/pilotso11/openxvpn/actions/workflows/docker.yml)
[![Docker Build](https://img.shields.io/docker/cloud/build/pilotso11/openxvpn?style=flat-square)](https://hub.docker.com/r/pilotso11/openxvpn/builds)
[![Docker Pulls](https://img.shields.io/docker/pulls/pilotso11/openxvpn?style=flat-square)](https://hub.docker.com/r/pilotso11/openxvpn)
[![MIT License](https://img.shields.io/github/license/pilotso11/openxvpn?style=flat-square)](./LICENSE)

A lightweight Docker image for running OpenVPN with ExpressVPN configuration, designed to proxy other services securely and easily. Ideal for scenarios where you want to route containerized applications through a VPN tunnel with minimal setup.

---

## Features

- **ExpressVPN Support**: Use your own ExpressVPN credentials and configuration files.
- **Docker-First**: Built for seamless integration with Docker Compose and containerized workflows.
- **Network Proxying**: Easily route other containers' traffic through the VPN.
- **Status Web UI**: Real-time VPN status and IP info available on port 80.
- **Healthchecks**: Automated health monitoring for reliable service orchestration.

---

## Prerequisites

- Docker and Docker Compose installed on your host.
- Valid ExpressVPN account credentials.
- One or more ExpressVPN `.ovpn` configuration files (provided in `openxvpn/expressvpn/` or your own).

---

## Installation

1. **Clone this repository** (or pull the image directly from Docker Hub):

   ```sh
   git clone https://github.com/pilotso11/openxvpn.git
   cd openxvpn
   ```

2. **(Optional) Add your own ExpressVPN config files**
   Place your `.ovpn` files in the `expressvpn/` directory if you want to use custom servers.

---

## Usage

### Docker Compose Example

Below is a sample `docker-compose.yml` to run `openxvpn` and proxy another service through the VPN:

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
      - OPEN_VPN_USER=your_expressvpn_username
      - OPEN_VPN_PASSWORD=your_expressvpn_password
      # - SERVER=sydney   # Optional: partial match for preferred server config file
      # - LAN=192.168.2.0/24  # Optional: your local network CIDR
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    privileged: true
    ports:
      - "8000:80"   # VPN Status Web UI
      - "9000:9000" # Example: another service port

  another_service:
    image: your/image
    network_mode: "service:xvpn"
    depends_on:
      xvpn:
        condition: service_healthy
```

- **Access the VPN status page:** [http://localhost:8000](http://localhost:8000)

---

## Environment Variables

| Variable           | Required | Description                                                                 |
|--------------------|----------|-----------------------------------------------------------------------------|
| `OPEN_VPN_USER`    | Yes      | Your ExpressVPN username                                                    |
| `OPEN_VPN_PASSWORD`| Yes      | Your ExpressVPN password                                                    |
| `SERVER`           | No       | Partial string to select a specific `.ovpn` config (e.g., `sydney`, `usa`)  |
| `LAN`              | No       | Local network CIDR to keep accessible (default: `192.168.2.0/24`)           |

---

## Health & Status

- **Healthcheck:**
  The container uses a healthcheck script to verify that the external IP changes after connecting to the VPN. If the IP does not change, the container is marked unhealthy.
- **Status Web UI:**
  - Served on port 80 inside the container (map to any host port, e.g., `8000:80`).
  - Displays current VPN status, original and VPN IP, and geolocation info.
  - JSON status available at `/status.json`.

---

## How It Works

- On startup, the container:
  1. Verifies VPN credentials.
  2. Selects an `.ovpn` config file (optionally filtered by `SERVER`).
  3. Starts OpenVPN and a lightweight web server for status.
  4. Periodically checks and updates the VPN status and IP info.

- Other containers can use `network_mode: "service:xvpn"` to route all their traffic through the VPN.

---

## Troubleshooting

- **Container is unhealthy:**
  - Check your ExpressVPN credentials.
  - Ensure at least one valid `.ovpn` file is present in `/vpn/config/`.
  - Review logs with `docker logs xvpn`.

- **Cannot access local network:**
  - Adjust the `LAN` environment variable to match your local network.

- **Status page not loading:**
  - Ensure the port mapping (`8000:80`) is correct and not blocked by a firewall.

---

## Contributing

Contributions, issues, and feature requests are welcome!
Feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the [MIT License](./LICENSE).

---

## Credits

- Built by [pilotso11](https://github.com/pilotso11)
- Not affiliated with ExpressVPN.
- Uses [OpenVPN](https://openvpn.net/) and [mini_httpd](https://acme.com/software/mini_httpd/).

---
