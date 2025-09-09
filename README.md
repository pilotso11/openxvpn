# openxvpn

![go](https://github.com/pilotso11/openxvpn/actions/workflows/go.yml/badge.svg)
![docker](https://github.com/pilotso11/openxvpn/actions/workflows/docker.yml/badge.svg)
![Coverage](https://img.shields.io/badge/Coverage-88.8%25-brightgreen)
[![MIT License](https://img.shields.io/github/license/pilotso11/openxvpn?style=flat-square)](./LICENSE)

A lightweight Docker image for running OpenVPN with ExpressVPN configuration, designed to proxy other services securely and easily. Now available in **two implementations**: the original shell scripts and a new Go implementation with enhanced monitoring, speed testing, and comprehensive API capabilities.

---

## ✨ New: Dual Implementation Support

Choose between two implementations based on your needs:

| Feature | Shell Implementation | **Go Implementation** |
|---------|---------------------|----------------------|
| **Stability** | ✅ Proven, battle-tested | ✅ Enhanced error handling & graceful shutdown |
| **Monitoring** | ✅ Basic health checks | ✅ **Advanced health monitoring with speed tests** |
| **API** | ✅ Simple JSON endpoints | ✅ **Comprehensive REST API** |
| **Logging** | ✅ Standard logs | ✅ **Structured JSON logs with credential redaction** |
| **Recovery** | ✅ Basic restart logic | ✅ **Context-based failure recovery** |
| **Configuration** | ✅ Environment variables | ✅ **YAML + Environment variables** |
| **Authentication** | ❌ No API security | ✅ **Optional API authentication with health endpoint bypass** |
| **Speed Testing** | ❌ Not available | ✅ **6 built-in endpoints with randomization** |

---

## Features

- **ExpressVPN Support**: Use your own ExpressVPN credentials and configuration files.
- **Docker-First**: Built for seamless integration with Docker Compose and containerized workflows.
- **Network Proxying**: Easily route other containers' traffic through the VPN.
- **Status Web UI**: Real-time VPN status and IP info available on port 80.
- **Advanced Health Monitoring**: Configurable health checks with context-based graceful shutdown.
- **Speed Testing**: Built-in bandwidth testing with 6 endpoints and randomization.
- **Secure Logging**: Structured JSON logs with automatic credential redaction.
- **API Security**: Optional authentication with health endpoint bypass for monitoring systems.
- **Dual Mode**: Choose between shell scripts (stable) or Go implementation (enhanced features).

---

## Quick Start

### Default (Go Implementation)
```bash
# With inline API key
docker run --rm -it \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun:/dev/net/tun \
  --privileged \
  -e OPEN_VPN_USER=your_expressvpn_username \
  -e OPEN_VPN_PASSWORD=your_expressvpn_password \
  -e IP2LOCATION_IO_KEY=your_api_key \
  -e LAN=192.168.1.0/24 \
  -p 8080:80 \
  pilotso11/openxvpn

# With API key from file
docker run --rm -it \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun:/dev/net/tun \
  --privileged \
  -e OPEN_VPN_USER=your_expressvpn_username \
  -e OPEN_VPN_PASSWORD=your_expressvpn_password \
  -v ./ip2location.key:/config/ip2location.key:ro \
  -e IP2LOCATION_IO_KEY_FILE=/config/ip2location.key \
  -e LAN=192.168.1.0/24 \
  -p 8080:80 \
  pilotso11/openxvpn
```

### Shell Implementation (Original)
```bash
docker run --rm -it \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun:/dev/net/tun \
  --privileged \
  --entrypoint "/bin/bash" \
  -e OPEN_VPN_USER=your_expressvpn_username \
  -e OPEN_VPN_PASSWORD=your_expressvpn_password \
  -e LAN=192.168.1.0/24 \
  -p 8080:80 \
  pilotso11/openxvpn /vpn/scripts/vpn.sh
```

---

## Docker Compose Examples

### Go Implementation (Default)
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
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    privileged: true
    environment:
      - OPEN_VPN_USER=your_expressvpn_username
      - OPEN_VPN_PASSWORD=your_expressvpn_password
      - LAN=192.168.2.0/24
    ports:
      - "8000:80"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

  another_service:
    image: your/image
    network_mode: "service:xvpn"
    depends_on:
      xvpn:
        condition: service_healthy
```

### Shell Implementation (Original)
```yaml
services:
  xvpn:
    image: pilotso11/openxvpn
    entrypoint: ["/bin/bash", "/vpn/scripts/vpn.sh"]
    # ... rest of configuration same as above
    # Note: Uses default healthcheck (shell script)
```

---

## Environment Variables

| Variable           | Required | Description                                                                 |
|--------------------|----------|-----------------------------------------------------------------------------|
| `OPEN_VPN_USER`    | One-Of      | Your ExpressVPN username                                                    |
| `OPEN_VPN_PASSWORD`| One-Of      | Your ExpressVPN password                                                    |
| `OPEN_VPN_USER_PASS_PATH`| One-Of      | Path to a file containing your ExpressVPN username and password on two lines (e.g., `/path/to/userpass.txt`) |
| `SERVER`           | No          | Partial string to select a specific `.ovpn` config (e.g., `sydney`, `usa`)  |
| `LAN`              | Recommended | Local network CIDR to keep accessible (default: `192.168.0.0/16`)           |
| `IP2LOCATION_IO_KEY` | No        | IP2Location.io API key for geolocation features                             |
| `IP2LOCATION_IO_KEY_FILE` | No   | Path to file containing IP2Location.io API key                              |

---

## API Endpoints

### Go Implementation

#### Health & Status (No Authentication Required)
- **`GET /health`** - Docker health check (returns 200 if VPN connected)
- **`GET /api/v1/status`** - Detailed JSON status with health metrics
- **`GET /status`** - Legacy compatibility endpoint
- **`POST /api/v1/healthcheck`** - Run immediate health check

#### Management (Authentication Required if Enabled)
- **`POST /api/v1/reconnect`** - Force VPN reconnection
- **`GET /api/v1/ipinfo`** - Current IP geolocation information
- **`GET /ip2location.json`** - IP2Location compatibility endpoint
- **`GET /api/v1/cache/stats`** - IP cache statistics
- **`POST /api/v1/cache/clear`** - Clear IP geolocation cache

#### Speed Testing (Authentication Required if Enabled)
- **`POST /api/v1/speedtest`** - Run immediate speed test
- **`GET /api/v1/speedtest/endpoints`** - Available speed test endpoints

#### User Interface
- **`GET /`** - Modern HTML status dashboard

### Shell Implementation (Original)
- **`GET /status.json`** - Simple JSON status
- **`GET /`** - Template-based HTML status page

### Authentication
When API authentication is enabled, health endpoints (`/health`, `/api/v1/status`, `/status`, `/api/v1/healthcheck`) remain accessible without authentication to support monitoring systems and Docker health checks.

---

## Health & Status

### Go Implementation Features
- **Advanced Health Monitoring**: Configurable failure thresholds and context-based recovery
- **Speed Testing**: Built-in bandwidth testing with 6 endpoints (ThinkBroadband, Speedtest.net, OVH, Cachefly, DigitalOcean, Linode)
- **Structured Logging**: JSON logs with credential redaction and component-level detail
- **Graceful Shutdown**: Context-based service termination without explicit Stop() methods
- **Performance Metrics**: Success rates, restart counts, uptime tracking, speed test results

### Enhanced Status Response (Go)
```json
{
  "status": "connected",
  "uptime": "02:34:12",
  "server": "australia-melbourne",
  "network": {
    "current_ip": "192.0.2.1",
    "original_ip": "203.0.113.1"
  },
  "health": {
    "status": "healthy",
    "last_check": "2024-01-15T10:45:00Z",
    "consecutive_fails": 0,
    "success_rate": 99.2,
    "last_speed_test": {
      "endpoint": "ThinkBroadband",
      "test_size": "5MB",
      "speed_mbps": 45.2,
      "success": true,
      "timestamp": "2024-01-15T10:30:00Z"
    }
  },
  "reliability": {
    "restart_count": 1,
    "last_restart": "2024-01-15T08:15:30Z"
  }
}
```

### Shell Implementation (Original)
- **Basic Health Check**: IP verification via external service
- **Simple Status**: Current IP, original IP, timestamp
- **Template System**: Dynamic HTML generation with status updates

---

## Configuration

### Go Implementation (Enhanced)
Create a `config.yaml` file for advanced configuration:

```yaml
vpn:
  provider: "expressvpn"
  server: "australia"  # Optional filter
  timeout: "30s"

health:
  check_interval: "30s"
  timeout: "5s"  # HTTP request timeout
  failure_threshold: 3
  speed_test:
    enabled: true
    interval: "15m"
    test_sizes: ["1MB", "5MB", "10MB"]
    max_duration: "30s"
    randomize_endpoints: true
    selected_endpoints: []  # Empty = use all built-in endpoints

recovery:
  max_retries: 3
  restart_delay: "30s"
  container_exit: true

api:
  listen: ":80"
  auth:
    enabled: false
    token: ""  # API bearer token for authentication

network:
  lan: "192.168.1.0/24"
  ip2location_key: ""  # Set directly or via IP2LOCATION_IO_KEY env var
  ip2location_key_file: ""  # Path to file containing API key
```

Mount as volume: `-v ./config.yaml:/vpn/config.yaml`

### Shell Implementation
Uses environment variables only (original behavior).

---

## Migration Guide

### From Shell to Go Implementation
1. **Test Go mode**: Change entrypoint to `/vpn/openxvpn`
2. **Update health checks**: Use `/health` endpoint instead of shell script
3. **Update monitoring**: Leverage new `/api/v1/status` for detailed metrics
4. **Optional**: Add YAML configuration for advanced features

### From Go back to Shell Implementation
1. **Change entrypoint**: `["/bin/bash", "/vpn/scripts/vpn.sh"]`
2. **Revert health check**: Remove curl-based health check (uses default)
3. **Update monitoring**: Use `/status.json` endpoint

---

## How It Works

- On startup, the container:
    1. Verifies VPN credentials.
    2. Selects an `.ovpn` config file (optionally filtered by `SERVER`).
    3. Starts OpenVPN and a web server for status.
    4. **Go mode**: Advanced health monitoring with recovery
    5. **Shell mode**: Basic periodic IP verification

- Other containers can use `network_mode: "service:xvpn"` to route all their traffic through the VPN.

---

## Troubleshooting

### General Issues
- **Container is unhealthy:**
    - Check your ExpressVPN credentials.
    - Ensure at least one valid `.ovpn` file is present.
    - Review logs with `docker logs xvpn`.

- **Cannot access local network:**
    - Adjust the `LAN` environment variable to match your local network.

### Go Implementation Debugging
```bash
# View structured logs
docker logs xvpn | jq .

# Filter by component
docker logs xvpn | jq 'select(.component == "health")'
docker logs xvpn | jq 'select(.component == "speedtest")'

# Check detailed status with speed test results
curl http://localhost:8080/api/v1/status | jq .

# Run immediate speed test
curl -X POST http://localhost:8080/api/v1/speedtest | jq .

# Check available speed test endpoints
curl http://localhost:8080/api/v1/speedtest/endpoints | jq .

# Monitor with authentication (if enabled)
curl -H "Authorization: Bearer your-token" http://localhost:8080/api/v1/status | jq .
```

### Shell Implementation Debugging
```bash
# View traditional logs
docker logs xvpn

# Check simple status
curl http://localhost:8080/status.json
```

---

## Advanced Usage

### Switching Between Modes

**Build once, run either mode:**
```bash
# Build image with both implementations
docker build -t my-openxvpn .

# Run Go implementation (default)
docker run my-openxvpn

# Run shell implementation
docker run --entrypoint "/bin/bash" my-openxvpn /vpn/scripts/vpn.sh
```

**Docker Compose with environment-based switching:**
```yaml
services:
  xvpn:
    image: my-openxvpn
    entrypoint: 
      - "${VPN_MODE:-/vpn/openxvpn}"  # Default to Go, override with VPN_MODE=bash
    command: 
      - "${VPN_MODE_ARGS:-}"          # Additional args for shell mode
```

Run with: `VPN_MODE="/bin/bash" VPN_MODE_ARGS="/vpn/scripts/vpn.sh" docker-compose up`

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
- Go implementation uses standard library and [Viper](https://github.com/spf13/viper) for configuration.

---