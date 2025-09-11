# openxvpn

![go](https://github.com/pilotso11/openxvpn/actions/workflows/go.yml/badge.svg)
![docker](https://github.com/pilotso11/openxvpn/actions/workflows/docker.yml/badge.svg)
![Coverage](https://img.shields.io/badge/Coverage-88.8%25-brightgreen)
[![MIT License](https://img.shields.io/github/license/pilotso11/openxvpn?style=flat-square)](./LICENSE)

A lightweight Docker image for running OpenVPN with ExpressVPN configuration, designed to proxy other services securely and easily. Built with Go for enhanced monitoring, speed testing, and comprehensive API capabilities.

---

## 🌟 Features

- **ExpressVPN Support**: Use your own ExpressVPN credentials and configuration files
- **Docker-First**: Built for seamless integration with Docker Compose and containerized workflows
- **Network Proxying**: Easily route other containers' traffic through the VPN
- **Advanced Health Monitoring**: Configurable health checks with context-based graceful shutdown
- **Speed Testing**: Built-in bandwidth testing with 6 endpoints and randomization
- **REST API**: Complete programmatic control and status monitoring
- **Web Dashboard**: Real-time status with geolocation and speed metrics
- **Secure Logging**: Structured JSON logs with automatic credential redaction
- **API Security**: Optional authentication with health endpoint bypass for monitoring systems
- **Flexible Config**: Environment variables, YAML files, or credential files
- **Multi-IP Detection**: Supports multiple IP detection services with failover

---

## Quick Start

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

---

## Docker Compose Example

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

### Health & Status (No Authentication Required)
- **`GET /health`** - Docker health check endpoint (returns 200 if VPN connected)
- **`GET /api/v1/status`** - Detailed JSON status with health and speed test metrics
- **`GET /status`** - Legacy compatibility endpoint (simple JSON format)
- **`POST /api/v1/healthcheck`** - Force immediate health check

### VPN Management (Authentication Required if Enabled)  
- **`POST /api/v1/reconnect`** - Force VPN reconnection and restart

### IP & Geolocation (Authentication Required if Enabled)
- **`GET /api/v1/ipinfo`** - Current IP geolocation information with detailed location data
- **`GET /ip2location.json`** - Raw IP2Location API compatibility endpoint
- **`GET /api/v1/cache/stats`** - IP geolocation cache statistics
- **`POST /api/v1/cache/clear`** - Clear IP geolocation cache

### Metrics & Statistics (Authentication Required if Enabled)
- **`GET /stats.json`** - API call statistics and performance metrics

### User Interface
- **`GET /`** - Modern HTML status dashboard with real-time metrics

### Speed Testing
Speed testing functionality is integrated into the health monitoring system and accessible through:
- **`GET /api/v1/status`** - Includes latest speed test results and aggregated data
- Speed tests run automatically at configured intervals when enabled
- Results include endpoint used, test size, speed in Mbps, and timestamp

### Authentication
When API authentication is enabled, health endpoints (`/health`, `/api/v1/status`, `/status`, `/api/v1/healthcheck`) remain accessible without authentication to support monitoring systems and Docker health checks.

### API Response Examples

#### GET /api/v1/status
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
    },
    "speed_test_aggregate": {
      "fastest_speed": 52.1,
      "slowest_speed": 38.9,
      "average_speed": 44.3,
      "success_rate": 95.0
    }
  },
  "reliability": {
    "restart_count": 1,
    "last_restart": "2024-01-15T08:15:30Z"
  }
}
```

#### GET /health
```json
{
  "status": "healthy"
}
```

#### GET /status (Legacy)
```json
{
  "status": "connected",
  "ip": "192.0.2.1",
  "at": "2024-01-15T10:45:00Z"
}
```

#### GET /api/v1/ipinfo
```json
{
  "ip": "192.0.2.1",
  "country": "Australia",
  "region": "Victoria", 
  "city": "Melbourne",
  "isp": "ExpressVPN",
  "timezone": "Australia/Melbourne",
  "latitude": -37.8136,
  "longitude": 144.9631
}
```

#### GET /stats.json
```json
{
  "incoming_calls": {
    "total": 1245,
    "by_endpoint": {
      "/api/v1/status": 892,
      "/health": 234,
      "/": 119
    }
  },
  "outgoing_calls": {
    "total": 567,
    "by_service": {
      "ipify": 234,
      "ip2location": 187,
      "ifconfig.me": 146
    }
  },
  "vpn_events": {
    "restarts": 2,
    "connects": 3,
    "disconnects": 2
  },
  "speed_tests": {
    "total_runs": 24,
    "success_rate": 95.8,
    "average_speed": 44.3
  }
}
```

---

## Health & Status

### Features
- **Advanced Health Monitoring**: Configurable failure thresholds and context-based recovery
- **Speed Testing**: Built-in bandwidth testing with 6 endpoints (ThinkBroadband, Speedtest.net, OVH, Cachefly, DigitalOcean, Linode)
- **Structured Logging**: JSON logs with credential redaction and component-level detail
- **Graceful Shutdown**: Context-based service termination without explicit Stop() methods
- **Performance Metrics**: Success rates, restart counts, uptime tracking, speed test results

### Enhanced Status Response
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

---

## Configuration

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

---

## How It Works

On startup, the container:
1. Verifies VPN credentials
2. Selects an `.ovpn` config file (optionally filtered by `SERVER`)
3. Starts OpenVPN and a web server for status
4. Begins advanced health monitoring with recovery

Other containers can use `network_mode: "service:xvpn"` to route all their traffic through the VPN.

---

## Troubleshooting

### General Issues
- **Container is unhealthy:**
    - Check your ExpressVPN credentials
    - Ensure at least one valid `.ovpn` file is present
    - Review logs with `docker logs xvpn`

- **Cannot access local network:**
    - Adjust the `LAN` environment variable to match your local network

### Debugging Commands
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
- Not affiliated with ExpressVPN
- Uses [OpenVPN](https://openvpn.net/)
- Go implementation uses standard library and [Viper](https://github.com/spf13/viper) for configuration

---