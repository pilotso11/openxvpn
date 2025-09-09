# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Testing
```bash
# Build the Go binary
make build

# Run all tests with coverage
make test-coverage

# Run specific package tests
go test ./pkg/vpn
go test ./pkg/health -v

# Run a single test
go test ./pkg/vpn -run TestManagerImpl_Start

# Format, vet, and lint code
make fmt
make vet
make lint

# CI test suite (format + vet + race + coverage)
make ci-test
```

### Docker Development
```bash
# Build Docker image
make docker-build

# Test Docker image
make docker-test

# Run container locally for testing
docker run --cap-add=NET_ADMIN --device=/dev/net/tun:/dev/net/tun --privileged \
  -e OPEN_VPN_USER=test -e OPEN_VPN_PASSWORD=test \
  -p 8080:80 openxvpn
```

## Architecture Overview

### Core Components Architecture
OpenXVPN follows a clean layered architecture with dependency injection:

```
Application (main.go)
├── VPN Manager (pkg/vpn) - OpenVPN process lifecycle & state management
├── Health Monitor (pkg/health) - Monitoring, recovery, speed testing
├── Web Server (pkg/web) - REST API & HTML dashboard
├── IP Detector (pkg/ipdetector) - Multi-service IP detection & geolocation
├── Config (pkg/config) - Multi-source configuration with validation
└── Logging (pkg/logging) - Secure structured logging with credential redaction
```

### Key Interfaces
- `vpn.Manager` - VPN lifecycle operations (Start/Stop/Restart/GetStatus)
- `health.Monitor` - Health monitoring with failure callbacks
- `ipdetector.Detector` - IP detection and geolocation services
- All interfaces support dependency injection for testing

### State Management
VPN Manager uses atomic state machine: `Disconnected → Connecting → Connected` with failure states. Health Monitor tracks statistics and triggers recovery callbacks on threshold breaches.

## Configuration System

### Multi-Layer Priority
1. Environment Variables (highest)
2. Legacy Variables (`OPEN_VPN_*`, `SERVER`, `LAN`)
3. YAML Configuration File (`config.yaml`)
4. Default Values (lowest)

### Secret Resolution
- Passwords: `OPEN_VPN_PASSWORD` or `OPEN_VPN_USER_PASS_PATH` (file)
- API Keys: `IP2LOCATION_IO_KEY` or `IP2LOCATION_IO_KEY_FILE` (file)
- All secrets automatically redacted from logs

## Testing Patterns

### Test Structure
- **Unit tests**: `*_test.go` files alongside source
- **Integration tests**: `main_test.go`
- **Mocks**: `internal/testutils/mocks.go` with interface-based mocking
- **E2E tests**: Full VPN lifecycle testing with mock OpenVPN executables

### Running Tests
```bash
# Package-specific coverage
go test -coverprofile=coverage.out ./pkg/vpn
go tool cover -html=coverage.out

# Test with race detection
go test -race ./...

# Verbose test output
go test -v ./pkg/health
```

### Mock Usage
```go
// Use provided mocks for testing
mockVPN := testutils.NewMockVPNManager().WithStatus("connected")
mockIP := testutils.NewMockIPDetector().WithCurrentIP("10.0.0.1")
```

## Code Patterns

### Error Handling
- Use `fmt.Errorf` with context: `fmt.Errorf("failed to start VPN: %w", err)`
- Log errors at appropriate level before returning
- Health monitor uses error counting for recovery decisions

### Logging
- Use structured logging: `slog.Info("message", "key", value)`
- Credentials automatically redacted by logging.RedactorHandler
- Context-aware logging throughout request handling

### Concurrency
- All components are thread-safe using mutexes or atomic operations
- Use context.Context for cancellation and timeouts
- Health monitor and VPN manager run in separate goroutines

### Configuration
- Add new config fields to structs in `pkg/config/config.go`
- Update `setDefaults()` for default values
- Add validation in `Validate()` method
- Environment variable naming: `SECTION_FIELD` (e.g., `API_LISTEN`)

## API Development

### Adding Endpoints
1. Add handler method to `web.Server` struct
2. Register route in `Start()` method
3. Use `withAuth()` middleware if authentication needed
4. Health-related endpoints bypass authentication automatically

### Response Patterns
- Use structured JSON responses with consistent fields
- Legacy compatibility: maintain existing `/status` endpoint format
- Error responses include HTTP status codes and descriptive messages

## Dual Implementation Support

This project supports both Go (default) and shell script implementations:
- **Go Implementation**: Enhanced features, monitoring, API (default Docker entrypoint)
- **Shell Scripts**: Legacy compatibility (`/vpn/scripts/vpn.sh`)
- When modifying core functionality, consider impact on both implementations
- API endpoints maintain backward compatibility with shell script format
- Once the go version is working, the intention is to deprecate shell scripts.
## Common Development Tasks

### Adding New VPN Features
1. Extend `vpn.Manager` interface if needed
2. Implement in `ManagerImpl` with thread safety
3. Add corresponding tests with mock OpenVPN processes
4. Update health checks if state management changes

### Extending Health Monitoring
1. Modify `health.Status` struct for new metrics
2. Update `runHealthCheck()` method with new verifications
3. Add failure callback registration if needed
4. Ensure new fields are covered by mutex protection

### Adding Configuration Options
1. Add fields to appropriate config struct (`VPN`, `Health`, `API`, `Network`)
2. Update defaults in `setDefaults()`
3. Add validation logic in `Validate()`
4. Document in README.md environment variables table

### Web API Extensions
1. Add handler methods to `Server` struct
2. Follow existing patterns for authentication and logging
3. Maintain backward compatibility with legacy endpoints
4. Add corresponding tests for new endpoints
