# OpenXVPN - Dual Implementation VPN Container

OpenXVPN is a Docker-based VPN application with dual implementation support: a modern Go application (default) and legacy shell scripts. It integrates with ExpressVPN configurations to provide VPN connectivity for containerized services with advanced monitoring, speed testing, and comprehensive REST APIs.

**ALWAYS reference these instructions first** and fallback to search or bash commands only when you encounter unexpected information that does not match the information here.

## Working Effectively

### Bootstrap and Build the Repository
- Install Go 1.24+ and verify: `go version`
- Download dependencies: `go mod download && go mod verify`
- **Build Go binary**: `make build` -- **NEVER CANCEL**: Takes ~20 seconds first time, <1 second subsequent builds. Set timeout to 60+ minutes.
- **Alternative build**: `go build -o out/openxvpn .` -- Same timing as make build
- **Build for all platforms**: `make build-all` -- **NEVER CANCEL**: Takes 3-5 minutes. Set timeout to 60+ minutes.

### Testing Commands
- **Run tests**: `make test` -- **NEVER CANCEL**: Takes ~5 seconds. Set timeout to 30+ minutes.
- **Run full test suite**: `make test-coverage` -- **NEVER CANCEL**: Takes ~27 seconds with 74.6% coverage. Set timeout to 60+ minutes.
- **Run tests with race detection**: `make test-race` -- **NEVER CANCEL**: Takes ~15 seconds. Set timeout to 30+ minutes.
- **Run verbose tests**: `make test-verbose` -- **NEVER CANCEL**: Takes ~20 seconds. Set timeout to 30+ minutes.

### Code Quality and Formatting
- **Format code**: `make fmt` -- Takes <1 second
- **Vet code**: `make vet` -- Takes ~2 seconds
- **Run linter** (CI only): `make lint` -- Requires golangci-lint, not available locally
- **All CI checks**: `make ci-test` -- **NEVER CANCEL**: Takes ~30 seconds total. Set timeout to 60+ minutes.

### Docker Commands
- **Build Docker image**: `make docker-build` -- **NEVER CANCEL**: May take 10-15 minutes depending on network. May fail in restricted environments due to certificate issues.
- **Test Docker image**: `make docker-test` -- Tests basic image structure
- **Note**: Docker builds may fail in CI environments due to certificate verification issues with Go proxy

## Dual Implementation Usage

### Go Implementation (Default, Recommended)
- **Binary location**: `./out/openxvpn` (after `make build`)
- **Features**: Advanced health monitoring, speed testing, comprehensive REST API, structured JSON logging
- **Configuration**: Supports both YAML config files and environment variables
- **Health endpoint**: `/health` (used by Docker health checks)
- **API endpoints**: `/api/v1/status`, `/api/v1/reconnect`, `/api/v1/speedtest`, etc.

### Shell Implementation (Legacy)
- **Entry script**: `./scripts/vpn.sh` 
- **Features**: Basic health checks, simple JSON status, template-based HTML generation
- **Configuration**: Environment variables only
- **Health script**: `./scripts/check.sh`
- **Web server**: `./scripts/serve.sh` (uses mini_httpd + templates)

### Running the Application
- **Go mode (local)**: `./out/openxvpn` (requires VPN credentials via env vars)
- **Shell mode (local)**: `bash ./scripts/vpn.sh` (requires VPN credentials via env vars)
- **Docker Go mode**: Default entrypoint in Dockerfile
- **Docker Shell mode**: Override entrypoint to `["/bin/bash", "/vpn/scripts/vpn.sh"]`

## Validation and Testing

### Manual Validation Requirements
**CRITICAL**: After making any changes, you MUST validate functionality by:

1. **Build validation**: `make build && ./out/openxvpn --help`
2. **Test validation**: `make test-coverage` (verify all tests pass)
3. **Format validation**: `make fmt && make vet` (verify no formatting/vet issues)
4. **Shell script validation**: `bash -n ./scripts/*.sh` (verify shell script syntax)
5. **Configuration validation**: Check that config loading works: `./out/openxvpn` (should fail with config error, not compilation error)
6. **Docker structure validation** (if modifying Docker): `make docker-build` (may fail due to network restrictions)

### Scenario Validation After Changes
**ALWAYS test real functionality after any code changes**:

1. **Basic application startup**: Verify app starts and shows expected config error
2. **API endpoint structure**: Check that Go implementation defines expected routes  
3. **Shell script compatibility**: Verify scripts have valid syntax with `bash -n`
4. **Configuration loading**: Test both YAML and environment variable config paths
5. **Mock testing workflows**: Run tests using internal/testutils mocks for components you modified
6. **Integration points**: If modifying VPN, health, or web components, test their interaction

### Expected Command Behaviors
- `./out/openxvpn --help`: Shows usage (exits with 1 due to missing VPN credentials)
- `./out/openxvpn` without credentials: Fails with "VPN username and password are required"
- All make commands: Should complete without errors
- Tests: 74.6% coverage expected, all packages should pass

## Repository Structure

### Key Directories
- `pkg/`: Go packages (config, health, ipdetector, logging, speedtest, vpn, web)
- `scripts/`: Shell implementation (vpn.sh, check.sh, serve.sh, mock_openvpn.sh)
- `expressvpn/`: 62 ExpressVPN .ovpn configuration files
- `web/`: HTML templates for shell implementation (index.html, status.json)
- `internal/testutils/`: Mock implementations for testing
- `.github/workflows/`: CI/CD pipelines (go.yml, docker.yml)

### Important Files
- `main.go`: Go application entry point with graceful shutdown
- `config.yaml`: Default configuration with comprehensive options
- `Dockerfile`: Multi-stage build supporting both implementations
- `Makefile`: Build automation with comprehensive targets
- `go.mod`: Go 1.24 with minimal dependencies (viper, testify)

### Build Artifacts (Do NOT commit)
- `out/`: Go binary output directory
- `dist/`: Multi-platform build outputs  
- `coverage.out`, `coverage.html`: Test coverage reports

## Common Tasks

### Adding New Features
1. **Identify implementation**: Determine if feature applies to Go, Shell, or both implementations
2. **Update Go packages**: Modify appropriate packages in `pkg/` directory
3. **Update tests**: Add tests to maintain >70% coverage
4. **Update configuration**: Modify `config.yaml` if new config options needed
5. **Update shell scripts**: If feature applies to shell implementation
6. **Validation sequence**: `make fmt && make vet && make test-coverage && make build`

### Debugging Issues
- **Go logs**: Structured JSON with credential redaction: `./out/openxvpn 2>&1 | jq .`
- **Shell logs**: Standard bash output from scripts
- **Test specific packages**: `go test -v ./pkg/config` (example for config package)
- **Mock testing**: Use `internal/testutils` mocks for isolated testing
- **Coverage analysis**: View `coverage.html` after `make test-coverage`

### Configuration Management
- **Environment variables**: `OPEN_VPN_USER`, `OPEN_VPN_PASSWORD`, `SERVER`, `LAN`, `IP2LOCATION_IO_KEY`
- **YAML configuration**: Mount custom `config.yaml` for advanced options
- **ExpressVPN configs**: Server filtering via `SERVER` env var (e.g., `SERVER=australia`)
- **Docker secrets**: Support for credential files via `*_FILE` environment variables

## CI/CD and GitHub Actions

### GitHub Workflows
- **Go workflow** (`.github/workflows/go.yml`): Builds, tests, updates coverage badge
- **Docker workflow** (`.github/workflows/docker.yml`): Multi-platform Docker builds and publishing
- **Coverage reporting**: Automatic README.md badge updates on main branch

### Required Environment Setup for CI
- Go 1.24+
- Docker with buildx support  
- golangci-lint (for linting)
- git configured for coverage badge commits

### Troubleshooting CI Issues
- **Go dependency issues**: Check `go.mod` and `go.sum` integrity
- **Docker build failures**: Often due to network/certificate restrictions in CI
- **Coverage badge updates**: Requires push permissions to update README.md
- **Test failures**: Run locally with `make test-coverage` to reproduce

## Development Guidelines

### Code Style
- **Go formatting**: Always run `make fmt` before committing
- **Go vetting**: Always run `make vet` before committing  
- **Test coverage**: Maintain >70% coverage, aim for >90% on new code
- **Error handling**: Use structured logging with credential redaction
- **Context usage**: Properly handle context cancellation for graceful shutdown

### Testing Strategy
- **Unit tests**: Test individual packages in isolation using mocks
- **Integration tests**: Use `internal/testutils` for component interaction testing
- **Mock implementations**: Available for VPN manager, IP detector, speed tester
- **Coverage tracking**: Use `make test-coverage` to generate detailed reports
- **Race detection**: Always included in CI via `make test-race`

### Security Considerations
- **Credential redaction**: Automatic in structured logging (logging/redactor.go)
- **Environment variables**: Use `*_FILE` variants for secrets in containers
- **API authentication**: Optional in Go implementation with health endpoint bypass
- **Docker secrets**: Dockerfile includes warnings about sensitive environment variables

## API Reference (Go Implementation)

### Health and Status (No Authentication)
- `GET /health`: Docker health check endpoint
- `GET /api/v1/status`: Detailed JSON status with metrics
- `POST /api/v1/healthcheck`: Force immediate health check

### Management (Authentication Optional)  
- `POST /api/v1/reconnect`: Force VPN reconnection
- `GET /api/v1/ipinfo`: Current IP geolocation
- `POST /api/v1/cache/clear`: Clear IP cache

### Speed Testing (Authentication Optional)
- `POST /api/v1/speedtest`: Run immediate speed test
- `GET /api/v1/speedtest/endpoints`: Available test endpoints

### Shell Implementation API
- `GET /status.json`: Simple JSON status
- `GET /ip2location.json`: IP geolocation data
- `GET /`: HTML status dashboard

## Quick Reference Commands

```bash
# Standard development workflow
make fmt && make vet && make test && make build

# Full CI validation
make ci-test

# Build and test specific package  
go test -v -race ./pkg/config

# Validate shell scripts
bash -n ./scripts/*.sh

# Build Docker image (may fail in restricted environments)
make docker-build

# Clean build artifacts
make clean

# Generate documentation
go doc ./pkg/config  # Example for config package
```

Remember: **NEVER CANCEL** long-running commands. Builds and tests are designed to complete within documented timeframes.