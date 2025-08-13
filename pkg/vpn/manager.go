// Package vpn provides VPN connection management functionality including
// OpenVPN process lifecycle management, configuration file selection,
// network routing, and connection status monitoring.
package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"openxvpn/pkg/config"
	"openxvpn/pkg/ipdetector"
)

// State represents the current state of the VPN connection.
// It uses atomic operations for thread-safe state management.
type State int32

const (
	// StateDisconnected indicates the VPN is not connected
	StateDisconnected State = iota
	// StateConnecting indicates the VPN is in the process of connecting
	StateConnecting
	// StateConnected indicates the VPN is successfully connected
	StateConnected
	// StateReconnecting indicates the VPN is attempting to reconnect
	StateReconnecting
	// StateFailed indicates the VPN connection has failed
	StateFailed
)

// String returns the string representation of the VPN state.
// This method implements the fmt.Stringer interface for better logging and debugging.
func (s State) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Manager defines the interface for VPN connection management operations.
// It provides methods to control the VPN lifecycle, monitor status, and integrate
// with health monitoring components for IP tracking and detection.
type Manager interface {
	// Start initiates the VPN connection process including IP detection,
	// configuration file selection, network routing setup, and OpenVPN process startup.
	Start(ctx context.Context) error

	// Stop gracefully terminates the VPN connection, attempting a clean shutdown
	// before forcefully killing the process if necessary.
	Stop() error

	// Restart performs a complete VPN reconnection by stopping the current
	// connection and starting a new one with a configured delay.
	Restart(ctx context.Context) error

	// GetStatus returns the current VPN connection status including state,
	// IP addresses, uptime, and server information.
	GetStatus() Status

	// UpdateCurrentIP updates the current detected IP address, typically
	// called by health monitoring components.
	UpdateCurrentIP(ip string)

	// GetIPDetector returns the IP detector instance for use by other
	// components like health monitors.
	GetIPDetector() ipdetector.Detector
}

var _ Manager = (*ManagerImpl)(nil)

// ManagerImpl is the concrete implementation of the Manager interface.
// It manages the OpenVPN process lifecycle, handles configuration selection,
// monitors connection state, and provides IP detection capabilities.
// All operations are thread-safe using appropriate synchronization primitives.
type ManagerImpl struct {
	// config holds the application configuration
	config *config.Config
	// state tracks the current VPN state using atomic operations for thread safety
	state atomic.Int32
	// process holds the running OpenVPN process (protected by mu)
	process *exec.Cmd
	// processExited signals when the process monitoring goroutine completes (protected by mu)
	processExited chan struct{}
	// mu protects concurrent access to mutable fields
	mu sync.RWMutex
	// originalIP stores the IP address before VPN connection (protected by mu)
	originalIP string
	// currentIP stores the current detected IP address (protected by mu)
	currentIP string
	// selectedOVPN stores the path to the selected OpenVPN config file (protected by mu)
	selectedOVPN string
	// startTime records when the VPN connection was established (protected by mu)
	startTime time.Time
	// logger provides structured logging
	logger *slog.Logger
	// ipDetector provides IP address detection and geolocation services
	ipDetector ipdetector.Detector
}

// Status represents the current state and information about the VPN connection.
// This struct is used for JSON serialization in API responses and status reporting.
type Status struct {
	// State is the current VPN connection state as a string
	State string `json:"state"`
	// OriginalIP is the public IP address before VPN connection
	OriginalIP string `json:"original_ip"`
	// CurrentIP is the current detected public IP address
	CurrentIP string `json:"current_ip"`
	// Uptime is the duration since the VPN connection was established
	Uptime string `json:"uptime"`
	// Server is the name of the connected VPN server
	Server string `json:"server"`
}

// NewManager creates a new VPN manager instance with the provided configuration and logger.
// It initializes the IP detector with the configured API key and timeout settings.
// The manager is ready to use but requires calling Start() to begin VPN operations.
func NewManager(cfg *config.Config, logger *slog.Logger) *ManagerImpl {
	// Create IP detector with API key from config
	ipDetector := ipdetector.NewDetector(ipdetector.Config{
		Timeout:        cfg.Health.Timeout,
		IP2LocationKey: cfg.Network.IP2LocationKey,
		Logger:         logger.With("component", "ipdetector"),
	})

	return &ManagerImpl{
		config:     cfg,
		logger:     logger,
		ipDetector: ipDetector,
	}
}

// Start initiates the complete VPN connection process in the following sequence:
// 1. Detects the original IP address before connecting
// 2. Selects an appropriate OpenVPN configuration file
// 3. Configures LAN routing (if specified in config)
// 4. Starts the OpenVPN process and monitors its state
// The method returns an error if any critical step fails, though LAN routing failures are non-fatal.
func (m *ManagerImpl) Start(ctx context.Context) error {
	m.logger.Info("Starting VPN manager")

	// Get original IP before connecting
	if err := m.fetchOriginalIP(); err != nil {
		return fmt.Errorf("failed to get original IP: %w", err)
	}

	// Select OpenVPN config file
	if err := m.selectConfigFile(); err != nil {
		return fmt.Errorf("failed to select config file: %w", err)
	}

	// Configure LAN routes
	if err := m.configureLANRoutes(); err != nil {
		m.logger.Warn("Failed to configure LAN routes", "error", err)
	}

	// Start OpenVPN process
	return m.startVPN(ctx)
}

// Stop gracefully terminates the VPN connection by first attempting to send
// an interrupt signal to the OpenVPN process, then waiting up to 5 seconds for
// graceful shutdown. If the process doesn't stop gracefully, it's forcefully killed.
// The method is thread-safe and handles race conditions with the process monitoring goroutine.
func (m *ManagerImpl) Stop() error {
	m.setState(StateDisconnected)

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.process != nil {
		m.logger.Info("Stopping OpenVPN process")

		// Try graceful shutdown first
		if err := m.process.Process.Signal(os.Interrupt); err != nil {
			m.logger.Warn("Failed to send interrupt signal", "error", err)
		}

		// Wait for process monitoring goroutine to complete, or timeout
		// This avoids the race condition of two goroutines calling Wait()
		exitChan := m.processExited
		if exitChan != nil {
			select {
			case <-exitChan:
				m.logger.Info("OpenVPN process stopped gracefully")
			case <-time.After(5 * time.Second):
				m.logger.Warn("Force killing OpenVPN process")
				if err := m.process.Process.Kill(); err != nil {
					// Process might have already finished, which is fine
					if !strings.Contains(err.Error(), "process already finished") {
						return fmt.Errorf("failed to kill process: %w", err)
					}
				}
				// Wait a bit more for the monitoring goroutine to finish after kill
				select {
				case <-exitChan:
				case <-time.After(1 * time.Second):
					m.logger.Warn("Process monitoring goroutine didn't exit after kill")
				}
			}
		}

		m.process = nil
		m.processExited = nil
		// Explicitly set state to disconnected when Stop() is called
		// This prevents race conditions with the process monitoring goroutine
		m.setState(StateDisconnected)
	}

	return nil
}

// GetStatus returns a snapshot of the current VPN connection status.
// The method calculates uptime from the connection start time and extracts
// the server name from the selected configuration file. All fields are
// safely accessed under read lock to ensure thread safety.
func (m *ManagerImpl) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.state.Load() == int32(StateConnected) {
		uptime := ""
		if !m.startTime.IsZero() {
			uptime = time.Since(m.startTime).Round(time.Second).String()
		}
		server := ""
		if m.selectedOVPN != "" {
			server = strings.TrimSuffix(filepath.Base(m.selectedOVPN), ".ovpn")
		}

		return Status{
			State:      State(m.state.Load()).String(),
			OriginalIP: m.originalIP,
			CurrentIP:  m.currentIP,
			Uptime:     uptime,
			Server:     server,
		}
	} else {
		return Status{State: State(m.state.Load()).String(),
			OriginalIP: m.originalIP,
			CurrentIP:  m.currentIP,
		}
	}
}

// Restart performs a complete VPN reconnection by stopping the current connection,
// waiting for the configured restart delay, and then starting a new connection.
// This method is useful for recovering from connection issues or switching servers.
// If either the stop or start operation fails, an error is returned.
func (m *ManagerImpl) Restart(ctx context.Context) error {
	m.logger.Info("Restarting VPN connection")

	if err := m.Stop(); err != nil {
		m.logger.Error("Failed to stop VPN during restart", "error", err)
		return fmt.Errorf("failed to stop VPN during restart: %w", err)
	}

	// Wait a bit before restarting
	time.Sleep(m.config.Recovery.RestartDelay)

	if err := m.Start(ctx); err != nil {
		return fmt.Errorf("failed to start VPN during restart: %w", err)
	}

	return nil
}

// setState atomically updates the VPN connection state and logs the change.
// This method is thread-safe and can be called from multiple goroutines concurrently.
func (m *ManagerImpl) setState(state State) {
	m.state.Store(int32(state))
	m.logger.Debug("VPN state changed", "state", state.String())
}

// fetchOriginalIP detects and stores the public IP address before VPN connection.
// This IP is used as a baseline to verify that the VPN is working by comparing
// it with the IP after connection. The detection uses the configured timeout.
func (m *ManagerImpl) fetchOriginalIP() error {
	m.logger.Debug("Fetching original IP address")

	ctx, cancel := context.WithTimeout(context.Background(), m.config.Health.Timeout)
	defer cancel()

	ip, err := m.ipDetector.GetCurrentIP(ctx)
	if err != nil {
		return fmt.Errorf("failed to detect original IP: %w", err)
	}

	m.mu.Lock()
	m.originalIP = ip
	m.logger.Info("Original IP address detected", "ip", m.originalIP)
	m.mu.Unlock()
	return nil
}

// selectConfigFile searches for OpenVPN configuration files matching the configured
// server name pattern and randomly selects one. This provides load balancing across
// multiple server configurations for the same location or provider.
func (m *ManagerImpl) selectConfigFile() error {
	pattern := filepath.Join(m.config.VPN.ConfigPath, "*"+m.config.VPN.Server+"*.ovpn")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to glob config files: %w", err)
	}

	if len(matches) == 0 {
		return fmt.Errorf("no OpenVPN config files found matching pattern: %s", pattern)
	}

	// Randomly select one of the matching files
	selected := matches[rand.Intn(len(matches))]

	m.mu.Lock()
	m.selectedOVPN = selected
	m.mu.Unlock()

	m.logger.Info("Selected OpenVPN config", "file", selected)
	return nil
}

// configureLANRoutes sets up routing for the local network to ensure LAN access
// remains available while connected to the VPN. It detects the default gateway
// and adds a specific route for the configured LAN network. This prevents the
// VPN from blocking access to local network resources like printers and file shares.
func (m *ManagerImpl) configureLANRoutes() error {
	if m.config.Network.LAN == "" {
		return nil
	}

	m.logger.Debug("Configuring LAN routes", "lan", m.config.Network.LAN)

	// Get default gateway
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}

	// Parse gateway from output like "default via 192.168.1.1 dev eth0"
	parts := strings.Fields(string(output))
	if len(parts) < 3 || parts[1] != "via" {
		return fmt.Errorf("unexpected route output format: %s", string(output))
	}

	gateway := parts[2]

	// Add route for LAN network
	cmd = exec.Command("ip", "route", "add", m.config.Network.LAN, "via", gateway)
	if err := cmd.Run(); err != nil {
		// Route might already exist, which is fine
		m.logger.Debug("Failed to add LAN route (might already exist)", "error", err)
	} else {
		m.logger.Info("Added LAN route", "lan", m.config.Network.LAN, "gateway", gateway)
	}

	return nil
}

// startVPN launches the OpenVPN process with the selected configuration and credentials.
// It creates a temporary credentials file, builds the OpenVPN command with appropriate
// arguments, starts the process in a background goroutine for monitoring, and waits
// briefly to verify successful startup before marking the connection as established.
func (m *ManagerImpl) startVPN(ctx context.Context) error {
	m.setState(StateConnecting)
	m.mu.Lock()
	m.startTime = time.Now()
	m.mu.Unlock()

	// Create credentials file
	credFile, err := m.createCredentialsFile()
	if err != nil {
		return fmt.Errorf("failed to create credentials file: %w", err)
	}
	defer func(name string) {
		_ = os.Remove(name)
	}(credFile)

	// Build OpenVPN command
	args := []string{
		"--config", m.selectedOVPN,
		"--auth-user-pass", credFile,
		"--script-security", "2",
		"--dhcp-option", "DOMAIN-ROUTE .",
		"--down-pre",
		"--up", "/etc/openvpn/up.sh",
		"--down", "/etc/openvpn/down.sh",
	}

	m.logger.Info("Starting OpenVPN", "config", m.selectedOVPN, "executable", m.config.VPN.OpenVPNExecutable)

	m.mu.Lock()
	m.process = exec.CommandContext(ctx, m.config.VPN.OpenVPNExecutable, args...)
	m.processExited = make(chan struct{})
	m.mu.Unlock()

	// Start the process in background
	if err := m.process.Start(); err != nil {
		m.setState(StateFailed)
		return fmt.Errorf("failed to start OpenVPN: %w", err)
	}

	// Monitor the process
	go func() {
		defer close(m.processExited) // Signal when monitoring completes

		// Only this goroutine should call Wait() to avoid race conditions
		err := m.process.Wait()
		if err != nil {
			m.logger.Error("OpenVPN process exited with error", "error", err)
			m.setState(StateFailed)
		} else {
			m.logger.Info("OpenVPN process exited normally")
			m.setState(StateDisconnected)
		}
	}()

	// Give OpenVPN time to establish connection
	time.Sleep(2 * time.Second)

	// Check if process failed during startup
	if State(m.state.Load()) == StateFailed {
		return fmt.Errorf("OpenVPN process failed to start properly")
	}

	m.setState(StateConnected)

	return nil
}

// createCredentialsFile creates a temporary file containing VPN authentication credentials
// for OpenVPN to use. The file is created with restrictive permissions (0600) to protect
// sensitive credentials, and contains the username and password on separate lines.
// The caller is responsible for removing the file after use.
func (m *ManagerImpl) createCredentialsFile() (string, error) {
	file, err := os.CreateTemp("", "openvpn-auth-*")
	if err != nil {
		return "", err
	}

	if err := os.Chmod(file.Name(), 0600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return "", err
	}

	_, err = fmt.Fprintf(file, "%s\n%s\n", m.config.VPN.Username, m.config.VPN.Password)
	if err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return "", err
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}

	return file.Name(), nil
}

// UpdateCurrentIP updates the current IP address (called by health monitor)
func (m *ManagerImpl) UpdateCurrentIP(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentIP = ip
}

// GetIPDetector returns the IP detector for use by other components
func (m *ManagerImpl) GetIPDetector() ipdetector.Detector {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ipDetector
}
