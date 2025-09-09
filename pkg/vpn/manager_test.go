package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"openxvpn/pkg/config"
	"openxvpn/pkg/ipdetector"
)

// Mock IP detector for testing
type mockIPDetector struct {
	currentIP string
	err       error
}

func (m *mockIPDetector) GetCurrentIP(ctx context.Context) (string, error) {
	return m.currentIP, m.err
}

func (m *mockIPDetector) GetIPInfo(ctx context.Context, ip string) (*ipdetector.IPInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &ipdetector.IPInfo{
		IP:      ip,
		Country: "Test Country",
		ISP:     "Test ISP",
	}, nil
}

func (m *mockIPDetector) GetCurrentIPInfo(ctx context.Context) (*ipdetector.IPInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &ipdetector.IPInfo{
		IP:      m.currentIP,
		Country: "Test Country",
		ISP:     "Test ISP",
	}, nil
}

func (m *mockIPDetector) HealthCheck(ctx context.Context) error {
	return m.err
}

func (m *mockIPDetector) CheckIPChange(ctx context.Context, lastIP string) (bool, string, error) {
	changed := lastIP != m.currentIP
	return changed, m.currentIP, m.err
}

func (m *mockIPDetector) ClearCache() {}

func (m *mockIPDetector) GetCacheStats() map[string]any {
	return map[string]any{}
}

func (m *mockIPDetector) GetRawIP2LocationData(ctx context.Context, ip string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []byte(`{"ip":"` + ip + `","country":"Test Country"}`), nil
}

// Helper function to create test config
func createTestConfig() *config.Config {
	return &config.Config{
		VPN: config.VPNConfig{
			ConfigPath: "/tmp/test-configs",
			Server:     "test",
			Username:   "testuser",
			Password:   "testpass",
		},
		Network: config.NetworkConfig{
			LAN:            "192.168.1.0/24",
			IP2LocationKey: "test-key",
		},
		Health: config.HealthConfig{
			Timeout: 10 * time.Second,
		},
		Recovery: config.RecoveryConfig{
			RestartDelay: 1 * time.Second,
		},
	}
}

// Helper function to create test logger
func createTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// Helper function to create temporary config files
func createTempConfigFiles(t *testing.T, configPath string) []string {
	if err := os.MkdirAll(configPath, 0755); err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	files := []string{
		"test_server_1.ovpn",
		"test_server_2.ovpn",
		"another_test_server.ovpn",
	}

	var createdFiles []string
	for _, file := range files {
		fullPath := filepath.Join(configPath, file)
		if err := os.WriteFile(fullPath, []byte("test config content"), 0644); err != nil {
			t.Fatalf("Failed to create config file %s: %v", fullPath, err)
		}
		createdFiles = append(createdFiles, fullPath)
	}

	return createdFiles
}

func TestNewManager(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()

	manager := NewManager(cfg, logger)

	assert.NotNil(t, manager, "Expected manager to be created")

	assert.Equal(t, cfg, manager.config, "Expected config to be set correctly")

	assert.Equal(t, logger, manager.logger, "Expected logger to be set correctly")

	assert.NotNil(t, manager.ipDetector, "Expected IP detector to be created")
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateDisconnected, "disconnected"},
		{StateConnecting, "connecting"},
		{StateConnected, "connected"},
		{StateReconnecting, "reconnecting"},
		{StateFailed, "failed"},
		{State(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.state.String()
			assert.Equal(t, tt.expected, result, "Expected %s, got %s", tt.expected, result)
		})
	}
}

func TestManagerImpl_GetStatus(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Test initial status
	status := manager.GetStatus()
	assert.Equal(t, "disconnected", status.State, "Expected initial state to be disconnected, got %s", status.State)

	assert.Equal(t, "", status.OriginalIP, "Expected original IP to be empty initially, got %s", status.OriginalIP)

	assert.Equal(t, "", status.CurrentIP, "Expected current IP to be empty initially, got %s", status.CurrentIP)

	assert.Equal(t, "", status.Uptime, "Expected uptime to be empty initially, got %s", status.Uptime)

	assert.Equal(t, "", status.Server, "Expected server to be empty initially, got %s", status.Server)

	// Test status with some values set
	manager.setState(StateConnected)
	manager.mu.Lock()
	manager.originalIP = "1.2.3.4"
	manager.currentIP = "5.6.7.8"
	manager.selectedOVPN = "/path/to/test_server.ovpn"
	manager.startTime = time.Now().Add(-5 * time.Minute)
	manager.mu.Unlock()

	status = manager.GetStatus()
	assert.Equal(t, "connected", status.State, "Expected state to be connected, got %s", status.State)

	assert.Equal(t, "1.2.3.4", status.OriginalIP, "Expected original IP to be 1.2.3.4, got %s", status.OriginalIP)

	assert.Equal(t, "5.6.7.8", status.CurrentIP, "Expected current IP to be 5.6.7.8, got %s", status.CurrentIP)

	assert.Equal(t, "test_server", status.Server, "Expected server to be test_server, got %s", status.Server)

	assert.NotEmpty(t, status.Uptime, "Expected uptime to be set")
}

func TestManagerImpl_SetState(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Test setting different states
	states := []State{StateConnecting, StateConnected, StateDisconnected, StateFailed}

	for _, state := range states {
		manager.setState(state)
		assert.Equal(t, state, State(manager.state.Load()), "Expected state to be %s, got %s", state.String(), State(manager.state.Load()).String())
	}
}

func TestManagerImpl_UpdateCurrentIP(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	testIP := "10.20.30.40"
	manager.UpdateCurrentIP(testIP)

	manager.mu.RLock()
	currentIP := manager.currentIP
	manager.mu.RUnlock()

	assert.Equal(t, testIP, currentIP, "Expected current IP to be %s, got %s", testIP, currentIP)
}

func TestManagerImpl_GetIPDetector(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	detector := manager.GetIPDetector()
	assert.NotNil(t, detector, "Expected IP detector to be returned")

	assert.Equal(t, manager.ipDetector, detector, "Expected returned detector to be the same as internal detector")
}

func TestManagerImpl_SelectConfigFile_NoFiles(t *testing.T) {
	cfg := createTestConfig()
	cfg.VPN.ConfigPath = "/nonexistent/path"
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	err := manager.selectConfigFile()
	assert.Error(t, err, "Expected error when no config files found")

	assert.Contains(t, err.Error(), "no OpenVPN config files found", "Expected specific error message, got: %v", err)
}

func TestManagerImpl_SelectConfigFile_Success(t *testing.T) {
	tempDir := t.TempDir()
	cfg := createTestConfig()
	cfg.VPN.ConfigPath = tempDir
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Create test config files
	createTempConfigFiles(t, tempDir)

	err := manager.selectConfigFile()
	assert.NoError(t, err, "Unexpected error")

	manager.mu.RLock()
	selectedOVPN := manager.selectedOVPN
	manager.mu.RUnlock()

	assert.NotEmpty(t, selectedOVPN, "Expected a config file to be selected")

	assert.True(t, strings.HasSuffix(selectedOVPN, ".ovpn"), "Expected selected file to have .ovpn extension")

	assert.True(t, strings.Contains(selectedOVPN, "test"), "Expected selected file to match server pattern")
}

func TestManagerImpl_CreateCredentialsFile(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	credFile, err := manager.createCredentialsFile()
	assert.NoError(t, err, "Unexpected error creating credentials file")

	defer os.Remove(credFile)

	// Check file exists and has correct permissions
	info, err := os.Stat(credFile)
	assert.NoError(t, err, "Credentials file not found")

	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "Expected file permissions 0600, got %o", info.Mode().Perm())

	// Check file content
	content, err := os.ReadFile(credFile)
	assert.NoError(t, err, "Failed to read credentials file")

	lines := strings.Split(string(content), "\n")
	assert.GreaterOrEqual(t, len(lines), 2, "Expected at least 2 lines in credentials file")

	assert.Equal(t, cfg.VPN.Username, lines[0], "Expected first line to be username %s, got %s", cfg.VPN.Username, lines[0])

	assert.Equal(t, cfg.VPN.Password, lines[1], "Expected second line to be password %s, got %s", cfg.VPN.Password, lines[1])
}

func TestManagerImpl_FetchOriginalIP_Success(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Replace IP detector with mock
	mockDetector := &mockIPDetector{
		currentIP: "192.168.1.100",
		err:       nil,
	}
	manager.ipDetector = mockDetector

	err := manager.fetchOriginalIP()
	assert.NoError(t, err, "Unexpected error")

	manager.mu.RLock()
	originalIP := manager.originalIP
	manager.mu.RUnlock()

	assert.Equal(t, "192.168.1.100", originalIP, "Expected original IP to be 192.168.1.100, got %s", originalIP)
}

func TestManagerImpl_FetchOriginalIP_Error(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Replace IP detector with mock that returns error
	mockDetector := &mockIPDetector{
		currentIP: "",
		err:       fmt.Errorf("network error"),
	}
	manager.ipDetector = mockDetector

	err := manager.fetchOriginalIP()
	assert.Error(t, err, "Expected error when IP detection fails")

	assert.Contains(t, err.Error(), "failed to detect original IP", "Expected specific error message, got: %v", err)
}

func TestManagerImpl_Stop_NoProcess(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Test stopping when no process is running
	err := manager.Stop()
	assert.NoError(t, err, "Unexpected error when stopping with no process")

	assert.Equal(t, StateDisconnected, State(manager.state.Load()), "Expected state to be disconnected after stop")
}

func TestManagerImpl_Restart(t *testing.T) {
	cfg := createTestConfig()
	cfg.Recovery.RestartDelay = 10 * time.Millisecond // Reduce delay for testing
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Replace IP detector with mock
	mockDetector := &mockIPDetector{
		currentIP: "192.168.1.100",
		err:       nil,
	}
	manager.ipDetector = mockDetector

	// Create temporary config directory and files
	tempDir := t.TempDir()
	cfg.VPN.ConfigPath = tempDir
	createTempConfigFiles(t, tempDir)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// This will fail to actually start OpenVPN (which is expected in tests)
	// but should test the restart logic
	err := manager.Restart(ctx)

	// We expect this to fail since we don't have actual OpenVPN installed
	// but we can verify the restart logic was called
	if err == nil {
		t.Log("Restart succeeded (unexpected but not necessarily wrong)")
	} else {
		assert.True(t, strings.Contains(err.Error(), "openvpn") || strings.Contains(err.Error(), "exec"), "Expected OpenVPN-related error, got: %v", err)
	}
}

func TestManagerImpl_ConfigureLANRoutes_NoLAN(t *testing.T) {
	cfg := createTestConfig()
	cfg.Network.LAN = "" // No LAN configured
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	err := manager.configureLANRoutes()
	assert.NoError(t, err, "Unexpected error when no LAN configured")
}

// Note: Testing configureLANRoutes with actual routing commands would require
// root privileges and might interfere with the system, so we keep it minimal.

func TestManagerImpl_Start_MissingConfig(t *testing.T) {
	cfg := createTestConfig()
	cfg.VPN.ConfigPath = "/nonexistent/path"
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Replace IP detector with mock
	mockDetector := &mockIPDetector{
		currentIP: "192.168.1.100",
		err:       nil,
	}
	manager.ipDetector = mockDetector

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := manager.Start(ctx)
	assert.Error(t, err, "Expected error when config files are missing")

	assert.Contains(t, err.Error(), "failed to select config file", "Expected config file error, got: %v", err)
}

func TestManagerImpl_Start_IPDetectionFailure(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Replace IP detector with mock that fails
	mockDetector := &mockIPDetector{
		currentIP: "",
		err:       fmt.Errorf("IP detection failed"),
	}
	manager.ipDetector = mockDetector

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := manager.Start(ctx)
	assert.Error(t, err, "Expected error when IP detection fails")

	assert.Contains(t, err.Error(), "failed to get original IP", "Expected IP detection error, got: %v", err)
}

// E2E Tests using Mock OpenVPN

func TestManagerImpl_E2E_SuccessfulConnection(t *testing.T) {
	// Create temporary directory for test configs
	tempDir := t.TempDir()

	// Create test config
	cfg := createTestConfig()
	cfg.VPN.ConfigPath = tempDir
	cfg.VPN.OpenVPNExecutable = filepath.Join(tempDir, "mock_openvpn.sh")

	// Copy mock OpenVPN script to temp directory
	mockScript := `#!/bin/bash
echo "Mock OpenVPN starting..."
echo "Config file: $2"
echo "Auth file: $4"
echo "Attempting connection..."
sleep 0.1
echo "Connected to mock VPN server"
echo "VPN connection established"
trap 'echo "Received interrupt signal, shutting down..."; exit 0' INT TERM
while true; do sleep 0.1; done
`
	err := os.WriteFile(cfg.VPN.OpenVPNExecutable, []byte(mockScript), 0755)
	assert.NoError(t, err, "Failed to create mock script")

	// Create test OpenVPN config file
	configContent := `# Test OpenVPN config
client
dev tun
proto udp
remote test.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
verb 3
`
	configPath := filepath.Join(tempDir, "test_server.ovpn")
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err, "Failed to create config file")

	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Replace IP detector with mock
	mockDetector := &mockIPDetector{
		currentIP: "192.168.1.100",
		err:       nil,
	}
	manager.ipDetector = mockDetector

	// Test successful start
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	assert.NoError(t, err, "Expected successful start with mock OpenVPN")

	// Verify state
	status := manager.GetStatus()
	assert.Equal(t, "connected", status.State, "Expected connected state")
	assert.Equal(t, "192.168.1.100", status.OriginalIP, "Expected original IP")
	assert.Equal(t, "test_server", status.Server, "Expected server name")

	// Test stop
	err = manager.Stop()
	assert.NoError(t, err, "Expected successful stop")

	status = manager.GetStatus()
	assert.Equal(t, "disconnected", status.State, "Expected disconnected state after stop")
}

func TestManagerImpl_E2E_ConnectionFailure(t *testing.T) {
	// Create temporary directory for test configs
	tempDir := t.TempDir()

	// Create test config
	cfg := createTestConfig()
	cfg.VPN.ConfigPath = tempDir
	cfg.VPN.OpenVPNExecutable = filepath.Join(tempDir, "mock_openvpn_fail.sh")

	// Create failing mock OpenVPN script
	mockScript := `#!/bin/bash
echo "Mock OpenVPN starting..."
echo "Config file: $2"
echo "Auth file: $4"
echo "Attempting connection..."
sleep 0.1
echo "ERROR: Connection failed" >&2
exit 1
`
	err := os.WriteFile(cfg.VPN.OpenVPNExecutable, []byte(mockScript), 0755)
	assert.NoError(t, err, "Failed to create mock script")

	// Create test OpenVPN config file
	configContent := `# Test OpenVPN config with failure
client
dev tun
proto udp
remote test.example.com 1194
MOCK_FAIL
`
	configPath := filepath.Join(tempDir, "test_server.ovpn")
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err, "Failed to create config file")

	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Replace IP detector with mock
	mockDetector := &mockIPDetector{
		currentIP: "192.168.1.100",
		err:       nil,
	}
	manager.ipDetector = mockDetector

	// Test failed start
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	assert.Error(t, err, "Expected error when mock OpenVPN fails")
	assert.Contains(t, err.Error(), "OpenVPN failed to establish connection", "Expected OpenVPN start error")
}

func TestManagerImpl_E2E_Restart(t *testing.T) {
	// Create temporary directory for test configs
	tempDir := t.TempDir()

	// Create test config
	cfg := createTestConfig()
	cfg.VPN.ConfigPath = tempDir
	cfg.VPN.OpenVPNExecutable = filepath.Join(tempDir, "mock_openvpn.sh")
	cfg.Recovery.RestartDelay = 100 * time.Millisecond // Fast restart for testing

	// Create mock OpenVPN script
	mockScript := `#!/bin/bash
echo "Mock OpenVPN starting..."
echo "Config file: $2"
echo "Auth file: $4"
echo "Attempting connection..."
sleep 0.1
echo "Connected to mock VPN server"
echo "VPN connection established"
trap 'echo "Received interrupt signal, shutting down..."; exit 0' INT TERM
while true; do sleep 0.1; done
`
	err := os.WriteFile(cfg.VPN.OpenVPNExecutable, []byte(mockScript), 0755)
	assert.NoError(t, err, "Failed to create mock script")

	// Create test OpenVPN config file
	configContent := `# Test OpenVPN config
client
dev tun
proto udp
remote test.example.com 1194
`
	configPath := filepath.Join(tempDir, "test_server.ovpn")
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err, "Failed to create config file")

	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Replace IP detector with mock
	mockDetector := &mockIPDetector{
		currentIP: "192.168.1.100",
		err:       nil,
	}
	manager.ipDetector = mockDetector

	// Test restart
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = manager.Restart(ctx)
	assert.NoError(t, err, "Expected successful restart with mock OpenVPN")

	// Verify state
	status := manager.GetStatus()
	assert.Equal(t, "connected", status.State, "Expected connected state after restart")

	// Cleanup
	err = manager.Stop()
	assert.NoError(t, err, "Expected successful stop after restart test")
}

func TestManagerImpl_E2E_MultipleConfigFiles(t *testing.T) {
	// Create temporary directory for test configs
	tempDir := t.TempDir()

	// Create test config
	cfg := createTestConfig()
	cfg.VPN.ConfigPath = tempDir
	cfg.VPN.Server = "multi" // Should match multiple files
	cfg.VPN.OpenVPNExecutable = filepath.Join(tempDir, "mock_openvpn.sh")

	// Create mock OpenVPN script
	mockScript := `#!/bin/bash
echo "Mock OpenVPN starting..."
echo "Config file: $2"
echo "Auth file: $4"
echo "Attempting connection..."
sleep 0.1
echo "Connected to mock VPN server"
echo "VPN connection established"
trap 'echo "Received interrupt signal, shutting down..."; exit 0' INT TERM
while true; do sleep 0.1; done
`
	err := os.WriteFile(cfg.VPN.OpenVPNExecutable, []byte(mockScript), 0755)
	assert.NoError(t, err, "Failed to create mock script")

	// Create multiple test config files
	configFiles := []string{
		"multi_server_1.ovpn",
		"multi_server_2.ovpn",
		"multi_server_3.ovpn",
		"other_server.ovpn", // This should not be selected
	}

	configContent := `# Test OpenVPN config
client
dev tun
proto udp
remote test.example.com 1194
`

	for _, file := range configFiles {
		configPath := filepath.Join(tempDir, file)
		err = os.WriteFile(configPath, []byte(configContent), 0644)
		assert.NoError(t, err, "Failed to create config file %s", file)
	}

	logger := createTestLogger()
	manager := NewManager(cfg, logger)

	// Replace IP detector with mock
	mockDetector := &mockIPDetector{
		currentIP: "192.168.1.100",
		err:       nil,
	}
	manager.ipDetector = mockDetector

	// Test start (should select one of the multi_server files)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	assert.NoError(t, err, "Expected successful start with multi config selection")

	// Verify state and selected server
	status := manager.GetStatus()
	assert.Equal(t, "connected", status.State, "Expected connected state")
	assert.True(t, strings.HasPrefix(status.Server, "multi_server_"), "Expected multi_server config to be selected, got: %s", status.Server)

	// Cleanup
	err = manager.Stop()
	assert.NoError(t, err, "Expected successful stop")
}
