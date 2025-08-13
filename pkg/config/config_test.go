package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFromEnvironment(t *testing.T) {
	// Set environment variables
	os.Setenv("OPEN_VPN_USER", "testuser")
	os.Setenv("OPEN_VPN_PASSWORD", "testpass")
	os.Setenv("SERVER", "australia")
	os.Setenv("LAN", "10.0.0.0/8")
	os.Setenv("IP2LOCATION_IO_KEY", "test-api-key")

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
		os.Unsetenv("OPEN_VPN_PASSWORD")
		os.Unsetenv("SERVER")
		os.Unsetenv("LAN")
		os.Unsetenv("IP2LOCATION_IO_KEY")
	}()

	cfg, err := Load("")
	require.NoError(t, err, "Expected config to load successfully with env vars")

	assert.Equal(t, "testuser", cfg.VPN.Username)
	assert.Equal(t, "testpass", cfg.VPN.Password)
	assert.Equal(t, "australia", cfg.VPN.Server)
	assert.Equal(t, "10.0.0.0/8", cfg.Network.LAN)
	assert.Equal(t, "test-api-key", cfg.Network.IP2LocationKey)

	// Check that defaults were applied
	assert.Equal(t, 30*time.Second, cfg.Health.CheckInterval)
	assert.Equal(t, 5*time.Second, cfg.Health.Timeout)
	assert.Equal(t, 3, cfg.Health.FailureThreshold)
	assert.Equal(t, 3, cfg.Recovery.MaxRetries)
	assert.Equal(t, 30*time.Second, cfg.Recovery.RestartDelay)
	assert.Equal(t, ":80", cfg.API.Listen)
}

func TestLoadMissingCredentials(t *testing.T) {
	// Clear environment variables to test missing credentials
	os.Unsetenv("OPEN_VPN_USER")
	os.Unsetenv("OPEN_VPN_PASSWORD")

	_, err := Load("")

	// Should fail validation due to missing credentials
	require.Error(t, err, "Expected error when loading config without credentials")
	assert.Contains(t, err.Error(), "VPN username and password are required")
}

func TestLoadIP2LocationKeyFromFile(t *testing.T) {
	// Create temporary API key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "ip2location.key")

	err := os.WriteFile(keyFile, []byte("file-api-key-123\n"), 0600)
	require.NoError(t, err, "Failed to create test file")

	// Set environment variables
	os.Setenv("OPEN_VPN_USER", "testuser")
	os.Setenv("OPEN_VPN_PASSWORD", "testpass")
	os.Setenv("IP2LOCATION_IO_KEY_FILE", keyFile)

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
		os.Unsetenv("OPEN_VPN_PASSWORD")
		os.Unsetenv("IP2LOCATION_IO_KEY_FILE")
	}()

	cfg, err := Load("")
	require.NoError(t, err, "Expected config to load successfully with API key file")

	assert.Equal(t, "file-api-key-123", cfg.Network.IP2LocationKey)
}

func TestLoadIP2LocationKeyPriority(t *testing.T) {
	// Create temporary API key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "ip2location.key")

	err := os.WriteFile(keyFile, []byte("file-key"), 0600)
	require.NoError(t, err, "Failed to create test file")

	// Set both inline key and file path (inline should take priority)
	os.Setenv("OPEN_VPN_USER", "testuser")
	os.Setenv("OPEN_VPN_PASSWORD", "testpass")
	os.Setenv("IP2LOCATION_IO_KEY", "inline-key")
	os.Setenv("IP2LOCATION_IO_KEY_FILE", keyFile)

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
		os.Unsetenv("OPEN_VPN_PASSWORD")
		os.Unsetenv("IP2LOCATION_IO_KEY")
		os.Unsetenv("IP2LOCATION_IO_KEY_FILE")
	}()

	cfg, err := Load("")
	require.NoError(t, err, "Expected config to load successfully")

	// Inline key should take priority
	assert.Equal(t, "inline-key", cfg.Network.IP2LocationKey, "Inline key should take priority over file")
}

func TestLoadVPNPasswordFromFile(t *testing.T) {
	// Create temporary password file
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "vpn.password")

	err := os.WriteFile(passwordFile, []byte("file-password-123\n"), 0600)
	require.NoError(t, err, "Failed to create test password file")

	// Set environment variables
	os.Setenv("OPEN_VPN_USER", "testuser")
	os.Setenv("OPEN_VPN_PASSWORD_FILE", passwordFile)

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
		os.Unsetenv("OPEN_VPN_PASSWORD_FILE")
	}()

	cfg, err := Load("")
	require.NoError(t, err, "Expected config to load successfully with password file")

	assert.Equal(t, "file-password-123", cfg.VPN.Password)
}

func TestLoadVPNPasswordPriority(t *testing.T) {
	// Create temporary password file
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "vpn.password")

	err := os.WriteFile(passwordFile, []byte("file-password"), 0600)
	require.NoError(t, err, "Failed to create test password file")

	// Set both inline password and file path (inline should take priority)
	os.Setenv("OPEN_VPN_USER", "testuser")
	os.Setenv("OPEN_VPN_PASSWORD", "inline-password")
	os.Setenv("OPEN_VPN_PASSWORD_FILE", passwordFile)

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
		os.Unsetenv("OPEN_VPN_PASSWORD")
		os.Unsetenv("OPEN_VPN_PASSWORD_FILE")
	}()

	cfg, err := Load("")
	require.NoError(t, err, "Expected config to load successfully")

	// Inline password should take priority
	assert.Equal(t, "inline-password", cfg.VPN.Password, "Inline password should take priority over file")
}

func TestLoadVPNPasswordFromYAMLFile(t *testing.T) {
	// Create temporary password file
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "vpn.password")

	err := os.WriteFile(passwordFile, []byte("yaml-file-password"), 0600)
	require.NoError(t, err, "Failed to create test password file")

	// Create YAML config with password_file
	configFile := filepath.Join(tmpDir, "test-config.yaml")
	yamlContent := `
vpn:
  password_file: "` + passwordFile + `"
`

	err = os.WriteFile(configFile, []byte(yamlContent), 0644)
	require.NoError(t, err, "Failed to create test config file")

	// Set required environment variable
	os.Setenv("OPEN_VPN_USER", "testuser")

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
	}()

	cfg, err := Load(configFile)
	require.NoError(t, err, "Expected config to load successfully with YAML password file")

	assert.Equal(t, "yaml-file-password", cfg.VPN.Password)
}

func TestLoadSecretFileErrors(t *testing.T) {
	tests := []struct {
		name          string
		setupEnv      func(tmpDir string)
		expectedError string
	}{
		{
			name: "VPN password file not found",
			setupEnv: func(tmpDir string) {
				os.Setenv("OPEN_VPN_USER", "testuser")
				os.Setenv("OPEN_VPN_PASSWORD_FILE", "/nonexistent/password.txt")
			},
			expectedError: "failed to resolve VPN password",
		},
		{
			name: "VPN password file empty",
			setupEnv: func(tmpDir string) {
				passwordFile := filepath.Join(tmpDir, "empty.password")
				os.WriteFile(passwordFile, []byte(""), 0600)
				os.Setenv("OPEN_VPN_USER", "testuser")
				os.Setenv("OPEN_VPN_PASSWORD_FILE", passwordFile)
			},
			expectedError: "VPN password file",
		},
		{
			name: "IP2Location key file not found",
			setupEnv: func(tmpDir string) {
				os.Setenv("OPEN_VPN_USER", "testuser")
				os.Setenv("OPEN_VPN_PASSWORD", "testpass")
				os.Setenv("IP2LOCATION_IO_KEY_FILE", "/nonexistent/key.txt")
			},
			expectedError: "failed to resolve IP2Location key",
		},
		{
			name: "IP2Location key file empty",
			setupEnv: func(tmpDir string) {
				keyFile := filepath.Join(tmpDir, "empty.key")
				os.WriteFile(keyFile, []byte("   \n  "), 0600)
				os.Setenv("OPEN_VPN_USER", "testuser")
				os.Setenv("OPEN_VPN_PASSWORD", "testpass")
				os.Setenv("IP2LOCATION_IO_KEY_FILE", keyFile)
			},
			expectedError: "IP2Location key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Clear environment
			os.Unsetenv("OPEN_VPN_USER")
			os.Unsetenv("OPEN_VPN_PASSWORD")
			os.Unsetenv("OPEN_VPN_PASSWORD_FILE")
			os.Unsetenv("IP2LOCATION_IO_KEY")
			os.Unsetenv("IP2LOCATION_IO_KEY_FILE")

			tt.setupEnv(tmpDir)

			defer func() {
				os.Unsetenv("OPEN_VPN_USER")
				os.Unsetenv("OPEN_VPN_PASSWORD")
				os.Unsetenv("OPEN_VPN_PASSWORD_FILE")
				os.Unsetenv("IP2LOCATION_IO_KEY")
				os.Unsetenv("IP2LOCATION_IO_KEY_FILE")
			}()

			_, err := Load("")
			require.Error(t, err, "Expected error for test case: %s", tt.name)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestLoadFromYAMLFile(t *testing.T) {
	// Create temporary YAML config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test-config.yaml")

	yamlContent := `
vpn:
  provider: "expressvpn"
  config_path: "/test/config"
  server: "sydney"
  timeout: "60s"

health:
  check_interval: "45s"
  timeout: "10s"
  failure_threshold: 5

recovery:
  max_retries: 5
  restart_delay: "45s"
  container_exit: false

api:
  listen: ":8080"
  auth:
    enabled: true
    token: "test-token"

network:
  lan: "172.16.0.0/12"
  ip2location_key: "yaml-api-key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	require.NoError(t, err, "Failed to create test config file")

	// Set required environment variables
	os.Setenv("OPEN_VPN_USER", "testuser")
	os.Setenv("OPEN_VPN_PASSWORD", "testpass")

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
		os.Unsetenv("OPEN_VPN_PASSWORD")
	}()

	cfg, err := Load(configFile)
	require.NoError(t, err, "Expected config to load successfully from YAML")

	// Check YAML values
	assert.Equal(t, "/test/config", cfg.VPN.ConfigPath)
	assert.Equal(t, "sydney", cfg.VPN.Server)
	assert.Equal(t, 60*time.Second, cfg.VPN.Timeout)
	assert.Equal(t, 45*time.Second, cfg.Health.CheckInterval)
	assert.Equal(t, 5, cfg.Health.FailureThreshold)
	assert.Equal(t, ":8080", cfg.API.Listen)
	assert.True(t, cfg.API.Auth.Enabled)
	assert.Equal(t, "test-token", cfg.API.Auth.Token)
	assert.Equal(t, "172.16.0.0/12", cfg.Network.LAN)

	// Environment variables should still override YAML
	assert.Equal(t, "testuser", cfg.VPN.Username, "Environment should override YAML")
}

func TestValidationSuccess(t *testing.T) {
	// Set required environment variables
	os.Setenv("OPEN_VPN_USER", "testuser")
	os.Setenv("OPEN_VPN_PASSWORD", "testpass")

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
		os.Unsetenv("OPEN_VPN_PASSWORD")
	}()

	cfg, err := Load("")
	require.NoError(t, err, "Expected validation to pass with valid credentials")

	// Verify the config was loaded correctly
	assert.Equal(t, "testuser", cfg.VPN.Username)
	assert.Equal(t, "testpass", cfg.VPN.Password)
}

func TestEnvOverrides(t *testing.T) {
	// Set environment variables that should override YAML config
	os.Setenv("OPEN_VPN_USER", "envuser")
	os.Setenv("OPEN_VPN_PASSWORD", "envpass")
	os.Setenv("SERVER", "envserver")
	os.Setenv("LAN", "10.10.0.0/16")

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
		os.Unsetenv("OPEN_VPN_PASSWORD")
		os.Unsetenv("SERVER")
		os.Unsetenv("LAN")
	}()

	// Create YAML config with different values
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test-config.yaml")

	yamlContent := `
vpn:
  server: "yamlserver"
  
network:
  lan: "192.168.0.0/16"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	require.NoError(t, err, "Failed to create test config file")

	cfg, err := Load(configFile)
	require.NoError(t, err, "Expected config to load successfully")

	// Environment should override YAML
	assert.Equal(t, "envuser", cfg.VPN.Username, "Environment should override YAML")
	assert.Equal(t, "envpass", cfg.VPN.Password, "Environment should override YAML")
	assert.Equal(t, "envserver", cfg.VPN.Server, "Environment should override YAML")
	assert.Equal(t, "10.10.0.0/16", cfg.Network.LAN, "Environment should override YAML")
}

func TestConfigDefaults(t *testing.T) {
	// Test that defaults are applied when values are not set
	os.Setenv("OPEN_VPN_USER", "testuser")
	os.Setenv("OPEN_VPN_PASSWORD", "testpass")

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
		os.Unsetenv("OPEN_VPN_PASSWORD")
	}()

	cfg, err := Load("")
	require.NoError(t, err, "Expected config to load successfully")

	// Test default values
	assert.Equal(t, "expressvpn", cfg.VPN.Provider)
	assert.Equal(t, "/vpn/config", cfg.VPN.ConfigPath)
	assert.Equal(t, 30*time.Second, cfg.VPN.Timeout)
	assert.Equal(t, 30*time.Second, cfg.Health.CheckInterval)
	assert.Equal(t, 5*time.Second, cfg.Health.Timeout)
	assert.Equal(t, 3, cfg.Health.FailureThreshold)
	assert.False(t, cfg.Health.SpeedTest.Enabled)
	assert.Equal(t, 3, cfg.Recovery.MaxRetries)
	assert.Equal(t, 30*time.Second, cfg.Recovery.RestartDelay)
	assert.True(t, cfg.Recovery.ContainerExit)
	assert.Equal(t, ":80", cfg.API.Listen)
	assert.False(t, cfg.API.Auth.Enabled)
	assert.Equal(t, "192.168.0.0/16", cfg.Network.LAN)
}

func TestLoadWithNonExistentFile(t *testing.T) {
	// Test loading with a config file that doesn't exist (should use defaults + env)
	os.Setenv("OPEN_VPN_USER", "testuser")
	os.Setenv("OPEN_VPN_PASSWORD", "testpass")

	defer func() {
		os.Unsetenv("OPEN_VPN_USER")
		os.Unsetenv("OPEN_VPN_PASSWORD")
	}()

	cfg, err := Load("/path/that/does/not/exist.yaml")

	// This should succeed if the config loading handles missing files gracefully
	// by using just environment variables and defaults
	if err != nil {
		// If it fails, it should be due to file not found, not validation
		assert.Contains(t, err.Error(), "no such file or directory")
	} else {
		// If it succeeds, verify basic functionality
		assert.Equal(t, "testuser", cfg.VPN.Username)
		assert.Equal(t, "testpass", cfg.VPN.Password)
	}
}
