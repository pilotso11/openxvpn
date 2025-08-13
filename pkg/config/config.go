package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	VPN      VPNConfig      `mapstructure:"vpn"`
	Health   HealthConfig   `mapstructure:"health"`
	Recovery RecoveryConfig `mapstructure:"recovery"`
	API      APIConfig      `mapstructure:"api"`
	Network  NetworkConfig  `mapstructure:"network"`
	TestMode bool           `mapstructure:"test_mode"`
}

type VPNConfig struct {
	Provider          string        `mapstructure:"provider"`
	ConfigPath        string        `mapstructure:"config_path"`
	Username          string        `mapstructure:"username"`
	Password          string        `mapstructure:"password"`
	PasswordFile      string        `mapstructure:"password_file"`
	Server            string        `mapstructure:"server"`
	Timeout           time.Duration `mapstructure:"timeout"`
	OpenVPNExecutable string        `mapstructure:"openvpn_executable"`
}

type HealthConfig struct {
	CheckInterval    time.Duration   `mapstructure:"check_interval"`
	Timeout          time.Duration   `mapstructure:"timeout"`
	FailureThreshold int             `mapstructure:"failure_threshold"`
	SpeedTest        SpeedTestConfig `mapstructure:"speed_test"`
}

type SpeedTestConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	Interval           time.Duration `mapstructure:"interval"`
	TestSizes          []string      `mapstructure:"test_sizes"`
	MaxDuration        time.Duration `mapstructure:"max_duration"`
	RandomizeEndpoints bool          `mapstructure:"randomize_endpoints"`
	// SelectedEndpoints allows specifying which built-in endpoints to use (by name)
	// If empty, all built-in endpoints will be used
	SelectedEndpoints []string `mapstructure:"selected_endpoints"`
}

type RecoveryConfig struct {
	MaxRetries    int           `mapstructure:"max_retries"`
	RestartDelay  time.Duration `mapstructure:"restart_delay"`
	ContainerExit bool          `mapstructure:"container_exit"`
}

type APIConfig struct {
	Listen string     `mapstructure:"listen"`
	Auth   AuthConfig `mapstructure:"auth"`
}

type AuthConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Token   string `mapstructure:"token"`
}

type NetworkConfig struct {
	LAN                string `mapstructure:"lan"`
	IP2LocationKey     string `mapstructure:"ip2location_key"`
	IP2LocationKeyFile string `mapstructure:"ip2location_key_file"`
}

// Load loads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set default values
	setDefaults(v)

	// Read config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("/vpn")
		v.AddConfigPath(".")
	}

	// Read environment variables
	v.AutomaticEnv()
	v.SetEnvPrefix("OPENXVPN")

	// Override with legacy environment variables for compatibility
	if user := os.Getenv("OPEN_VPN_USER"); user != "" {
		v.Set("vpn.username", user)
	}
	if password := os.Getenv("OPEN_VPN_PASSWORD"); password != "" {
		v.Set("vpn.password", password)
	}
	if passwordFile := os.Getenv("OPEN_VPN_PASSWORD_FILE"); passwordFile != "" {
		v.Set("vpn.password_file", passwordFile)
	}
	if server := os.Getenv("SERVER"); server != "" {
		v.Set("vpn.server", server)
	}
	if lan := os.Getenv("LAN"); lan != "" {
		v.Set("network.lan", lan)
	}
	if apiKey := os.Getenv("IP2LOCATION_IO_KEY"); apiKey != "" {
		v.Set("network.ip2location_key", apiKey)
	}
	if apiKeyFile := os.Getenv("IP2LOCATION_IO_KEY_FILE"); apiKeyFile != "" {
		v.Set("network.ip2location_key_file", apiKeyFile)
	}
	if openVPNExe := os.Getenv("OPENVPN_EXECUTABLE"); openVPNExe != "" {
		v.Set("vpn.openvpn_executable", openVPNExe)
	}
	if testMode := os.Getenv("TEST_MODE"); testMode != "" {
		v.Set("test_mode", testMode == "true" || testMode == "1")
	}

	// Try to read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Resolve IP2Location key from file if specified
	if err := config.resolveIP2LocationKey(); err != nil {
		return nil, fmt.Errorf("failed to resolve IP2Location key: %w", err)
	}

	// Resolve VPN password from file if specified
	if err := config.resolveVPNPassword(); err != nil {
		return nil, fmt.Errorf("failed to resolve VPN password: %w", err)
	}

	// Validate required fields
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("vpn.provider", "expressvpn")
	v.SetDefault("vpn.config_path", "/vpn/config")
	v.SetDefault("vpn.timeout", "30s")
	v.SetDefault("vpn.openvpn_executable", "openvpn")

	v.SetDefault("health.check_interval", "30s")
	v.SetDefault("health.timeout", "5s") // 5-second timeout for HTTP calls
	v.SetDefault("health.failure_threshold", 3)
	v.SetDefault("health.dns_leak_check", false)
	v.SetDefault("health.speed_test.enabled", false)
	v.SetDefault("health.speed_test.interval", "15m")
	v.SetDefault("health.speed_test.test_sizes", []string{"1MB", "5MB", "10MB"})
	v.SetDefault("health.speed_test.max_duration", "30s")
	v.SetDefault("health.speed_test.randomize_endpoints", true)

	v.SetDefault("recovery.max_retries", 3)
	v.SetDefault("recovery.restart_delay", "30s")
	v.SetDefault("recovery.container_exit", true)

	v.SetDefault("api.listen", ":80")
	v.SetDefault("api.enable_tls", false)
	v.SetDefault("api.auth.enabled", false)

	v.SetDefault("network.lan", "192.168.0.0/16")
}

// resolveIP2LocationKey resolves the IP2Location API key from file if specified
func (c *Config) resolveIP2LocationKey() error {
	// If key is already set directly, use it
	if c.Network.IP2LocationKey != "" {
		return nil
	}

	// If key file is specified, read from file
	if c.Network.IP2LocationKeyFile != "" {
		keyBytes, err := os.ReadFile(c.Network.IP2LocationKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read IP2Location key file %s: %w", c.Network.IP2LocationKeyFile, err)
		}

		// Trim whitespace and set the key
		c.Network.IP2LocationKey = strings.TrimSpace(string(keyBytes))

		if c.Network.IP2LocationKey == "" {
			return fmt.Errorf("IP2Location key file %s is empty", c.Network.IP2LocationKeyFile)
		}
	}

	return nil
}

// resolveVPNPassword resolves the VPN password from file if specified
func (c *Config) resolveVPNPassword() error {
	// If password is already set directly, use it
	if c.VPN.Password != "" {
		return nil
	}

	// If password file is specified, read from file
	if c.VPN.PasswordFile != "" {
		passwordBytes, err := os.ReadFile(c.VPN.PasswordFile)
		if err != nil {
			return fmt.Errorf("failed to read VPN password file %s: %w", c.VPN.PasswordFile, err)
		}

		// Trim whitespace and set the password
		c.VPN.Password = strings.TrimSpace(string(passwordBytes))

		if c.VPN.Password == "" {
			return fmt.Errorf("VPN password file %s is empty", c.VPN.PasswordFile)
		}
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Skip VPN credential validation in test mode
	if !c.TestMode && (c.VPN.Username == "" || c.VPN.Password == "") {
		return fmt.Errorf("VPN username and password are required")
	}

	if c.Health.CheckInterval <= 0 {
		return fmt.Errorf("health check interval must be positive")
	}

	if c.Recovery.MaxRetries < 0 {
		return fmt.Errorf("max retries must be non-negative")
	}

	return nil
}
