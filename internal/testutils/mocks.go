// Package testutils provides shared testing utilities and mocks for the openxvpn project.
// This package consolidates common test fixtures and mock implementations to reduce
// code duplication across test files.
package testutils

import (
	"context"
	"fmt"
	"sync"
	"time"

	"openxvpn/pkg/ipdetector"
	"openxvpn/pkg/metrics"
	"openxvpn/pkg/speedtest"
	"openxvpn/pkg/vpn"
)

// MockVPNManager provides a comprehensive mock implementation of vpn.Manager
// that supports all testing scenarios across the codebase. It combines functionality
// from the previous individual mock implementations into a single, configurable mock.
type MockVPNManager struct {
	// Core VPN status and configuration
	Status     vpn.Status
	ipDetector ipdetector.Detector

	// Error injection for testing failure scenarios
	startErr   error
	stopErr    error
	restartErr error

	// Call tracking for verifying method invocations
	mu          sync.RWMutex
	startCalled bool
	stopCalled  bool
	callHistory []string

	// Behavior control flags
	shouldFail bool
}

// NewMockVPNManager creates a new mock VPN manager with default settings.
// The mock is configured with reasonable defaults and can be customized
// using the provided setter methods.
func NewMockVPNManager() *MockVPNManager {
	return &MockVPNManager{
		Status: vpn.Status{
			State:      "connected",
			OriginalIP: "203.0.113.1", // Example original IP
			CurrentIP:  "192.0.2.1",   // Example current IP after VPN
			Server:     "test-server",
		},
		ipDetector:  &MockIPDetector{},
		callHistory: make([]string, 0),
	}
}

// Configuration methods for test setup

// WithStatus sets the VPN status returned by GetStatus()
func (m *MockVPNManager) WithStatus(status vpn.Status) *MockVPNManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Status = status
	return m
}

// WithIPDetector sets the IP detector instance
func (m *MockVPNManager) WithIPDetector(detector ipdetector.Detector) *MockVPNManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipDetector = detector
	return m
}

// WithStartError configures Start() to return the specified error
func (m *MockVPNManager) WithStartError(err error) *MockVPNManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startErr = err
	return m
}

// WithStopError configures Stop() to return the specified error
func (m *MockVPNManager) WithStopError(err error) *MockVPNManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopErr = err
	return m
}

// WithRestartError configures Restart() to return the specified error
func (m *MockVPNManager) WithRestartError(err error) *MockVPNManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restartErr = err
	return m
}

// WithFailureMode enables/disables general failure behavior
func (m *MockVPNManager) WithFailureMode(shouldFail bool) *MockVPNManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = shouldFail
	return m
}

// VPN Manager interface implementation

func (m *MockVPNManager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.startCalled = true
	m.callHistory = append(m.callHistory, "Start")

	if m.startErr != nil {
		return m.startErr
	}

	return nil
}

func (m *MockVPNManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stopCalled = true
	m.callHistory = append(m.callHistory, "Stop")

	if m.stopErr != nil {
		return m.stopErr
	}

	return nil
}

func (m *MockVPNManager) Restart(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callHistory = append(m.callHistory, "Restart")

	if m.shouldFail {
		return fmt.Errorf("mock restart failed")
	}

	if m.restartErr != nil {
		return m.restartErr
	}

	return nil
}

func (m *MockVPNManager) GetStatus() vpn.Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid races
	status := m.Status
	return status
}

func (m *MockVPNManager) UpdateCurrentIP(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Status.CurrentIP = ip
	m.callHistory = append(m.callHistory, fmt.Sprintf("UpdateCurrentIP(%s)", ip))
}

func (m *MockVPNManager) GetIPDetector() ipdetector.Detector {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.ipDetector
}

func (m *MockVPNManager) SetMetricsCollector(collector interface{ RecordVPNEvent(eventType string) }) {
	// Mock implementation - no-op for testing
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callHistory = append(m.callHistory, "SetMetricsCollector")
}

// Test assertion helpers

// WasStartCalled returns true if Start() was called
func (m *MockVPNManager) WasStartCalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.startCalled
}

// WasStopCalled returns true if Stop() was called
func (m *MockVPNManager) WasStopCalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stopCalled
}

// GetCallHistory returns the sequence of method calls made to this mock
func (m *MockVPNManager) GetCallHistory() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid races
	history := make([]string, len(m.callHistory))
	copy(history, m.callHistory)
	return history
}

// Reset clears all call tracking state for reuse in multiple test cases
func (m *MockVPNManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.startCalled = false
	m.stopCalled = false
	m.callHistory = m.callHistory[:0] // Clear slice but keep capacity
}

// MockIPDetector provides a mock implementation of ipdetector.Detector
type MockIPDetector struct {
	CurrentIP  string
	ShouldFail bool
	mu         sync.RWMutex
}

// NewMockIPDetector creates a new mock IP detector with default values
func NewMockIPDetector() *MockIPDetector {
	return &MockIPDetector{
		CurrentIP: "192.168.1.100",
	}
}

// WithCurrentIP sets the IP address returned by IP detection methods
func (m *MockIPDetector) WithCurrentIP(ip string) *MockIPDetector {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CurrentIP = ip
	return m
}

// WithFailure configures the detector to return errors
func (m *MockIPDetector) WithFailure(shouldFail bool) *MockIPDetector {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ShouldFail = shouldFail
	return m
}

func (m *MockIPDetector) GetCurrentIP(ctx context.Context) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ShouldFail {
		return "", fmt.Errorf("mock IP detection failed")
	}
	return m.CurrentIP, nil
}

func (m *MockIPDetector) GetIPInfo(ctx context.Context, ip string) (*ipdetector.IPInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ShouldFail {
		return nil, fmt.Errorf("mock IP info failed")
	}

	return &ipdetector.IPInfo{
		IP:      ip,
		Country: "US",
		City:    "Test City",
	}, nil
}

func (m *MockIPDetector) GetCurrentIPInfo(ctx context.Context) (*ipdetector.IPInfo, error) {
	ip, err := m.GetCurrentIP(ctx)
	if err != nil {
		return nil, err
	}
	return m.GetIPInfo(ctx, ip)
}

func (m *MockIPDetector) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ShouldFail {
		return fmt.Errorf("mock health check failed")
	}
	return nil
}

func (m *MockIPDetector) CheckIPChange(ctx context.Context, lastIP string) (bool, string, error) {
	ip, err := m.GetCurrentIP(ctx)
	if err != nil {
		return false, "", err
	}
	return ip != lastIP, ip, nil
}

func (m *MockIPDetector) GetRawIP2LocationData(ctx context.Context, ip string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ShouldFail {
		return nil, fmt.Errorf("mock raw data failed")
	}
	return []byte(`{"ip":"` + ip + `","country":"US"}`), nil
}

func (m *MockIPDetector) ClearCache() {
	// Mock implementation - no actual cache to clear
}

func (m *MockIPDetector) GetCacheStats() map[string]any {
	return map[string]any{
		"total_entries": 0,
		"cache_ttl":     "24h0m0s",
	}
}

func (m *MockIPDetector) SetMetricsCollector(collector *metrics.Collector) {
	// Mock implementation - no-op for testing
}

// MockSpeedTester provides a mock implementation of speedtest.Tester
type MockSpeedTester struct {
	shouldFail bool
	results    []*speedtest.Result
	endpoints  []string
	validation map[string]bool
	mu         sync.RWMutex
}

// NewMockSpeedTester creates a new mock speed tester
func NewMockSpeedTester() *MockSpeedTester {
	return &MockSpeedTester{
		endpoints: []string{"test-endpoint", "backup-endpoint"},
		validation: map[string]bool{
			"test-endpoint (1MB)": true,
			"test-endpoint (5MB)": true,
		},
	}
}

func (m *MockSpeedTester) RunTest(ctx context.Context) (*speedtest.Result, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldFail {
		return nil, fmt.Errorf("mock speed test failed")
	}
	return &speedtest.Result{
		Endpoint:  "test-endpoint",
		TestSize:  "1MB",
		URL:       "http://test.example.com/1mb",
		Duration:  time.Second,
		BytesRead: 1024 * 1024,
		SpeedMbps: 8.0,
		Success:   true,
		Timestamp: time.Now(),
	}, nil
}

func (m *MockSpeedTester) RunMultipleTests(ctx context.Context, count int) ([]*speedtest.Result, *speedtest.AggregateResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldFail {
		return nil, nil, fmt.Errorf("mock multiple speed tests failed")
	}

	results := make([]*speedtest.Result, count)
	for i := 0; i < count; i++ {
		results[i] = &speedtest.Result{
			Endpoint:  "test-endpoint",
			TestSize:  "1MB",
			URL:       "http://test.example.com/1mb",
			Duration:  time.Second,
			BytesRead: 1024 * 1024,
			SpeedMbps: float64(8 + i),
			Success:   true,
			Timestamp: time.Now(),
		}
	}

	aggregate := &speedtest.AggregateResult{
		TotalTests:       count,
		SuccessfulTests:  count,
		FailedTests:      0,
		SuccessRate:      100.0,
		AverageSpeedMbps: 10.0,
		FastestSpeedMbps: 15.0,
		SlowestSpeedMbps: 8.0,
		Timestamp:        time.Now(),
	}

	return results, aggregate, nil
}

func (m *MockSpeedTester) GetAvailableEndpoints() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.endpoints != nil {
		return m.endpoints
	}
	return []string{"test-endpoint", "backup-endpoint"}
}

func (m *MockSpeedTester) GetAvailableSizes() []string {
	return []string{"1MB", "5MB", "10MB"}
}

func (m *MockSpeedTester) GetEndpointInfo() map[string]map[string]string {
	return map[string]map[string]string{
		"test-endpoint": {
			"1MB": "http://test.example.com/1mb",
			"5MB": "http://test.example.com/5mb",
		},
	}
}

func (m *MockSpeedTester) ValidateEndpoints(ctx context.Context) map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.validation != nil {
		return m.validation
	}
	return map[string]bool{
		"test-endpoint (1MB)": true,
		"test-endpoint (5MB)": true,
	}
}

// Configuration methods

func (m *MockSpeedTester) WithFailure(shouldFail bool) *MockSpeedTester {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = shouldFail
	return m
}

func (m *MockSpeedTester) WithEndpoints(endpoints []string) *MockSpeedTester {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoints = endpoints
	return m
}

func (m *MockSpeedTester) WithValidation(validation map[string]bool) *MockSpeedTester {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.validation = validation
	return m
}
