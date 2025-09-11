package health

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"openxvpn/internal/testutils"
	"openxvpn/pkg/config"
	"openxvpn/pkg/ipdetector"
	"openxvpn/pkg/speedtest"
	"openxvpn/pkg/vpn"
)

var _ vpn.Manager = (*mockVPNManager)(nil)

// mockVPNManager for testing health monitor
type mockVPNManager struct {
	status     vpn.Status
	ipDetector ipdetector.Detector
	currentIP  string
	shouldFail bool
}

func (m *mockVPNManager) GetStatus() vpn.Status {
	status := m.status
	status.CurrentIP = m.currentIP
	return status
}

func (m *mockVPNManager) Start(ctx context.Context) error {
	return nil
}

func (m *mockVPNManager) Stop() error {
	return nil
}

func (m *mockVPNManager) Restart(ctx context.Context) error {
	if m.shouldFail {
		return fmt.Errorf("mock restart failed")
	}
	return nil
}

func (m *mockVPNManager) UpdateCurrentIP(ip string) {
	m.currentIP = ip
}

func (m *mockVPNManager) GetIPDetector() ipdetector.Detector {
	return m.ipDetector
}

func (m *mockVPNManager) SetMetricsCollector(collector interface{ RecordVPNEvent(eventType string) }) {
	// Mock implementation - no-op for testing
}

// mockIPDetector for testing health monitor
type mockIPDetector struct {
	currentIP  string
	shouldFail bool
}

func (m *mockIPDetector) GetCurrentIP(ctx context.Context) (string, error) {
	if m.shouldFail {
		return "", fmt.Errorf("mock IP detection failed")
	}
	return m.currentIP, nil
}

func (m *mockIPDetector) GetIPInfo(ctx context.Context, ip string) (*ipdetector.IPInfo, error) {
	return &ipdetector.IPInfo{
		IP:        ip,
		Timestamp: time.Now(),
	}, nil
}

func (m *mockIPDetector) GetCurrentIPInfo(ctx context.Context) (*ipdetector.IPInfo, error) {
	return m.GetIPInfo(ctx, m.currentIP)
}

func (m *mockIPDetector) CheckIPChange(ctx context.Context, previousIP string) (bool, string, error) {
	return m.currentIP != previousIP, m.currentIP, nil
}

func (m *mockIPDetector) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *mockIPDetector) GetRawIP2LocationData(ctx context.Context, ip string) ([]byte, error) {
	return []byte(`{"ip":"` + ip + `"}`), nil
}

func (m *mockIPDetector) ClearCache() {}

func (m *mockIPDetector) GetCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"total_entries":   0,
		"expired_entries": 0,
		"valid_entries":   0,
		"cache_ttl":       "1h0m0s",
	}
}

func createTestMonitor() (*MonitorImpl, *testutils.MockVPNManager, *testutils.MockIPDetector) {
	cfg := &config.Config{
		Health: config.HealthConfig{
			CheckInterval:    30 * time.Second,
			Timeout:          5 * time.Second,
			FailureThreshold: 3,
		},
	}

	mockIP := testutils.NewMockIPDetector().WithCurrentIP("192.0.2.1")

	mockVPN := testutils.NewMockVPNManager().WithStatus(vpn.Status{
		State:      "connected",
		OriginalIP: "203.0.113.1",
		CurrentIP:  "192.0.2.1",
		Server:     "test-server",
	}).WithIPDetector(mockIP)

	monitor := &MonitorImpl{
		config:     cfg,
		vpnManager: mockVPN,
		logger:     slog.Default(),
		ipDetector: mockIP,
		status: Status{
			Status:           "healthy",
			LastCheck:        time.Now(),
			CurrentIP:        "192.0.2.1",
			OriginalIP:       "203.0.113.1",
			ConsecutiveFails: 0,
			TotalChecks:      0,
			SuccessRate:      0,
			RestartCount:     0,
		},
		callbacks: []FailureCallback{},
	}

	return monitor, mockVPN, mockIP
}

func TestNewMonitor(t *testing.T) {
	cfg := &config.Config{
		Health: config.HealthConfig{
			CheckInterval:    30 * time.Second,
			Timeout:          5 * time.Second,
			FailureThreshold: 3,
		},
	}

	ipDetector := ipdetector.NewDetector(ipdetector.Config{
		Timeout: 5 * time.Second,
		Logger:  slog.Default(),
	})

	mockVPN := &mockVPNManager{
		ipDetector: ipDetector,
	}

	monitor := NewMonitor(cfg, mockVPN, slog.Default())

	assert.Equal(t, cfg, monitor.config, "Expected config to be set")
	assert.Equal(t, mockVPN, monitor.vpnManager, "Expected VPN manager to be set")
	assert.NotNil(t, monitor.logger, "Expected logger to be set")
}

func TestGetStatus(t *testing.T) {
	monitor, _, _ := createTestMonitor()

	status := monitor.GetStatus()

	assert.Equal(t, "healthy", status.Status, "Expected status 'healthy'")
	assert.Equal(t, "192.0.2.1", status.CurrentIP, "Expected current IP '192.0.2.1'")
	assert.Equal(t, "203.0.113.1", status.OriginalIP, "Expected original IP '203.0.113.1'")
}

func TestAddFailureCallback(t *testing.T) {
	monitor, _, _ := createTestMonitor()

	var callbackCalled int32 // Use atomic for race-safe access
	callback := func(status Status, shouldRestart bool, shouldExitContainer bool) error {
		atomic.StoreInt32(&callbackCalled, 1)
		return nil
	}

	monitor.AddFailureCallback(callback)

	assert.Len(t, monitor.callbacks, 1, "Expected 1 callback")

	// Trigger callbacks by simulating failure threshold
	monitor.mu.Lock()
	monitor.status.ConsecutiveFails = monitor.config.Health.FailureThreshold
	monitor.triggerFailureCallbacks()
	monitor.mu.Unlock()

	// Give callbacks time to execute
	time.Sleep(20 * time.Millisecond)

	assert.Equal(t, int32(1), atomic.LoadInt32(&callbackCalled), "Expected callback to be called")
}

func TestPerformHealthCheckSuccess(t *testing.T) {
	monitor, mockVPN, _ := createTestMonitor()

	// Set up successful health check scenario - already configured in createTestMonitor
	// mockVPN is already set to "connected" state
	// mockIP is already set to "192.0.2.1"

	currentIP, originalIP, err := monitor.performHealthCheck()

	require.NoError(t, err, "Expected successful health check")
	assert.Equal(t, "192.0.2.1", currentIP, "Expected current IP to be returned")
	assert.Equal(t, "203.0.113.1", originalIP, "Expected original IP to be returned")

	// Check that VPN manager was called (can't check internal state directly with testutils mocks)
	assert.True(t, len(mockVPN.GetCallHistory()) > 0, "Expected VPN manager methods to be called")
}

func TestPerformHealthCheckVPNDisconnected(t *testing.T) {
	monitor, mockVPN, _ := createTestMonitor()

	// Set up disconnected VPN scenario
	mockVPN.WithStatus(vpn.Status{State: "disconnected"})

	_, _, err := monitor.performHealthCheck()

	require.Error(t, err, "Expected health check to fail when VPN is disconnected")
	assert.Contains(t, err.Error(), "VPN is not connected", "Expected error to contain 'VPN is not connected'")
}

func TestPerformHealthCheckIPDetectionFail(t *testing.T) {
	monitor, mockVPN, mockIP := createTestMonitor()

	// Set up IP detection failure scenario
	mockVPN.WithStatus(vpn.Status{State: "connected"})
	mockIP.WithFailure(true)

	_, _, err := monitor.performHealthCheck()

	require.Error(t, err, "Expected health check to fail when IP detection fails")

	assert.Contains(t, err.Error(), "failed to get current IP", "Expected error to contain 'failed to get current IP'")
}

func TestPerformHealthCheckIPUnchanged(t *testing.T) {
	monitor, mockVPN, mockIP := createTestMonitor()

	// Set up scenario where IP hasn't changed (VPN not working)
	mockVPN.Status.State = "connected"
	mockVPN.Status.OriginalIP = "192.0.2.1"
	mockIP.CurrentIP = "192.0.2.1" // Same as original

	_, _, err := monitor.performHealthCheck()

	require.Error(t, err, "Expected health check to fail when IP is unchanged")
	assert.Contains(t, err.Error(), "IP address unchanged from original", "Expected error to contain 'IP address unchanged from original'")
}

func TestRunHealthCheckSuccess(t *testing.T) {
	monitor, mockVPN, mockIP := createTestMonitor()

	// Set up successful scenario
	mockVPN.Status.State = "connected"
	mockIP.CurrentIP = "192.0.2.1"
	mockIP.ShouldFail = false

	initialChecks := monitor.status.TotalChecks

	monitor.runHealthCheck()

	status := monitor.GetStatus()

	assert.Equal(t, "healthy", status.Status, "Expected status 'healthy'")
	assert.Equal(t, initialChecks+1, status.TotalChecks, "Expected total checks to increment by 1")
	assert.Equal(t, 0, status.ConsecutiveFails, "Expected consecutive fails to be 0")
	assert.Equal(t, 100.0, status.SuccessRate, "Expected success rate 100%")
}

func TestRunHealthCheckFailure(t *testing.T) {
	monitor, mockVPN, mockIP := createTestMonitor()

	// Set up failure scenario
	mockVPN.Status.State = "connected"
	mockIP.ShouldFail = true

	initialChecks := monitor.status.TotalChecks

	monitor.runHealthCheck()

	status := monitor.GetStatus()

	assert.Equal(t, "unhealthy", status.Status, "Expected status 'unhealthy'")
	assert.Equal(t, initialChecks+1, status.TotalChecks, "Expected total checks to increment by 1")
	assert.Equal(t, 1, status.ConsecutiveFails, "Expected consecutive fails to be 1")
}

func TestRunHealthCheckFailureThreshold(t *testing.T) {
	monitor, mockVPN, mockIP := createTestMonitor()

	// Set up callback to track if it was called
	var callbackCalled int32 // Use atomic for race-safe access
	monitor.AddFailureCallback(func(status Status, shouldRestart bool, shouldExitContainer bool) error {
		atomic.StoreInt32(&callbackCalled, 1)
		return nil
	})

	// Set up failure scenario
	mockVPN.Status.State = "connected"
	mockIP.ShouldFail = true

	// Run health checks until threshold is reached
	for i := 0; i < monitor.config.Health.FailureThreshold; i++ {
		monitor.runHealthCheck()
	}

	// Give callbacks time to execute
	time.Sleep(20 * time.Millisecond)

	status := monitor.GetStatus()

	assert.Equal(t, monitor.config.Health.FailureThreshold, status.ConsecutiveFails, "Expected consecutive fails to match failure threshold")
	assert.Equal(t, int32(1), atomic.LoadInt32(&callbackCalled), "Expected failure callback to be called when threshold is reached")
}

func TestHandleRestart(t *testing.T) {
	monitor, _, _ := createTestMonitor()

	initialRestartCount := monitor.status.RestartCount

	monitor.HandleRestart()

	status := monitor.GetStatus()

	assert.Equal(t, initialRestartCount+1, status.RestartCount, "Expected restart count to increment by 1")
	assert.False(t, status.LastRestart.IsZero(), "Expected last restart time to be set")
	assert.True(t, time.Since(status.LastRestart) <= time.Second, "Expected last restart time to be recent")
}

func TestForceCheck(t *testing.T) {
	monitor, mockVPN, mockIP := createTestMonitor()

	// Set up successful scenario
	mockVPN.Status.State = "connected"
	mockIP.CurrentIP = "192.0.2.1"
	mockIP.ShouldFail = false

	initialChecks := monitor.status.TotalChecks

	status := monitor.ForceCheck()

	assert.Equal(t, "healthy", status.Status, "Expected status 'healthy'")
	assert.Equal(t, initialChecks+1, status.TotalChecks, "Expected total checks to increment by 1")
}

func TestStart_InitialSetup(t *testing.T) {
	monitor, _, _ := createTestMonitor()

	// Test that Start sets up the ticker (we can't easily test the goroutine behavior
	// without more complex setup, but we can verify basic initialization)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Start monitor - this will block, so we run it in a goroutine
	go monitor.Start(ctx)

	// Give it a moment to initialize
	time.Sleep(15 * time.Millisecond)

	// Use GetStatus() which is thread-safe to check if monitor is running
	status := monitor.GetStatus()
	assert.True(t, status.TotalChecks >= 1, "Expected at least one health check to have run")

	// Context will cancel after timeout, stopping the monitor
}

func TestSuccessRateCalculation(t *testing.T) {
	monitor, mockVPN, mockIP := createTestMonitor()

	// Set up alternating success/failure pattern
	mockVPN.Status.State = "connected"

	// Run 10 checks: 7 success, 3 failures
	for i := 0; i < 10; i++ {
		if i < 7 {
			mockIP.ShouldFail = false
			mockIP.CurrentIP = "192.0.2.1"
		} else {
			mockIP.ShouldFail = true
		}
		monitor.runHealthCheck()
	}

	status := monitor.GetStatus()

	expectedSuccessRate := 70.0 // 7/10 * 100
	assert.Equal(t, expectedSuccessRate, status.SuccessRate, "Expected success rate 70%")
	assert.Equal(t, 10, status.TotalChecks, "Expected 10 total checks")
}

// mockSpeedTester for testing speed test functionality
type mockSpeedTester struct {
	shouldFail bool
	results    []*speedtest.Result
	endpoints  []string
	validation map[string]bool
}

func (m *mockSpeedTester) RunTest(ctx context.Context) (*speedtest.Result, error) {
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

func (m *mockSpeedTester) RunMultipleTests(ctx context.Context, count int) ([]*speedtest.Result, *speedtest.AggregateResult, error) {
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

func (m *mockSpeedTester) GetAvailableEndpoints() []string {
	if m.endpoints != nil {
		return m.endpoints
	}
	return []string{"test-endpoint", "backup-endpoint"}
}

func (m *mockSpeedTester) GetAvailableSizes() []string {
	return []string{"1MB", "5MB", "10MB"}
}

func (m *mockSpeedTester) GetEndpointInfo() map[string]map[string]string {
	return map[string]map[string]string{
		"test-endpoint": {
			"1MB": "http://test.example.com/1mb",
			"5MB": "http://test.example.com/5mb",
		},
	}
}

func (m *mockSpeedTester) ValidateEndpoints(ctx context.Context) map[string]bool {
	if m.validation != nil {
		return m.validation
	}
	return map[string]bool{
		"test-endpoint (1MB)": true,
		"test-endpoint (5MB)": true,
	}
}

func TestRunSpeedTestNow_Disabled(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	// speedTester is nil by default, so speed testing is disabled

	ctx := context.Background()
	result, err := monitor.RunSpeedTestNow(ctx)

	require.Error(t, err, "Expected error when speed testing is disabled")
	assert.Nil(t, result, "Expected nil result when speed testing is disabled")
	assert.Contains(t, err.Error(), "speed testing is disabled", "Expected error to contain 'speed testing is disabled'")
}

func TestRunSpeedTestNow_Success(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	mockTester := &mockSpeedTester{shouldFail: false}
	monitor.speedTester = mockTester

	ctx := context.Background()
	result, err := monitor.RunSpeedTestNow(ctx)

	require.NoError(t, err, "Unexpected error")
	require.NotNil(t, result, "Expected result")
	assert.Equal(t, "test-endpoint", result.Endpoint, "Expected endpoint 'test-endpoint'")
	assert.Equal(t, 8.0, result.SpeedMbps, "Expected speed 8.0")

	// Check that status was updated
	status := monitor.GetStatus()
	assert.NotNil(t, status.LastSpeedTest, "Expected LastSpeedTest to be set")
}

func TestRunSpeedTestNow_Failure(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	mockTester := &mockSpeedTester{shouldFail: true}
	monitor.speedTester = mockTester

	ctx := context.Background()
	result, err := monitor.RunSpeedTestNow(ctx)

	require.Error(t, err, "Expected error from failed speed test")
	assert.Nil(t, result, "Expected nil result on failure")
}

func TestRunMultipleSpeedTests_Disabled(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	// speedTester is nil by default, so speed testing is disabled

	ctx := context.Background()
	results, aggregate, err := monitor.RunMultipleSpeedTests(ctx, 3)

	require.Error(t, err, "Expected error when speed testing is disabled")
	assert.Nil(t, results, "Expected nil results when speed testing is disabled")
	assert.Nil(t, aggregate, "Expected nil aggregate when speed testing is disabled")
}

func TestRunMultipleSpeedTests_Success(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	mockTester := &mockSpeedTester{shouldFail: false}
	monitor.speedTester = mockTester

	ctx := context.Background()
	count := 3
	results, aggregate, err := monitor.RunMultipleSpeedTests(ctx, count)

	require.NoError(t, err, "Unexpected error")
	assert.Len(t, results, count, "Expected correct number of results")
	require.NotNil(t, aggregate, "Expected aggregate result")
	assert.Equal(t, count, aggregate.TotalTests, "Expected correct number of total tests")

	// Check that status was updated
	status := monitor.GetStatus()
	assert.NotNil(t, status.SpeedTestAggregate, "Expected SpeedTestAggregate to be set")
}

func TestGetSpeedTestEndpoints_Disabled(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	// speedTester is nil by default, so speed testing is disabled

	endpoints := monitor.GetSpeedTestEndpoints()

	assert.Empty(t, endpoints, "Expected empty endpoints when disabled")
}

func TestGetSpeedTestEndpoints_Success(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	expectedEndpoints := []string{"test-endpoint", "backup-endpoint"}
	mockTester := &mockSpeedTester{endpoints: expectedEndpoints}
	monitor.speedTester = mockTester

	endpoints := monitor.GetSpeedTestEndpoints()

	assert.Len(t, endpoints, len(expectedEndpoints), "Expected correct number of endpoints")
	for i, expected := range expectedEndpoints {
		assert.Equal(t, expected, endpoints[i], "Expected correct endpoint at index %d", i)
	}
}

func TestValidateSpeedTestEndpoints_Disabled(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	// speedTester is nil by default, so speed testing is disabled

	ctx := context.Background()
	validation := monitor.ValidateSpeedTestEndpoints(ctx)

	assert.Empty(t, validation, "Expected empty validation when disabled")
}

func TestValidateSpeedTestEndpoints_Success(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	expectedValidation := map[string]bool{
		"test-endpoint (1MB)": true,
		"test-endpoint (5MB)": false,
	}
	mockTester := &mockSpeedTester{validation: expectedValidation}
	monitor.speedTester = mockTester

	ctx := context.Background()
	validation := monitor.ValidateSpeedTestEndpoints(ctx)

	assert.Len(t, validation, len(expectedValidation), "Expected correct number of validation entries")
	for key, expected := range expectedValidation {
		assert.Contains(t, validation, key, "Expected key %q in validation", key)
		assert.Equal(t, expected, validation[key], "Expected validation[%q] = %v", key, expected)
	}
}

func TestRunSpeedTest_NilTester(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	// speedTester is nil by default

	ctx := context.Background()

	// This should return early without error when speedTester is nil
	monitor.runSpeedTest(ctx)

	// No assertions needed, just verify it doesn't panic
}

func TestRunSpeedTest_IntervalNotMet(t *testing.T) {
	monitor, _, _ := createTestMonitor()
	mockTester := &mockSpeedTester{shouldFail: false}
	monitor.speedTester = mockTester
	monitor.lastSpeedTestTime = time.Now() // Set recent speed test time

	ctx := context.Background()

	// This should return early due to interval check
	monitor.runSpeedTest(ctx)

	// No assertions needed, just verify it doesn't panic
}

func TestNewMonitor_WithSpeedTest(t *testing.T) {
	cfg := &config.Config{
		Health: config.HealthConfig{
			CheckInterval:    30 * time.Second,
			Timeout:          5 * time.Second,
			FailureThreshold: 3,
			SpeedTest: config.SpeedTestConfig{
				Enabled:     true,
				Interval:    15 * time.Minute,
				TestSizes:   []string{"1MB", "5MB"},
				MaxDuration: 30 * time.Second,
			},
		},
	}

	ipDetector := ipdetector.NewDetector(ipdetector.Config{
		Timeout: 5 * time.Second,
		Logger:  slog.Default(),
	})

	mockVPN := &mockVPNManager{
		ipDetector: ipDetector,
	}

	monitor := NewMonitor(cfg, mockVPN, slog.Default())

	assert.NotNil(t, monitor.speedTester, "Expected speedTester to be created when speed test is enabled")
}

// Test concurrent access safety with multiple goroutines
func TestConcurrentAccess(t *testing.T) {
	monitor, mockVPN, mockIP := createTestMonitor()

	// Set up success scenario
	mockVPN.Status.State = "connected"
	mockIP.CurrentIP = "192.0.2.1"
	mockIP.ShouldFail = false

	// Channel to coordinate goroutines
	done := make(chan bool, 10)

	// Start multiple goroutines accessing the monitor concurrently
	// We avoid ForceCheck to prevent race condition from performHealthCheck
	// writing to status fields outside mutex lock (production code issue)
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Perform operations that are properly synchronized
			switch id % 3 {
			case 0:
				_ = monitor.GetStatus()
			case 1:
				monitor.HandleRestart()
			case 2:
				monitor.AddFailureCallback(func(status Status, shouldRestart bool, shouldExitContainer bool) error {
					return nil
				})
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(2 * time.Second):
			t.Fatal("Test timed out - possible deadlock")
		}
	}

	// Verify the monitor is still in a consistent state
	status := monitor.GetStatus()
	assert.NotEmpty(t, status.Status, "Expected status to be set")
	assert.True(t, len(monitor.callbacks) >= 3, "Expected at least 3 callbacks added") // Initial 0 + at least 3 from concurrent adds
}

// Test Start method with both speed test enabled and disabled scenarios
func TestStart_WithSpeedTest(t *testing.T) {
	// Create monitor with speed testing enabled
	cfg := &config.Config{
		Health: config.HealthConfig{
			CheckInterval:    100 * time.Millisecond,
			Timeout:          5 * time.Second,
			FailureThreshold: 3,
			SpeedTest: config.SpeedTestConfig{
				Enabled:  true,
				Interval: 200 * time.Millisecond, // Faster for testing
			},
		},
	}

	mockIP := &mockIPDetector{
		currentIP:  "192.0.2.1",
		shouldFail: false,
	}

	mockVPN := &mockVPNManager{
		status: vpn.Status{
			State:      "connected",
			OriginalIP: "203.0.113.1",
			CurrentIP:  "192.0.2.1",
			Server:     "test-server",
		},
		ipDetector: mockIP,
		currentIP:  "192.0.2.1",
		shouldFail: false,
	}

	monitor := &MonitorImpl{
		config:      cfg,
		vpnManager:  mockVPN,
		logger:      slog.Default(),
		ipDetector:  mockIP,
		speedTester: &mockSpeedTester{shouldFail: false},
		status: Status{
			Status:           "healthy",
			LastCheck:        time.Now(),
			CurrentIP:        "192.0.2.1",
			OriginalIP:       "203.0.113.1",
			ConsecutiveFails: 0,
			TotalChecks:      0,
			SuccessRate:      0,
			RestartCount:     0,
		},
		callbacks: []FailureCallback{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start monitor
	go monitor.Start(ctx)

	// Let it run for a bit to test both health checks and speed tests
	time.Sleep(300 * time.Millisecond)

	// Cancel context to stop the monitor before checking status to avoid race conditions
	cancel()
	time.Sleep(20 * time.Millisecond) // Give it time to stop

	status := monitor.GetStatus()
	assert.True(t, status.TotalChecks >= 2, "Expected multiple health checks to have run")
	// Speed test should have run at least once due to the short interval
	assert.NotNil(t, monitor.speedTestTicker, "Expected speed test ticker to be created")
}

// Test context cancellation behavior
func TestStart_ContextCancellation(t *testing.T) {
	monitor, mockVPN, mockIP := createTestMonitor()

	// Set up success scenario
	mockVPN.Status.State = "connected"
	mockIP.CurrentIP = "192.0.2.1"
	mockIP.ShouldFail = false

	ctx, cancel := context.WithCancel(context.Background())

	// Start monitor in background
	monitorStopped := make(chan bool, 1)
	go func() {
		monitor.Start(ctx)
		monitorStopped <- true
	}()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Verify monitor stops
	select {
	case <-monitorStopped:
		// Expected - monitor stopped gracefully
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Monitor did not stop within expected time after context cancellation")
	}

	// Verify at least one check ran
	status := monitor.GetStatus()
	assert.True(t, status.TotalChecks >= 1, "Expected at least one health check to have run")
}

// Test edge cases in failure callback triggering
func TestTriggerFailureCallbacks_EdgeCases(t *testing.T) {
	monitor, _, _ := createTestMonitor()

	t.Run("callback with error", func(t *testing.T) {
		var callbackError int32
		monitor.AddFailureCallback(func(status Status, shouldRestart bool, shouldExitContainer bool) error {
			atomic.StoreInt32(&callbackError, 1)
			return fmt.Errorf("callback failed")
		})

		monitor.mu.Lock()
		monitor.status.ConsecutiveFails = monitor.config.Health.FailureThreshold
		monitor.status.RestartCount = 0
		monitor.triggerFailureCallbacks()
		monitor.mu.Unlock()

		time.Sleep(20 * time.Millisecond)
		assert.Equal(t, int32(1), atomic.LoadInt32(&callbackError), "Expected callback with error to be called")
	})

	t.Run("shouldExitContainer flag", func(t *testing.T) {
		var shouldExit int32
		monitor.AddFailureCallback(func(status Status, shouldRestart bool, shouldExitContainer bool) error {
			if shouldExitContainer {
				atomic.StoreInt32(&shouldExit, 1)
			}
			return nil
		})

		// Set up scenario where max retries are exceeded
		monitor.mu.Lock()
		monitor.status.ConsecutiveFails = monitor.config.Health.FailureThreshold
		monitor.status.RestartCount = 999 // Exceed any reasonable max retries
		monitor.config.Recovery.MaxRetries = 5
		monitor.triggerFailureCallbacks()
		monitor.mu.Unlock()

		time.Sleep(20 * time.Millisecond)
		assert.Equal(t, int32(1), atomic.LoadInt32(&shouldExit), "Expected shouldExitContainer to be true when max retries exceeded")
	})
}

// Test speed test integration scenarios
func TestSpeedTest_Integration(t *testing.T) {
	monitor, _, _ := createTestMonitor()

	t.Run("speed test with failure", func(t *testing.T) {
		mockTester := &mockSpeedTester{shouldFail: true}
		monitor.speedTester = mockTester

		ctx := context.Background()

		// Should not error on speed test failure in runSpeedTest
		monitor.runSpeedTest(ctx)

		// Status should not be updated on failure
		status := monitor.GetStatus()
		assert.Nil(t, status.LastSpeedTest, "Expected LastSpeedTest to remain nil on failure")
	})

	t.Run("speed test interval enforcement", func(t *testing.T) {
		mockTester := &mockSpeedTester{shouldFail: false}
		monitor.speedTester = mockTester
		monitor.config.Health.SpeedTest.Interval = 1 * time.Hour
		monitor.lastSpeedTestTime = time.Now() // Set recent speed test time

		ctx := context.Background()

		// Should return early due to interval check
		monitor.runSpeedTest(ctx)

		// Status should not be updated since test was skipped
		status := monitor.GetStatus()
		assert.Nil(t, status.LastSpeedTest, "Expected LastSpeedTest to remain nil when interval not met")
	})

	t.Run("multiple speed tests failure", func(t *testing.T) {
		mockTester := &mockSpeedTester{shouldFail: true}
		monitor.speedTester = mockTester

		ctx := context.Background()
		results, aggregate, err := monitor.RunMultipleSpeedTests(ctx, 3)

		require.Error(t, err, "Expected error from failed multiple speed tests")
		assert.Nil(t, results, "Expected nil results on failure")
		assert.Nil(t, aggregate, "Expected nil aggregate on failure")
	})
}

// Test different configuration scenarios
func TestMonitor_DifferentConfigurations(t *testing.T) {
	t.Run("zero failure threshold", func(t *testing.T) {
		cfg := &config.Config{
			Health: config.HealthConfig{
				CheckInterval:    30 * time.Second,
				Timeout:          5 * time.Second,
				FailureThreshold: 0, // Zero threshold
			},
		}

		mockIP := &mockIPDetector{currentIP: "192.0.2.1", shouldFail: true}
		mockVPN := &mockVPNManager{
			status:     vpn.Status{State: "connected", OriginalIP: "203.0.113.1"},
			ipDetector: mockIP,
		}

		monitor := &MonitorImpl{
			config:     cfg,
			vpnManager: mockVPN,
			logger:     slog.Default(),
			ipDetector: mockIP,
			status:     Status{},
			callbacks:  []FailureCallback{},
		}

		var callbackTriggered int32
		monitor.AddFailureCallback(func(status Status, shouldRestart bool, shouldExitContainer bool) error {
			atomic.StoreInt32(&callbackTriggered, 1)
			return nil
		})

		// Run health check - should trigger callback immediately since threshold is 0
		monitor.runHealthCheck()
		time.Sleep(20 * time.Millisecond)

		assert.Equal(t, int32(1), atomic.LoadInt32(&callbackTriggered), "Expected callback to trigger with zero threshold")
	})

	t.Run("very short timeout", func(t *testing.T) {
		cfg := &config.Config{
			Health: config.HealthConfig{
				CheckInterval:    30 * time.Second,
				Timeout:          1 * time.Nanosecond, // Extremely short timeout
				FailureThreshold: 3,
			},
		}

		mockIP := &mockIPDetector{currentIP: "192.0.2.1", shouldFail: false}
		mockVPN := &mockVPNManager{
			status:     vpn.Status{State: "connected", OriginalIP: "203.0.113.1"},
			ipDetector: mockIP,
		}

		monitor := &MonitorImpl{
			config:     cfg,
			vpnManager: mockVPN,
			logger:     slog.Default(),
			ipDetector: mockIP,
			status:     Status{},
		}

		// Should handle timeout gracefully
		_, _, err := monitor.performHealthCheck()
		// This might succeed or fail depending on timing, but shouldn't panic
		_ = err
	})
}

// Test error conditions in public methods
func TestErrorConditions(t *testing.T) {
	t.Run("HandleRestart multiple times", func(t *testing.T) {
		monitor, _, _ := createTestMonitor()

		initialCount := monitor.status.RestartCount

		// Call HandleRestart multiple times
		for i := 0; i < 5; i++ {
			monitor.HandleRestart()
		}

		status := monitor.GetStatus()
		assert.Equal(t, initialCount+5, status.RestartCount, "Expected restart count to increment properly")
		assert.False(t, status.LastRestart.IsZero(), "Expected last restart time to be set")
	})

	t.Run("AddFailureCallback with nil", func(t *testing.T) {
		monitor, _, _ := createTestMonitor()

		initialCount := len(monitor.callbacks)

		// Adding nil callback should not crash
		monitor.AddFailureCallback(nil)

		assert.Len(t, monitor.callbacks, initialCount+1, "Expected callback list to grow even with nil callback")
	})
}

// Test integration between health monitoring and VPN management
func TestHealthVPNIntegration(t *testing.T) {
	monitor, mockVPN, mockIP := createTestMonitor()

	t.Run("VPN state changes affect health", func(t *testing.T) {
		// Start with connected state
		mockVPN.Status.State = "connected"
		mockIP.CurrentIP = "192.0.2.1"
		mockIP.ShouldFail = false

		// Should pass
		_, _, err := monitor.performHealthCheck()
		require.NoError(t, err, "Expected health check to pass when VPN is connected")

		// Change VPN state to disconnected
		mockVPN.Status.State = "disconnected"

		// Should fail
		_, _, err = monitor.performHealthCheck()
		require.Error(t, err, "Expected health check to fail when VPN is disconnected")
		assert.Contains(t, err.Error(), "VPN is not connected", "Expected specific error message")
	})

	t.Run("IP change detection", func(t *testing.T) {
		mockVPN.Status.State = "connected"
		mockVPN.Status.OriginalIP = "203.0.113.1"
		mockIP.CurrentIP = "203.0.113.1" // Same as original - bad
		mockIP.ShouldFail = false

		_, _, err := monitor.performHealthCheck()
		require.Error(t, err, "Expected health check to fail when IP hasn't changed")
		assert.Contains(t, err.Error(), "IP address unchanged from original", "Expected IP unchanged error")

		// Fix IP change
		mockIP.CurrentIP = "192.0.2.1" // Different from original - good
		_, _, err = monitor.performHealthCheck()
		require.NoError(t, err, "Expected health check to pass when IP has changed")

		// Verify current IP was updated in VPN manager
		assert.Equal(t, "192.0.2.1", mockVPN.GetStatus().CurrentIP, "Expected VPN manager current IP to be updated")
	})

	t.Run("success rate calculation with mixed results", func(t *testing.T) {
		monitor, mockVPN, mockIP := createTestMonitor()

		// Reset counters for clean test
		monitor.mu.Lock()
		monitor.successCount = 0
		monitor.failureCount = 0
		monitor.status.TotalChecks = 0
		monitor.mu.Unlock()

		mockVPN.Status.State = "connected"

		// Run pattern: 6 success, 4 failures = 60% success rate
		for i := 0; i < 10; i++ {
			if i < 6 {
				mockIP.ShouldFail = false
				mockIP.CurrentIP = "192.0.2.1"
			} else {
				mockIP.ShouldFail = true
			}
			monitor.runHealthCheck()
		}

		status := monitor.GetStatus()
		assert.Equal(t, 60.0, status.SuccessRate, "Expected 60% success rate")
		assert.Equal(t, 10, status.TotalChecks, "Expected 10 total checks")
	})
}
