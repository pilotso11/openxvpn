package main

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"openxvpn/internal/testutils"
	"openxvpn/pkg/config"
	"openxvpn/pkg/health"
	"openxvpn/pkg/speedtest"
)

// MockHealthMonitor provides a consolidated mock implementation of health.Monitor
// that combines features needed by different test suites
type MockHealthMonitor struct {
	status              health.Status
	callbacks           []health.FailureCallback
	startCalled         bool
	running             bool
	forceErr            error
	shouldRestart       bool
	shouldExitContainer bool
	mu                  sync.RWMutex
}

// NewMockHealthMonitor creates a new mock health monitor with sensible defaults
func NewMockHealthMonitor() *MockHealthMonitor {
	return &MockHealthMonitor{
		status: health.Status{
			Status:           "healthy",
			ConsecutiveFails: 0,
			TotalChecks:      10,
			SuccessRate:      100.0,
		},
		callbacks: make([]health.FailureCallback, 0),
	}
}

// Builder methods for configuration

func (m *MockHealthMonitor) WithStatus(status health.Status) *MockHealthMonitor {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = status
	return m
}

func (m *MockHealthMonitor) WithError(err error) *MockHealthMonitor {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forceErr = err
	return m
}

func (m *MockHealthMonitor) WithRestartBehavior(shouldRestart, shouldExitContainer bool) *MockHealthMonitor {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldRestart = shouldRestart
	m.shouldExitContainer = shouldExitContainer
	return m
}

// Interface implementations

func (m *MockHealthMonitor) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled = true
	m.running = true
}

func (m *MockHealthMonitor) GetStatus() health.Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *MockHealthMonitor) AddFailureCallback(callback health.FailureCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, callback)
}

func (m *MockHealthMonitor) ForceCheck() health.Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *MockHealthMonitor) HandleRestart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Mock implementation
}

func (m *MockHealthMonitor) RunSpeedTestNow(ctx context.Context) (*speedtest.Result, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.forceErr != nil {
		return nil, m.forceErr
	}

	return &speedtest.Result{
		Endpoint:  "mock-endpoint",
		TestSize:  "1MB",
		SpeedMbps: 25.0,
		Success:   true,
		Timestamp: time.Now(),
	}, nil
}

func (m *MockHealthMonitor) SetMetricsCollector(collector interface {
	RecordSpeedTestResult(speed float64, success bool)
}) {
	// Mock implementation - no-op for testing
}

// Test utility methods

func (m *MockHealthMonitor) WasStartCalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.startCalled
}

func (m *MockHealthMonitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

func (m *MockHealthMonitor) GetCallbackCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.callbacks)
}

func (m *MockHealthMonitor) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled = false
	m.running = false
	m.forceErr = nil
	m.callbacks = make([]health.FailureCallback, 0)
	m.status = health.Status{
		Status:           "healthy",
		ConsecutiveFails: 0,
		TotalChecks:      10,
		SuccessRate:      100.0,
	}
}

func createTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func createTestConfig() *config.Config {
	return &config.Config{
		VPN: config.VPNConfig{
			Provider:   "test",
			ConfigPath: "/test/path",
		},
		Health: config.HealthConfig{
			CheckInterval:    time.Minute,
			FailureThreshold: 3,
		},
		Recovery: config.RecoveryConfig{
			MaxRetries:    5,
			ContainerExit: true,
		},
		API: config.APIConfig{
			Listen: ":8080",
		},
	}
}

func TestApplication_setupRecoveryCallbacks(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	vpnManager := testutils.NewMockVPNManager()
	monitor := NewMockHealthMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := &Application{
		config:     cfg,
		logger:     logger,
		vpnManager: vpnManager,
		monitor:    monitor,
		webServer:  nil, // Skip web server for testing
		ctx:        ctx,
		cancel:     cancel,
	}

	// Test that setupRecoveryCallbacks adds a callback
	initialCallbacks := monitor.GetCallbackCount()
	app.setupRecoveryCallbacks()

	assert.Equal(t, initialCallbacks+1, monitor.GetCallbackCount(), "Expected %d callbacks", initialCallbacks+1)
}

func TestApplication_shutdown(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	vpnManager := testutils.NewMockVPNManager()
	monitor := NewMockHealthMonitor()
	ctx, cancel := context.WithCancel(context.Background())

	app := &Application{
		config:     cfg,
		logger:     logger,
		vpnManager: vpnManager,
		monitor:    monitor,
		webServer:  nil, // Skip web server for testing
		ctx:        ctx,
		cancel:     cancel,
	}

	var wg sync.WaitGroup
	app.shutdown(&wg)

	assert.True(t, vpnManager.WasStopCalled(), "Expected VPN manager Stop to be called")

	// Check that context is cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		assert.Fail(t, "Expected context to be cancelled during shutdown")
	}
}

func TestApplication_waitForShutdown(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	ctx, cancel := context.WithCancel(context.Background())

	app := &Application{
		config: cfg,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}

	// Test context cancellation triggers shutdown
	done := make(chan bool)
	go func() {
		app.waitForShutdown()
		done <- true
	}()

	// Cancel context to trigger shutdown
	cancel()

	select {
	case <-done:
		// Success - waitForShutdown returned
	case <-time.After(2 * time.Second):
		assert.Fail(t, "Timeout waiting for shutdown")
	}
}

// Test that recovery callbacks work properly
func TestApplication_recoveryCallbackRestart(t *testing.T) {
	cfg := createTestConfig()
	logger := createTestLogger()
	vpnManager := testutils.NewMockVPNManager()
	monitor := NewMockHealthMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := &Application{
		config:     cfg,
		logger:     logger,
		vpnManager: vpnManager,
		monitor:    monitor,
		webServer:  nil,
		ctx:        ctx,
		cancel:     cancel,
	}

	app.setupRecoveryCallbacks()

	// Verify that we have a callback
	assert.Greater(t, monitor.GetCallbackCount(), 0, "No callbacks were added")

	// Test that the app correctly set up recovery callbacks
	// The actual callback testing would require more complex setup
	// to test the recovery logic, but verifying callback registration
	// is sufficient for this consolidation test
}

// Note: setupApplication is difficult to test in isolation due to its dependencies
// on config.Load, vpn.NewManager, etc. In a real scenario, we would need to
// refactor it to accept dependencies as parameters to make it more testable.
// For now, we test the components that can be tested in isolation.
