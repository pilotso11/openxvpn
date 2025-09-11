package health

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"openxvpn/pkg/config"
	"openxvpn/pkg/ipdetector"
	"openxvpn/pkg/speedtest"
	"openxvpn/pkg/vpn"
)

// Status represents the current health monitoring state and statistics
// for the VPN connection and related services.
type Status struct {
	// Status indicates the overall health state ("healthy", "unhealthy", "degraded")
	Status string `json:"status"`

	// LastCheck is the timestamp of the most recent health check
	LastCheck time.Time `json:"last_check"`

	// CurrentIP is the currently detected public IP address
	CurrentIP string `json:"current_ip"`

	// OriginalIP is the public IP address before VPN connection
	OriginalIP string `json:"original_ip"`

	// ConsecutiveFails tracks the number of consecutive health check failures
	ConsecutiveFails int `json:"consecutive_fails"`

	// TotalChecks is the total number of health checks performed
	TotalChecks int `json:"total_checks"`

	// SuccessRate is the percentage of successful health checks (0-100)
	SuccessRate float64 `json:"success_rate"`

	// RestartCount tracks how many times the VPN has been restarted
	RestartCount int `json:"restart_count"`

	// LastRestart is the timestamp of the most recent VPN restart
	LastRestart time.Time `json:"last_restart,omitempty"`

	// LastSpeedTest contains the results of the most recent speed test
	LastSpeedTest *speedtest.Result `json:"last_speed_test,omitempty"`

	// SpeedTestAggregate contains aggregated results from multiple speed tests
	SpeedTestAggregate *speedtest.AggregateResult `json:"speed_test_aggregate,omitempty"`
}

var _ Monitor = (*MonitorImpl)(nil)

// Monitor defines the interface for health monitoring functionality.
// The monitor runs periodic health checks on VPN connections and can
// trigger failure callbacks when issues are detected.
type Monitor interface {
	// Start begins the health monitoring process with the provided context.
	// The monitor will stop gracefully when the context is cancelled.
	Start(ctx context.Context)

	// GetStatus returns the current health monitoring status including
	// connection state, failure counts, and success rates.
	GetStatus() Status

	// AddFailureCallback registers a callback function that will be invoked
	// when health check failures exceed the configured threshold.
	AddFailureCallback(callback FailureCallback)

	// ForceCheck immediately performs a health check and returns the status.
	ForceCheck() Status

	// HandleRestart records a VPN restart attempt in the monitoring statistics.
	HandleRestart()

	// RunSpeedTestNow performs an immediate speed test if speed testing is enabled.
	RunSpeedTestNow(ctx context.Context) (*speedtest.Result, error)

	// SetMetricsCollector sets the metrics collector for tracking speed test results
	SetMetricsCollector(collector interface {
		RecordSpeedTestResult(speedMbps float64, success bool)
	})
}

// MonitorImpl is the concrete implementation of the Monitor interface.
// It manages periodic health checks, failure tracking, and recovery callbacks.
type MonitorImpl struct {
	// config holds the application configuration
	config *config.Config

	// vpnManager provides VPN management operations
	vpnManager vpn.Manager

	// logger provides structured logging
	logger *slog.Logger

	// status holds the current monitoring state (protected by mu)
	status Status
	// failureCount tracks total health check failures for success rate calculation
	failureCount int
	// successCount tracks total health check successes for success rate calculation
	successCount int

	// mu protects concurrent access to status and callback fields
	mu sync.RWMutex

	// ticker manages periodic health check scheduling
	ticker *time.Ticker

	// callbacks holds registered failure callback functions
	callbacks []FailureCallback

	// ipDetector provides IP address detection and geolocation services
	ipDetector ipdetector.Detector

	// speedTestTicker manages periodic speed test scheduling (optional)
	speedTestTicker *time.Ticker
	// speedTester provides bandwidth testing functionality (optional)
	speedTester speedtest.Tester
	// lastSpeedTestTime tracks when the last speed test was performed
	lastSpeedTestTime time.Time
	// metricsCollector tracks speed test metrics (optional)
	metricsCollector interface {
		RecordSpeedTestResult(speedMbps float64, success bool)
	}
}

// FailureCallback is invoked when health check failures exceed the configured threshold.
// It receives the current status and boolean flags indicating whether restart should be
// attempted and whether the container should exit after maximum retries are reached.
type FailureCallback func(status Status, shouldRestart bool, shouldExitContainer bool) error

// NewMonitor creates a new health monitor instance with the provided configuration,
// VPN manager, and logger. It optionally initializes speed testing if enabled in config.
func NewMonitor(cfg *config.Config, vpnMgr vpn.Manager, logger *slog.Logger) *MonitorImpl {
	monitor := &MonitorImpl{
		config:     cfg,
		vpnManager: vpnMgr,
		logger:     logger,
		ipDetector: vpnMgr.GetIPDetector(), // Reuse the VPN manager's IP detector
	}

	// Initialize speed tester if enabled in configuration
	if cfg.Health.SpeedTest.Enabled {
		monitor.speedTester = speedtest.NewTester(&cfg.Health.SpeedTest, logger)
		monitor.logger.Info("Speed testing enabled",
			"interval", cfg.Health.SpeedTest.Interval,
			"test_sizes", cfg.Health.SpeedTest.TestSizes,
			"randomize", cfg.Health.SpeedTest.RandomizeEndpoints)
	}

	return monitor
}

// Start begins the health monitoring process with the provided context.
// The monitor performs an initial health check, then runs periodic checks
// at the configured interval. If speed testing is enabled, it also runs
// periodic speed tests. The monitor stops gracefully when the context is cancelled.
func (m *MonitorImpl) Start(ctx context.Context) {
	m.logger.Info("Starting health monitor", "interval", m.config.Health.CheckInterval)

	m.ticker = time.NewTicker(m.config.Health.CheckInterval)
	defer m.ticker.Stop()

	// Start speed test ticker if enabled
	if m.speedTester != nil {
		m.speedTestTicker = time.NewTicker(m.config.Health.SpeedTest.Interval)
		defer m.speedTestTicker.Stop()
		m.logger.Info("Starting speed test monitor", "interval", m.config.Health.SpeedTest.Interval)
	}

	// Initial health check
	m.runHealthCheck()

	// Main monitoring loop
	for {
		if m.speedTestTicker != nil {
			select {
			case <-ctx.Done():
				m.logger.Info("Health monitor stopped due to context cancellation")
				return
			case <-m.ticker.C:
				m.runHealthCheck()
			case <-m.speedTestTicker.C:
				if m.speedTester != nil {
					m.runSpeedTest(ctx)
				}
			}
		} else {
			select {
			case <-ctx.Done():
				m.logger.Info("Health monitor stopped due to context cancellation")
				return
			case <-m.ticker.C:
				m.runHealthCheck()
			}
		}
	}
}

// GetStatus returns a copy of the current health monitoring status.
// This method is thread-safe and returns a snapshot of the status at the time of call.
func (m *MonitorImpl) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// AddFailureCallback registers a callback function to be invoked when health check
// failures exceed the configured threshold. Multiple callbacks can be registered
// and will be executed concurrently in separate goroutines when triggered.
func (m *MonitorImpl) AddFailureCallback(callback FailureCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, callback)
}

// runHealthCheck executes a single health check cycle and updates the monitoring status.
// This method performs the actual health verification, updates statistics, and triggers
// failure callbacks if the failure threshold is exceeded. It's thread-safe and updates
// all status fields atomically under mutex protection.
func (m *MonitorImpl) runHealthCheck() {
	m.logger.Debug("Running health check")

	start := time.Now()
	currentIP, originalIP, err := m.performHealthCheck()

	// Prepare values to update
	var shouldTriggerCallbacks bool
	var consecutiveFails int

	// Critical section - minimize mutex holding time
	func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		m.status.LastCheck = start
		m.status.TotalChecks++

		if err != nil {
			m.status.Status = "unhealthy"
			m.failureCount++
			m.status.ConsecutiveFails++
			consecutiveFails = m.status.ConsecutiveFails

			// Check if we've exceeded failure threshold
			if m.status.ConsecutiveFails >= m.config.Health.FailureThreshold {
				shouldTriggerCallbacks = true
			}
		} else {
			m.status.Status = "healthy"
			m.successCount++
			m.status.ConsecutiveFails = 0

			// Update IP information
			m.status.CurrentIP = currentIP
			m.status.OriginalIP = originalIP
		}

		// Update success rate
		if m.status.TotalChecks > 0 {
			m.status.SuccessRate = float64(m.successCount) / float64(m.status.TotalChecks) * 100
		}
	}()

	// Handle expensive operations outside the mutex
	if err != nil {
		m.logger.Warn("Health check failed", "error", err)
		if shouldTriggerCallbacks {
			m.logger.Error("Health check failure threshold exceeded",
				"consecutive_fails", consecutiveFails,
				"threshold", m.config.Health.FailureThreshold)

			// Trigger failure callbacks outside the mutex
			m.triggerFailureCallbacks()
		}
	} else {
		m.logger.Debug("Health check passed")
	}

	m.logger.Debug("Health check completed",
		"duration", time.Since(start))
}

// performHealthCheck does the actual health verification
func (m *MonitorImpl) performHealthCheck() (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.config.Health.Timeout)
	defer cancel()

	// Get VPN status to check if it's running
	vpnStatus := m.vpnManager.GetStatus()
	if vpnStatus.State != "connected" {
		return "", "", fmt.Errorf("VPN is not connected (state: %s)", vpnStatus.State)
	}

	// Get current IP and update status
	currentIP, err := m.ipDetector.GetCurrentIP(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to get current IP: %w", err)
	}

	// Also update the VPN manager's current IP for status reporting
	m.vpnManager.UpdateCurrentIP(currentIP)

	// Check if IP has changed from original (VPN is working)
	if currentIP == vpnStatus.OriginalIP {
		return "", "", fmt.Errorf("IP address unchanged from original (%s), VPN may not be working", currentIP)
	}

	m.logger.Debug("Health check passed",
		"original_ip", vpnStatus.OriginalIP,
		"current_ip", currentIP)

	return currentIP, vpnStatus.OriginalIP, nil
}

// triggerFailureCallbacks executes all registered failure callbacks concurrently
// when the health check failure threshold is exceeded. This method determines
// whether a restart should be attempted and whether the container should exit
// based on the current failure and retry counts. Callbacks are executed in
// separate goroutines to prevent blocking the main monitoring loop.
func (m *MonitorImpl) triggerFailureCallbacks() {
	status := m.status // Already holding lock

	// Determine if restart should be attempted based on failure count
	shouldRestart := status.ConsecutiveFails >= m.config.Health.FailureThreshold

	// Determine if container should exit based on restart count
	shouldExitContainer := status.RestartCount >= m.config.Recovery.MaxRetries

	for _, callback := range m.callbacks {
		go func(cb FailureCallback) {
			if err := cb(status, shouldRestart, shouldExitContainer); err != nil {
				m.logger.Error("Failure callback error", "error", err)
			}
		}(callback)
	}
}

// HandleRestart increments restart counter and updates last restart time
func (m *MonitorImpl) HandleRestart() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.status.RestartCount++
	m.status.LastRestart = time.Now()

	m.logger.Info("VPN restart recorded",
		"restart_count", m.status.RestartCount,
		"last_restart", m.status.LastRestart)
}

// ForceCheck runs an immediate health check
func (m *MonitorImpl) ForceCheck() Status {
	m.runHealthCheck()
	return m.GetStatus()
}

// runSpeedTest performs a bandwidth speed test using a randomized endpoint selection.
// This method is called periodically when speed testing is enabled and ensures that
// sufficient time has passed since the last test to avoid excessive bandwidth usage.
// The test results are stored in the monitoring status and logged for review.
func (m *MonitorImpl) runSpeedTest(ctx context.Context) {
	if m.speedTester == nil {
		return
	}

	m.logger.Debug("Running speed test")

	// Check if enough time has passed since last speed test
	if time.Since(m.lastSpeedTestTime) < m.config.Health.SpeedTest.Interval {
		return
	}

	result, err := m.speedTester.RunTest(ctx)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.lastSpeedTestTime = time.Now()

	if err != nil {
		m.logger.Warn("Speed test failed", "error", err)
		// Record failed speed test in metrics
		if m.metricsCollector != nil {
			m.metricsCollector.RecordSpeedTestResult(0.0, false)
		}
		return
	}

	if result != nil {
		m.status.LastSpeedTest = result
		// Record successful speed test in metrics
		if m.metricsCollector != nil {
			m.metricsCollector.RecordSpeedTestResult(result.SpeedMbps, true)
		}
		m.logger.Info("Speed test completed",
			"endpoint", result.Endpoint,
			"test_size", result.TestSize,
			"speed_mbps", fmt.Sprintf("%.2f", result.SpeedMbps),
			"duration", result.Duration)
	}
}

// RunSpeedTestNow forces an immediate speed test
func (m *MonitorImpl) RunSpeedTestNow(ctx context.Context) (*speedtest.Result, error) {
	if m.speedTester == nil {
		return nil, fmt.Errorf("speed testing is disabled")
	}

	result, err := m.speedTester.RunTest(ctx)

	m.mu.Lock()
	m.lastSpeedTestTime = time.Now()

	if err != nil {
		// Record failed speed test in metrics
		if m.metricsCollector != nil {
			m.metricsCollector.RecordSpeedTestResult(0.0, false)
		}
	} else if result != nil {
		m.status.LastSpeedTest = result
		// Record successful speed test in metrics
		if m.metricsCollector != nil {
			m.metricsCollector.RecordSpeedTestResult(result.SpeedMbps, true)
		}
	}
	m.mu.Unlock()

	return result, err
}

// RunMultipleSpeedTests runs multiple speed tests and aggregates results
func (m *MonitorImpl) RunMultipleSpeedTests(ctx context.Context, count int) ([]*speedtest.Result, *speedtest.AggregateResult, error) {
	if m.speedTester == nil {
		return nil, nil, fmt.Errorf("speed testing is disabled")
	}

	results, aggregate, err := m.speedTester.RunMultipleTests(ctx, count)

	if aggregate != nil {
		m.mu.Lock()
		m.status.SpeedTestAggregate = aggregate
		m.mu.Unlock()
	}

	return results, aggregate, err
}

// GetSpeedTestEndpoints returns available speed test endpoints
func (m *MonitorImpl) GetSpeedTestEndpoints() []string {
	if m.speedTester == nil {
		return []string{}
	}
	return m.speedTester.GetAvailableEndpoints()
}

// ValidateSpeedTestEndpoints checks if configured endpoints are reachable
func (m *MonitorImpl) ValidateSpeedTestEndpoints(ctx context.Context) map[string]bool {
	if m.speedTester == nil {
		return map[string]bool{}
	}
	return m.speedTester.ValidateEndpoints(ctx)
}

// SetMetricsCollector sets the metrics collector for tracking speed test results
func (m *MonitorImpl) SetMetricsCollector(collector interface {
	RecordSpeedTestResult(speedMbps float64, success bool)
}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metricsCollector = collector
}
