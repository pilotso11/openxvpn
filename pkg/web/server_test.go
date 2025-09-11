package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"openxvpn/pkg/config"
	"openxvpn/pkg/health"
	"openxvpn/pkg/ipdetector"
	"openxvpn/pkg/metrics"
	"openxvpn/pkg/speedtest"
	"openxvpn/pkg/vpn"
)

// mockVPNManager implements the VPN manager interface for testing
type mockVPNManager struct {
	status       vpn.Status
	ipDetector   ipdetector.Detector
	restartError error
}

func (m *mockVPNManager) GetStatus() vpn.Status {
	return m.status
}

func (m *mockVPNManager) Start(ctx context.Context) error {
	return nil
}

func (m *mockVPNManager) Stop() error {
	return nil
}

func (m *mockVPNManager) Restart(ctx context.Context) error {
	return m.restartError
}

func (m *mockVPNManager) UpdateCurrentIP(ip string) {
	m.status.CurrentIP = ip
}

func (m *mockVPNManager) GetIPDetector() ipdetector.Detector {
	return m.ipDetector
}

func (m *mockVPNManager) SetMetricsCollector(collector interface{ RecordVPNEvent(eventType string) }) {
	// Mock implementation - do nothing
}

// mockIPDetector implements the IP detector interface for testing
type mockIPDetector struct {
	currentIP      string
	currentIPError error
	ipInfo         *ipdetector.IPInfo
	ipInfoError    error
	rawData        []byte
	rawDataError   error
	cacheStats     map[string]any
	cacheCleared   bool
}

func (m *mockIPDetector) GetCurrentIP(ctx context.Context) (string, error) {
	return m.currentIP, m.currentIPError
}

func (m *mockIPDetector) GetIPInfo(ctx context.Context, ip string) (*ipdetector.IPInfo, error) {
	return m.ipInfo, m.ipInfoError
}

func (m *mockIPDetector) GetCurrentIPInfo(ctx context.Context) (*ipdetector.IPInfo, error) {
	return m.ipInfo, m.ipInfoError
}

func (m *mockIPDetector) CheckIPChange(ctx context.Context, previousIP string) (bool, string, error) {
	return m.currentIP != previousIP, m.currentIP, m.currentIPError
}

func (m *mockIPDetector) HealthCheck(ctx context.Context) error {
	return m.currentIPError
}

func (m *mockIPDetector) GetRawIP2LocationData(ctx context.Context, ip string) ([]byte, error) {
	return m.rawData, m.rawDataError
}

func (m *mockIPDetector) GetCacheStats() map[string]any {
	return m.cacheStats
}

func (m *mockIPDetector) ClearCache() {
	m.cacheCleared = true
}

func (m *mockIPDetector) SetMetricsCollector(collector *metrics.Collector) {
	// Mock implementation - no-op for testing
}

// Ensure mockVPNManager implements the vpn.Manager interface
var _ vpn.Manager = (*mockVPNManager)(nil)

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
	RecordSpeedTestResult(speedMbps float64, success bool)
}) {
	// Mock implementation - do nothing
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

func createTestServer() (*Server, *mockVPNManager, *MockHealthMonitor) {
	cfg := &config.Config{
		API: config.APIConfig{
			Listen: ":8080",
			Auth: config.AuthConfig{
				Enabled: false,
			},
		},
		VPN: config.VPNConfig{
			Server: "",
		},
	}

	mockIPDet := &mockIPDetector{
		currentIP: "192.0.2.1",
		ipInfo: &ipdetector.IPInfo{
			IP:        "192.0.2.1",
			Country:   "Australia",
			Region:    "Victoria",
			City:      "Melbourne",
			ISP:       "Test ISP",
			Latitude:  -37.8136,
			Longitude: 144.9631,
			Timestamp: time.Now(),
		},
		rawData: []byte(`{"ip":"192.0.2.1","country_name":"Australia","city_name":"Melbourne"}`),
		cacheStats: map[string]any{
			"total_entries":   10,
			"valid_entries":   8,
			"expired_entries": 2,
		},
	}

	mockVPN := &mockVPNManager{
		status: vpn.Status{
			State:      "connected",
			OriginalIP: "203.0.113.1",
			CurrentIP:  "192.0.2.1",
			Uptime:     "02:34:12",
			Server:     "australia-melbourne",
		},
		ipDetector: mockIPDet,
	}

	mockHealth := NewMockHealthMonitor().WithStatus(health.Status{
		Status:           "healthy",
		LastCheck:        time.Now().Add(-30 * time.Second),
		CurrentIP:        "192.0.2.1",
		OriginalIP:       "203.0.113.1",
		ConsecutiveFails: 0,
		TotalChecks:      100,
		SuccessRate:      99.5,
		RestartCount:     1,
		LastRestart:      time.Now().Add(-2 * time.Hour),
	})

	server := NewServer(cfg, mockVPN, mockHealth, slog.Default())
	return server, mockVPN, mockHealth
}

func TestHealthEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		vpnState       string
		healthStatus   string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "healthy VPN",
			vpnState:       "connected",
			healthStatus:   "healthy",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "unhealthy VPN",
			vpnState:       "connected",
			healthStatus:   "unhealthy",
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "disconnected VPN",
			vpnState:       "disconnected",
			healthStatus:   "healthy",
			expectedStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with specific test state
			server, mockVPN, _ := createTestServer()
			mockVPN.status.State = tt.vpnState

			// Create health monitor with specific status
			mockHealth := NewMockHealthMonitor().WithStatus(health.Status{
				Status: tt.healthStatus,
			})
			server.monitor = mockHealth

			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()

			server.handleHealth(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "Expected status")

			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody, "Expected body to contain")
			}
		})
	}
}

func TestHealthEndpointMethodNotAllowed(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("POST", "/health", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code, "Expected status")
}

func TestStatusEndpoint(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()

	server.handleStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected status")

	var response StatusResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	assert.Equal(t, "connected", response.Status, "Expected status 'connected'")
	assert.Equal(t, "192.0.2.1", response.Network.CurrentIP, "Expected current IP '192.0.2.1'")
	assert.Equal(t, "healthy", response.Health.Status, "Expected health status 'healthy'")
	assert.Equal(t, 1, response.Reliability.RestartCount, "Expected restart count 1")
}

func TestLegacyStatusEndpoint(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()

	server.handleLegacyStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected status")

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	assert.Equal(t, "healthy", response["status"], "Expected status 'healthy'")
	assert.Equal(t, "192.0.2.1", response["ip"], "Expected IP '192.0.2.1'")
}

func TestReconnectEndpoint(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("POST", "/api/v1/reconnect", nil)
	w := httptest.NewRecorder()

	server.handleReconnect(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected status")

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	assert.Equal(t, "reconnecting", response["status"], "Expected status 'reconnecting'")
}

func TestReconnectEndpointWithServerChange(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("POST", "/api/v1/reconnect?server=new-server", nil)
	w := httptest.NewRecorder()

	serverBefore := server.config.VPN.Server
	server.handleReconnect(w, req)
	serverAfter := server.config.VPN.Server

	assert.Equal(t, http.StatusOK, w.Code, "Expected status")

	assert.NotEqual(t, serverBefore, serverAfter, "server has not been updated")
	assert.Equal(t, "new-server", serverAfter, "server has not been updated")

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	assert.Equal(t, "reconnecting", response["status"], "status is not reconnecting")
}

func TestReconnectEndpointMethodNotAllowed(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("GET", "/api/v1/reconnect", nil)
	w := httptest.NewRecorder()

	server.handleReconnect(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code, "Expected status")
}

func TestForceHealthCheckEndpoint(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("POST", "/api/v1/healthcheck", nil)
	w := httptest.NewRecorder()

	server.handleForceHealthCheck(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected status")

	var response health.Status
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	assert.Equal(t, "healthy", response.Status, "Expected status 'healthy'")
}

func TestCacheStatsEndpoint(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("GET", "/api/v1/cache/stats", nil)
	w := httptest.NewRecorder()

	server.handleCacheStats(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected status")

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Check that response has expected fields
	assert.Contains(t, response, "total_entries")
	assert.Contains(t, response, "expired_entries")
	assert.Contains(t, response, "valid_entries")
}

func TestCacheClearEndpoint(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("POST", "/api/v1/cache/clear", nil)
	w := httptest.NewRecorder()

	server.handleCacheClear(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected status")

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	assert.Equal(t, "success", response["status"], "Expected status 'success'")
}

func TestIndexEndpoint(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	server.handleIndex(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected status")

	assert.Contains(t, w.Body.String(), "VPN Status Dashboard")
	assert.Contains(t, w.Body.String(), "192.0.2.1")
	assert.Contains(t, w.Body.String(), "CONNECTED")

	contentType := w.Header().Get("Content-Type")
	assert.Equal(t, "text/html", contentType, "Content-Type")
}

func TestIndexEndpointNotFound(t *testing.T) {
	server, _, _ := createTestServer()

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()

	server.handleIndex(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected status")
}

func TestAuthMiddleware(t *testing.T) {
	cfg := &config.Config{
		API: config.APIConfig{
			Listen: ":8080",
			Auth: config.AuthConfig{
				Enabled: true,
				Token:   "test-token-123",
			},
		},
	}

	server := &Server{config: cfg}

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "valid token",
			authHeader:     "Bearer test-token-123",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid token",
			authHeader:     "Bearer wrong-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "missing bearer prefix",
			authHeader:     "test-token-123",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "no auth header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			authHandler := server.withAuth(nextHandler)

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			authHandler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "Expected status")
		})
	}
}

func TestAuthMiddlewareDisabled(t *testing.T) {
	cfg := &config.Config{
		API: config.APIConfig{
			Auth: config.AuthConfig{
				Enabled: false,
			},
		},
	}

	server := &Server{config: cfg}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authHandler := server.withAuth(nextHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	// No auth header
	w := httptest.NewRecorder()

	authHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected status when auth disabled")
}

func TestLoggingMiddleware(t *testing.T) {
	server := &Server{logger: slog.Default()}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	loggingHandler := server.withLogging(nextHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	start := time.Now()
	loggingHandler.ServeHTTP(w, req)
	duration := time.Since(start)

	assert.Equal(t, http.StatusOK, w.Code, "Expected status")

	// Test that it doesn't take too long (should be very fast)
	assert.True(t, duration <= 100*time.Millisecond, "Logging middleware took too long: %v", duration)
}

func TestHandleIPInfo(t *testing.T) {
	server, _, _ := createTestServer()

	tests := []struct {
		name           string
		method         string
		ipInfoError    error
		expectedStatus int
	}{
		{
			name:           "successful IP info request",
			method:         "GET",
			ipInfoError:    nil,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "method not allowed",
			method:         "POST",
			ipInfoError:    nil,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "IP info error",
			method:         "GET",
			ipInfoError:    fmt.Errorf("IP detection failed"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock IP detector error state
			mockIPDet := server.ipDetector.(*mockIPDetector)
			mockIPDet.ipInfoError = tt.ipInfoError

			req := httptest.NewRequest(tt.method, "/api/v1/ipinfo", nil)
			w := httptest.NewRecorder()

			server.handleIPInfo(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "Expected status")

			if tt.expectedStatus == http.StatusOK {
				var response ipdetector.IPInfo
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				assert.Equal(t, "192.0.2.1", response.IP, "Expected IP")
				assert.Equal(t, "Australia", response.Country, "Expected country")
			}
		})
	}
}

func TestHandleIP2LocationCompat(t *testing.T) {
	server, _, _ := createTestServer()

	tests := []struct {
		name             string
		method           string
		currentIPError   error
		rawDataError     error
		expectedStatus   int
		expectedContains string
	}{
		{
			name:             "successful request",
			method:           "GET",
			currentIPError:   nil,
			rawDataError:     nil,
			expectedStatus:   http.StatusOK,
			expectedContains: "192.0.2.1",
		},
		{
			name:           "method not allowed",
			method:         "POST",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "current IP error",
			method:         "GET",
			currentIPError: fmt.Errorf("failed to get IP"),
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:             "geolocation error - fallback to basic response",
			method:           "GET",
			currentIPError:   nil,
			rawDataError:     fmt.Errorf("geolocation failed"),
			expectedStatus:   http.StatusOK,
			expectedContains: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock IP detector error states
			mockIPDet := server.ipDetector.(*mockIPDetector)
			mockIPDet.currentIPError = tt.currentIPError
			mockIPDet.rawDataError = tt.rawDataError

			req := httptest.NewRequest(tt.method, "/ip2location.json", nil)
			w := httptest.NewRecorder()

			server.handleIP2LocationCompat(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "Expected status")

			if tt.expectedContains != "" {
				assert.Contains(t, w.Body.String(), tt.expectedContains, "Expected response to contain")
			}
		})
	}
}

func TestMethodNotAllowedForAllEndpoints(t *testing.T) {
	server, _, _ := createTestServer()

	endpointTests := []struct {
		path            string
		allowedMethod   string
		forbiddenMethod string
		handler         func(http.ResponseWriter, *http.Request)
	}{
		{"/api/v1/status", "GET", "POST", server.handleStatus},
		{"/status", "GET", "POST", server.handleLegacyStatus},
		{"/api/v1/reconnect", "POST", "GET", server.handleReconnect},
		{"/api/v1/healthcheck", "POST", "GET", server.handleForceHealthCheck},
		{"/api/v1/ipinfo", "GET", "POST", server.handleIPInfo},
		{"/ip2location.json", "GET", "POST", server.handleIP2LocationCompat},
		{"/api/v1/cache/stats", "GET", "POST", server.handleCacheStats},
		{"/api/v1/cache/clear", "POST", "GET", server.handleCacheClear},
	}

	for _, tt := range endpointTests {
		t.Run(fmt.Sprintf("%s_%s_not_allowed", tt.path, tt.forbiddenMethod), func(t *testing.T) {
			req := httptest.NewRequest(tt.forbiddenMethod, tt.path, nil)
			w := httptest.NewRecorder()

			tt.handler(w, req)

			assert.Equal(t, http.StatusMethodNotAllowed, w.Code, "Expected method not allowed")
		})
	}
}

func TestReconnectWithFormData(t *testing.T) {
	server, _, _ := createTestServer()

	tests := []struct {
		name           string
		formData       string
		expectedServer string
	}{
		{
			name:           "form data with server parameter",
			formData:       "server=test-server-form",
			expectedServer: "test-server-form",
		},
		{
			name:           "empty form data",
			formData:       "",
			expectedServer: "", // Should remain unchanged
		},
		{
			name:           "form data with other parameters",
			formData:       "other=value&server=form-server",
			expectedServer: "form-server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset server config
			originalServer := server.config.VPN.Server
			server.config.VPN.Server = ""

			req := httptest.NewRequest("POST", "/api/v1/reconnect", strings.NewReader(tt.formData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			server.handleReconnect(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Expected status")

			if tt.expectedServer != "" {
				assert.Equal(t, tt.expectedServer, server.config.VPN.Server, "Expected server to be set")
			} else {
				assert.Equal(t, "", server.config.VPN.Server, "Expected server to remain empty")
			}

			// Restore original server
			server.config.VPN.Server = originalServer
		})
	}
}

func TestServerStart(t *testing.T) {
	cfg := &config.Config{
		API: config.APIConfig{
			Listen: ":0", // Use any available port
			Auth: config.AuthConfig{
				Enabled: false,
			},
		},
		VPN: config.VPNConfig{
			Server: "",
		},
	}

	mockIPDet := &mockIPDetector{
		currentIP: "192.0.2.1",
		ipInfo: &ipdetector.IPInfo{
			IP:        "192.0.2.1",
			Country:   "Australia",
			Region:    "Victoria",
			City:      "Melbourne",
			Timestamp: time.Now(),
		},
		rawData:    []byte(`{"ip":"192.0.2.1"}`),
		cacheStats: map[string]any{"total_entries": 0},
	}

	mockVPN := &mockVPNManager{
		status: vpn.Status{
			State:      "connected",
			CurrentIP:  "192.0.2.1",
			OriginalIP: "203.0.113.1",
			Uptime:     "01:00:00",
			Server:     "test-server",
		},
		ipDetector: mockIPDet,
	}

	mockHealth := NewMockHealthMonitor().WithStatus(health.Status{
		Status:           "healthy",
		LastCheck:        time.Now(),
		ConsecutiveFails: 0,
		SuccessRate:      100.0,
	})

	server := NewServer(cfg, mockVPN, mockHealth, slog.Default())

	// Test server start with context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Give server a moment to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context to shutdown server
	cancel()

	// Wait for server to shutdown
	select {
	case err := <-errChan:
		// Server should shutdown cleanly
		assert.NoError(t, err, "Server should shutdown without error")
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not shutdown within timeout")
	}
}

func TestFullServerIntegration(t *testing.T) {
	server, _, _ := createTestServer()

	// Create a test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Route to appropriate handler
		switch r.URL.Path {
		case "/health":
			server.handleHealth(w, r)
		case "/api/v1/status":
			server.handleStatus(w, r)
		case "/api/v1/cache/stats":
			server.handleCacheStats(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer testServer.Close()

	client := &http.Client{Timeout: 10 * time.Second}

	// Test health endpoint
	resp, err := client.Get(testServer.URL + "/health")
	if err != nil {
		t.Fatalf("Failed to call health endpoint: %v", err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected health endpoint to return 200")

	// Test status endpoint
	resp, err = client.Get(testServer.URL + "/api/v1/status")
	if err != nil {
		t.Fatalf("Failed to call status endpoint: %v", err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status endpoint to return 200")

	var status StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode status response: %v", err)
	}

	assert.Equal(t, "connected", status.Status, "Expected status 'connected'")
}

func TestEdgeCasesAndErrorHandling(t *testing.T) {
	server, mockVPN, _ := createTestServer()

	t.Run("status endpoint with different VPN states", func(t *testing.T) {
		states := []string{"connecting", "disconnected", "reconnecting", "failed"}
		for _, state := range states {
			mockVPN.status.State = state
			req := httptest.NewRequest("GET", "/api/v1/status", nil)
			w := httptest.NewRecorder()

			server.handleStatus(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Expected OK status for state: %s", state)

			var response StatusResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&response))
			assert.Equal(t, state, response.Status, "Expected state: %s", state)
		}
	})

	t.Run("health endpoint with different health states", func(t *testing.T) {
		healthStates := []string{"unhealthy", "checking", "degraded"}
		for _, healthState := range healthStates {
			// Create new health monitor with specific status
			mockHealth := NewMockHealthMonitor().WithStatus(health.Status{
				Status: healthState,
			})
			server.monitor = mockHealth

			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()

			server.handleHealth(w, req)

			assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Expected service unavailable for health: %s", healthState)
			assert.Contains(t, w.Body.String(), healthState, "Expected response to contain health state")
		}
	})

	t.Run("index endpoint with different VPN states and CSS classes", func(t *testing.T) {
		testCases := []struct {
			vpnState    string
			expectedCSS string
		}{
			{"connected", "ok"},
			{"disconnected", "error"},
			{"connecting", "connecting"},
			{"failed", "error"},
		}

		for _, tc := range testCases {
			mockVPN.status.State = tc.vpnState
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			server.handleIndex(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Expected OK status")
			assert.Contains(t, w.Body.String(), tc.expectedCSS, "Expected CSS class for state: %s", tc.vpnState)
			assert.Contains(t, w.Body.String(), strings.ToUpper(tc.vpnState), "Expected uppercase state")
		}
	})

	t.Run("force health check endpoint method validation", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/healthcheck", nil)
		w := httptest.NewRecorder()

		server.handleForceHealthCheck(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("cache stats endpoint method validation", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/cache/stats", nil)
		w := httptest.NewRecorder()

		server.handleCacheStats(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("cache clear endpoint method validation", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/cache/clear", nil)
		w := httptest.NewRecorder()

		server.handleCacheClear(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestMiddlewareEdgeCases(t *testing.T) {
	t.Run("auth middleware with different bearer formats", func(t *testing.T) {
		cfg := &config.Config{
			API: config.APIConfig{
				Auth: config.AuthConfig{
					Enabled: true,
					Token:   "test-token-123",
				},
			},
		}

		server := &Server{config: cfg}

		testCases := []struct {
			name         string
			header       string
			expectedCode int
		}{
			{"bearer with extra spaces", "Bearer  test-token-123", http.StatusUnauthorized}, // Extra space should fail
			{"lowercase bearer", "bearer test-token-123", http.StatusUnauthorized},
			{"token only", "test-token-123", http.StatusUnauthorized},
			{"empty bearer", "Bearer ", http.StatusUnauthorized},
			{"bearer with wrong token", "Bearer wrong", http.StatusUnauthorized},
			{"valid token", "Bearer test-token-123", http.StatusOK},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})

				authHandler := server.withAuth(nextHandler)

				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", tc.header)
				w := httptest.NewRecorder()

				authHandler.ServeHTTP(w, req)

				assert.Equal(t, tc.expectedCode, w.Code, "Test case: %s", tc.name)
			})
		}
	})

	t.Run("logging middleware captures request details", func(t *testing.T) {
		server := &Server{logger: slog.Default()}

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("test response"))
		})

		loggingHandler := server.withLogging(nextHandler)

		req := httptest.NewRequest("POST", "/test/path?param=value", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		loggingHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		assert.Equal(t, "test response", w.Body.String())
	})
}

func TestHTTPHeadersAndContentTypes(t *testing.T) {
	t.Run("all JSON endpoints return correct content type", func(t *testing.T) {
		server, _, _ := createTestServer()

		jsonEndpoints := []struct {
			path    string
			method  string
			handler func(http.ResponseWriter, *http.Request)
		}{
			{"/api/v1/status", "GET", server.handleStatus},
			{"/status", "GET", server.handleLegacyStatus},
			{"/api/v1/reconnect", "POST", server.handleReconnect},
			{"/api/v1/healthcheck", "POST", server.handleForceHealthCheck},
			{"/api/v1/ipinfo", "GET", server.handleIPInfo},
			{"/api/v1/cache/stats", "GET", server.handleCacheStats},
			{"/api/v1/cache/clear", "POST", server.handleCacheClear},
		}

		for _, endpoint := range jsonEndpoints {
			req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
			w := httptest.NewRecorder()

			endpoint.handler(w, req)

			// Skip if method not allowed (we're testing content type on valid responses)
			if w.Code == http.StatusMethodNotAllowed {
				continue
			}

			assert.Equal(t, "application/json", w.Header().Get("Content-Type"),
				"Expected JSON content type for %s %s", endpoint.method, endpoint.path)
		}
	})

	t.Run("HTML endpoint returns correct content type", func(t *testing.T) {
		server, _, _ := createTestServer()

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		server.handleIndex(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "text/html", w.Header().Get("Content-Type"))
	})

	t.Run("IP2Location endpoint returns correct content type", func(t *testing.T) {
		server, _, _ := createTestServer()

		req := httptest.NewRequest("GET", "/ip2location.json", nil)
		w := httptest.NewRecorder()

		server.handleIP2LocationCompat(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})
}

func TestServerStartupErrorScenarios(t *testing.T) {
	t.Run("server start with invalid listen address", func(t *testing.T) {
		cfg := &config.Config{
			API: config.APIConfig{
				Listen: "invalid-address", // This should cause an error
				Auth: config.AuthConfig{
					Enabled: false,
				},
			},
			VPN: config.VPNConfig{
				Server: "",
			},
		}

		mockIPDet := &mockIPDetector{
			currentIP:  "192.0.2.1",
			ipInfo:     &ipdetector.IPInfo{IP: "192.0.2.1", Timestamp: time.Now()},
			cacheStats: map[string]any{"total_entries": 0},
		}

		mockVPN := &mockVPNManager{
			status:     vpn.Status{State: "connected", CurrentIP: "192.0.2.1"},
			ipDetector: mockIPDet,
		}

		mockHealth := NewMockHealthMonitor().WithStatus(health.Status{Status: "healthy"})

		server := NewServer(cfg, mockVPN, mockHealth, slog.Default())

		// This should return an error due to invalid listen address
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := server.Start(ctx)
		assert.Error(t, err, "Expected error with invalid listen address")
	})
}

func TestReconnectWithVPNError(t *testing.T) {
	server, mockVPN, _ := createTestServer()

	// Set up the mock to return an error on restart
	mockVPN.restartError = fmt.Errorf("VPN restart failed")

	req := httptest.NewRequest("POST", "/api/v1/reconnect", nil)
	w := httptest.NewRecorder()

	server.handleReconnect(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected OK status")

	// Give the goroutine a moment to execute
	time.Sleep(10 * time.Millisecond)

	var response map[string]string
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, "reconnecting", response["status"], "Expected reconnecting status")
}
