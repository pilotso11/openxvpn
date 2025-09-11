package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"openxvpn/pkg/metrics"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatsEndpoint(t *testing.T) {
	server, _, _ := createTestServer()

	// Create a test request for the stats endpoint
	req := httptest.NewRequest("GET", "/stats.json", nil)
	w := httptest.NewRecorder()

	// Call the handler directly
	server.handleStats(w, req)

	// The server created by createTestServer already initializes a metrics collector in NewServer
	assert.Equal(t, http.StatusOK, w.Code)
	// Response should be a valid JSON with empty stats
	var emptyStats metrics.StatsResponse
	var err error
	err = json.NewDecoder(w.Body).Decode(&emptyStats)
	assert.NoError(t, err)
	assert.Empty(t, emptyStats.IncomingAPICalls)

	// Reset the metrics collector to ensure we start fresh
	server.metricsCollector = metrics.NewCollector()

	// Record some metrics
	server.metricsCollector.RecordIncomingCall("/health")
	server.metricsCollector.RecordIncomingCall("/health")
	server.metricsCollector.RecordIncomingCall("/")
	server.metricsCollector.RecordOutgoingCall(metrics.IPOnlyLookup, "ifconfig.me")
	server.metricsCollector.RecordOutgoingCall(metrics.GeoLookup, "ip2location.io")
	server.metricsCollector.RecordOutgoingCall(metrics.GeoLookup, "ip2location.io")

	// Try again with the collector configured
	w = httptest.NewRecorder()
	server.handleStats(w, req)

	// Now we should get a successful response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	// Decode the response
	var response metrics.StatsResponse
	err = json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)

	// Verify the response contains the expected metrics
	assert.Contains(t, response.IncomingAPICalls, "/health")
	assert.Equal(t, 2, response.IncomingAPICalls["/health"].TotalCalls)
	assert.Contains(t, response.IncomingAPICalls, "/")
	assert.Equal(t, 1, response.IncomingAPICalls["/"].TotalCalls)

	assert.Contains(t, response.OutgoingAPICalls, metrics.IPOnlyLookup)
	assert.Contains(t, response.OutgoingAPICalls[metrics.IPOnlyLookup], "ifconfig.me")
	assert.Equal(t, 1, response.OutgoingAPICalls[metrics.IPOnlyLookup]["ifconfig.me"].TotalCalls)

	assert.Contains(t, response.OutgoingAPICalls, metrics.GeoLookup)
	assert.Contains(t, response.OutgoingAPICalls[metrics.GeoLookup], "ip2location.io")
	assert.Equal(t, 2, response.OutgoingAPICalls[metrics.GeoLookup]["ip2location.io"].TotalCalls)
}

func TestMetricsMiddleware(t *testing.T) {
	server, _, _ := createTestServer()
	server.metricsCollector = metrics.NewCollector()

	// Create a simple handler that just returns 200 OK
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap the handler with our logging middleware that records metrics
	wrappedHandler := server.withLogging(handler)

	// Send requests to different endpoints through the middleware
	endpoints := []string{"/health", "/", "/health", "/api/v1/status"}
	for _, endpoint := range endpoints {
		req := httptest.NewRequest("GET", endpoint, nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Get the stats and verify the calls were recorded
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/stats.json", nil)
	server.handleStats(w, req)

	var statsResponse metrics.StatsResponse
	err := json.NewDecoder(w.Body).Decode(&statsResponse)
	assert.NoError(t, err)

	// We should have counts for each distinct endpoint
	assert.Equal(t, 2, statsResponse.IncomingAPICalls["/health"].TotalCalls)
	assert.Equal(t, 1, statsResponse.IncomingAPICalls["/"].TotalCalls)
	assert.Equal(t, 1, statsResponse.IncomingAPICalls["/api/v1/status"].TotalCalls)
}

func TestSetMetricsCollector(t *testing.T) {
	// Create a server
	server, _, _ := createTestServer()

	// Create a new metrics collector
	collector := metrics.NewCollector()

	// Record some calls to verify it works
	collector.RecordIncomingCall("/test")
	collector.RecordOutgoingCall(metrics.IPOnlyLookup, "test-service")

	// Set the metrics collector
	server.SetMetricsCollector(collector)

	// Verify the metrics collector was set
	assert.Equal(t, collector, server.metricsCollector)

	// Test the handleStats method to verify it uses the collector
	req := httptest.NewRequest("GET", "/stats.json", nil)
	w := httptest.NewRecorder()
	server.handleStats(w, req)

	var response metrics.StatsResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)

	// Verify the previously recorded calls are present
	assert.Contains(t, response.IncomingAPICalls, "/test")
	assert.Equal(t, 1, response.IncomingAPICalls["/test"].TotalCalls)

	assert.Contains(t, response.OutgoingAPICalls, metrics.IPOnlyLookup)
	assert.Contains(t, response.OutgoingAPICalls[metrics.IPOnlyLookup], "test-service")
	assert.Equal(t, 1, response.OutgoingAPICalls[metrics.IPOnlyLookup]["test-service"].TotalCalls)
}

func TestHandleStatsMethodCheck(t *testing.T) {
	server, _, _ := createTestServer()
	server.metricsCollector = metrics.NewCollector()

	// Test with a POST request (should be method not allowed)
	req := httptest.NewRequest("POST", "/stats.json", nil)
	w := httptest.NewRecorder()
	server.handleStats(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleStatsNilCollector(t *testing.T) {
	server, _, _ := createTestServer()

	// Set metrics collector to nil
	server.metricsCollector = nil

	// Make request to stats endpoint
	req := httptest.NewRequest("GET", "/stats.json", nil)
	w := httptest.NewRecorder()
	server.handleStats(w, req)

	// Verify response
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Metrics collector not configured")
}
