package speedtest

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"openxvpn/pkg/config"
)

// createTestConfig creates a test configuration for TesterImpl
func createTestConfig() *config.SpeedTestConfig {
	return &config.SpeedTestConfig{
		Enabled:            true,
		Interval:           15 * time.Minute,
		TestSizes:          []string{"1MB", "5MB", "10MB"},
		MaxDuration:        30 * time.Second,
		RandomizeEndpoints: true,
		SelectedEndpoints:  []string{},
	}
}

// createTestTester creates a TesterImpl for testing
func createTestTester(cfg *config.SpeedTestConfig) *TesterImpl {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	if cfg == nil {
		cfg = createTestConfig()
	}
	return NewTester(cfg, logger)
}

func TestNewTester(t *testing.T) {
	cfg := createTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tester := NewTester(cfg, logger)

	require.NotNil(t, tester, "NewTester returned nil")
	assert.Equal(t, cfg, tester.config, "Config not properly assigned")
	assert.NotNil(t, tester.httpClient, "HTTP client not created")
	assert.Equal(t, cfg.MaxDuration, tester.httpClient.Timeout, "Expected correct timeout")
	assert.NotNil(t, tester.logger, "Logger not assigned")
	assert.NotNil(t, tester.rand, "Random generator not created")
}

func TestRunTest_Disabled(t *testing.T) {
	cfg := createTestConfig()
	cfg.Enabled = false
	tester := createTestTester(cfg)

	ctx := context.Background()
	result, err := tester.RunTest(ctx)

	require.Error(t, err, "Expected error when speed test is disabled")
	assert.Nil(t, result, "Expected nil result when speed test is disabled")
	assert.Contains(t, err.Error(), "speed test is disabled", "Expected 'speed test is disabled' error")
}

func TestBuiltInEndpoints(t *testing.T) {
	cfg := createTestConfig()
	tester := createTestTester(cfg)

	// Test that built-in endpoints are available
	endpoints := tester.GetAvailableEndpoints()
	assert.NotEmpty(t, endpoints, "Expected built-in endpoints to be available")
	assert.Contains(t, endpoints, "ThinkBroadband", "Expected ThinkBroadband endpoint")
	assert.Contains(t, endpoints, "Speedtest.net", "Expected Speedtest.net endpoint")
	assert.Contains(t, endpoints, "Cachefly CDN", "Expected Cachefly CDN endpoint")

	// Test endpoint info
	endpointInfo := tester.GetEndpointInfo()
	assert.NotEmpty(t, endpointInfo, "Expected endpoint info to be available")
	assert.Contains(t, endpointInfo, "ThinkBroadband", "Expected ThinkBroadband in endpoint info")

	// Test that ThinkBroadband has expected URLs
	thinkBroadband := endpointInfo["ThinkBroadband"]
	assert.Contains(t, thinkBroadband, "1MB", "Expected 1MB URL for ThinkBroadband")
	assert.Contains(t, thinkBroadband, "5MB", "Expected 5MB URL for ThinkBroadband")
	assert.Contains(t, thinkBroadband, "10MB", "Expected 10MB URL for ThinkBroadband")
}

func TestSelectedEndpoints(t *testing.T) {
	cfg := createTestConfig()
	cfg.SelectedEndpoints = []string{"ThinkBroadband", "Cachefly CDN"}
	tester := createTestTester(cfg)

	// Test that only selected endpoints are available
	endpoints := tester.GetAvailableEndpoints()
	assert.Len(t, endpoints, 2, "Expected exactly 2 selected endpoints")
	assert.Contains(t, endpoints, "ThinkBroadband", "Expected ThinkBroadband endpoint")
	assert.Contains(t, endpoints, "Cachefly CDN", "Expected Cachefly CDN endpoint")
	assert.NotContains(t, endpoints, "Speedtest.net", "Expected Speedtest.net to be filtered out")

	// Test endpoint info contains only selected endpoints
	endpointInfo := tester.GetEndpointInfo()
	assert.Len(t, endpointInfo, 2, "Expected exactly 2 endpoints in info")
	assert.Contains(t, endpointInfo, "ThinkBroadband", "Expected ThinkBroadband in endpoint info")
	assert.Contains(t, endpointInfo, "Cachefly CDN", "Expected Cachefly CDN in endpoint info")
}

func TestSelectedEndpoints_InvalidSelection(t *testing.T) {
	cfg := createTestConfig()
	cfg.SelectedEndpoints = []string{"NonExistentEndpoint"}
	tester := createTestTester(cfg)

	// Should fall back to all built-in endpoints when no valid selections found
	endpoints := tester.GetAvailableEndpoints()
	assert.NotEmpty(t, endpoints, "Expected fallback to all built-in endpoints")
	assert.Contains(t, endpoints, "ThinkBroadband", "Expected ThinkBroadband endpoint in fallback")
}

func TestSelectRandomTestSize(t *testing.T) {
	tests := []struct {
		name           string
		testSizes      []string
		randomize      bool
		expectedFirst  string
		allowedResults []string
	}{
		{
			name:           "Empty sizes",
			testSizes:      []string{},
			randomize:      true,
			expectedFirst:  "1MB",
			allowedResults: []string{"1MB"},
		},
		{
			name:           "Single size",
			testSizes:      []string{"5MB"},
			randomize:      true,
			expectedFirst:  "5MB",
			allowedResults: []string{"5MB"},
		},
		{
			name:           "Multiple sizes, no randomization",
			testSizes:      []string{"1MB", "5MB", "10MB"},
			randomize:      false,
			expectedFirst:  "1MB",
			allowedResults: []string{"1MB"},
		},
		{
			name:           "Multiple sizes, with randomization",
			testSizes:      []string{"1MB", "5MB", "10MB"},
			randomize:      true,
			allowedResults: []string{"1MB", "5MB", "10MB"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig()
			cfg.TestSizes = tt.testSizes
			cfg.RandomizeEndpoints = tt.randomize
			tester := createTestTester(cfg)

			result := tester.selectRandomTestSize()

			if !tt.randomize || len(tt.allowedResults) == 1 {
				assert.Equal(t, tt.expectedFirst, result, "Expected %s", tt.expectedFirst)
			} else {
				// For randomized selection, just check it's one of the valid sizes
				found := false
				for _, size := range tt.testSizes {
					if result == size {
						found = true
						break
					}
				}
				assert.True(t, found, "Result %s should be found in test sizes %v", result, tt.testSizes)
			}
		})
	}
}

func TestGetAvailableEndpoints(t *testing.T) {
	cfg := createTestConfig()
	tester := createTestTester(cfg)

	endpoints := tester.GetAvailableEndpoints()

	// Should have all built-in endpoints
	assert.NotEmpty(t, endpoints, "Expected endpoints to be available")
	assert.Contains(t, endpoints, "ThinkBroadband", "Expected ThinkBroadband endpoint")
	assert.Contains(t, endpoints, "Speedtest.net", "Expected Speedtest.net endpoint")
}

func TestGetAvailableSizes(t *testing.T) {
	cfg := createTestConfig()
	tester := createTestTester(cfg)

	sizes := tester.GetAvailableSizes()

	expected := []string{"1MB", "5MB", "10MB"}
	assert.Equal(t, len(expected), len(sizes), "Expected %d sizes, got %d", len(expected), len(sizes))

	for i, exp := range expected {
		assert.Equal(t, exp, sizes[i], "Expected size %s at index %d, got %s", exp, i, sizes[i])
	}
}

func TestGetEndpointInfo(t *testing.T) {
	cfg := createTestConfig()
	tester := createTestTester(cfg)

	info := tester.GetEndpointInfo()

	assert.NotEmpty(t, info, "Expected endpoint info to be available")
	assert.Contains(t, info, "ThinkBroadband", "Expected ThinkBroadband in endpoint info")
	assert.Contains(t, info, "Speedtest.net", "Expected Speedtest.net in endpoint info")

	// Check that endpoints have URLs
	for endpointName, urls := range info {
		assert.NotEmpty(t, urls, "Expected URLs for endpoint %s", endpointName)
	}
}

func TestParseTestSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		hasError bool
	}{
		{"1MB", 1024 * 1024, false},
		{"5MB", 5 * 1024 * 1024, false},
		{"10MB", 10 * 1024 * 1024, false},
		{"1KB", 1024, false},
		{"1GB", 1024 * 1024 * 1024, false},
		{"1024", 1024, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseTestSize(tt.input)

			if tt.hasError {
				assert.Error(t, err, "Expected error for input %s", tt.input)
			} else {
				assert.NoError(t, err, "Unexpected error for input %s", tt.input)
				assert.Equal(t, tt.expected, result, "Expected %d for input %s, got %d", tt.expected, tt.input, result)
			}
		})
	}
}

func TestCalculateSpeedMbps(t *testing.T) {
	cfg := createTestConfig()
	tester := createTestTester(cfg)

	tests := []struct {
		name      string
		bytesRead int64
		duration  time.Duration
		expected  float64
	}{
		{
			name:      "1MB in 1 second",
			bytesRead: 1024 * 1024, // 1MB
			duration:  time.Second,
			expected:  8.388608, // 1MB * 8 bits / 1,000,000 = 8.388608 Mbps
		},
		{
			name:      "5MB in 2 seconds",
			bytesRead: 5 * 1024 * 1024, // 5MB
			duration:  2 * time.Second,
			expected:  20.971520, // 5MB * 8 bits / 2 seconds / 1,000,000
		},
		{
			name:      "Zero duration",
			bytesRead: 1024 * 1024,
			duration:  0,
			expected:  0,
		},
		{
			name:      "Zero bytes",
			bytesRead: 0,
			duration:  time.Second,
			expected:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tester.calculateSpeedMbps(tt.bytesRead, tt.duration)
			assert.InDelta(t, tt.expected, result, 0.000001, "Speed calculation mismatch")
		})
	}
}

func TestGetEffectiveEndpoints(t *testing.T) {
	tests := []struct {
		name              string
		selectedEndpoints []string
		expectedCount     int
		shouldContain     []string
	}{
		{
			name:              "No selection - all endpoints",
			selectedEndpoints: []string{},
			expectedCount:     6, // All built-in endpoints
			shouldContain:     []string{"ThinkBroadband", "Speedtest.net"},
		},
		{
			name:              "Valid selection",
			selectedEndpoints: []string{"ThinkBroadband", "Speedtest.net"},
			expectedCount:     2,
			shouldContain:     []string{"ThinkBroadband", "Speedtest.net"},
		},
		{
			name:              "Invalid selection - fallback to all",
			selectedEndpoints: []string{"NonExistent"},
			expectedCount:     6, // Falls back to all built-in endpoints
			shouldContain:     []string{"ThinkBroadband", "Speedtest.net"},
		},
		{
			name:              "Mixed valid/invalid selection",
			selectedEndpoints: []string{"ThinkBroadband", "NonExistent"},
			expectedCount:     1,
			shouldContain:     []string{"ThinkBroadband"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig()
			cfg.SelectedEndpoints = tt.selectedEndpoints
			tester := createTestTester(cfg)

			endpoints := tester.getEffectiveEndpoints()
			assert.Equal(t, tt.expectedCount, len(endpoints), "Endpoint count mismatch")

			endpointNames := make([]string, len(endpoints))
			for i, ep := range endpoints {
				endpointNames[i] = ep.Name
			}

			for _, expected := range tt.shouldContain {
				assert.Contains(t, endpointNames, expected, "Should contain endpoint %s", expected)
			}
		})
	}
}

func TestSelectRandomEndpoint(t *testing.T) {
	cfg := createTestConfig()
	cfg.RandomizeEndpoints = false
	tester := createTestTester(cfg)

	tests := []struct {
		name     string
		testSize string
		hasURL   bool
	}{
		{
			name:     "Valid size",
			testSize: "1MB",
			hasURL:   true,
		},
		{
			name:     "Another valid size",
			testSize: "5MB",
			hasURL:   true,
		},
		{
			name:     "Invalid size",
			testSize: "999MB",
			hasURL:   false, // Should fallback
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpointName, url := tester.selectRandomEndpoint(tt.testSize)

			if tt.hasURL {
				assert.NotEmpty(t, endpointName, "Endpoint name should not be empty")
				assert.NotEmpty(t, url, "URL should not be empty")
				assert.NotEqual(t, "unknown", endpointName, "Should not return unknown endpoint")
			}
			// For invalid sizes, it might still find a fallback, so we just ensure it doesn't crash
		})
	}
}

func TestSelectRandomEndpoint_Randomization(t *testing.T) {
	cfg := createTestConfig()
	cfg.RandomizeEndpoints = true
	tester := createTestTester(cfg)

	// Test multiple times to see if we get different endpoints (though it's not guaranteed)
	results := make(map[string]int)
	for i := 0; i < 20; i++ {
		endpointName, url := tester.selectRandomEndpoint("1MB")
		assert.NotEmpty(t, endpointName, "Endpoint name should not be empty")
		assert.NotEmpty(t, url, "URL should not be empty")
		results[endpointName]++
	}

	// We should have at least one result
	assert.NotEmpty(t, results, "Should have at least one endpoint result")
}

func TestFindFastestSpeed(t *testing.T) {
	cfg := createTestConfig()
	tester := createTestTester(cfg)

	results := []*Result{
		{Success: true, SpeedMbps: 10.5},
		{Success: true, SpeedMbps: 25.3},
		{Success: false, SpeedMbps: 30.0}, // Should be ignored
		{Success: true, SpeedMbps: 15.7},
	}

	fastest := tester.findFastestSpeed(results)
	assert.Equal(t, 25.3, fastest, "Should find the fastest successful speed")
}

func TestFindSlowestSpeed(t *testing.T) {
	cfg := createTestConfig()
	tester := createTestTester(cfg)

	results := []*Result{
		{Success: true, SpeedMbps: 10.5},
		{Success: true, SpeedMbps: 25.3},
		{Success: false, SpeedMbps: 5.0}, // Should be ignored
		{Success: true, SpeedMbps: 15.7},
	}

	slowest := tester.findSlowestSpeed(results)
	assert.Equal(t, 10.5, slowest, "Should find the slowest successful speed")
}

func TestFindSlowestSpeed_NoSuccessful(t *testing.T) {
	cfg := createTestConfig()
	tester := createTestTester(cfg)

	results := []*Result{
		{Success: false, SpeedMbps: 10.5},
		{Success: false, SpeedMbps: 25.3},
	}

	slowest := tester.findSlowestSpeed(results)
	assert.Equal(t, float64(0), slowest, "Should return 0 when no successful results")
}

func TestRunMultipleTests_InvalidCount(t *testing.T) {
	cfg := createTestConfig()
	cfg.Enabled = false // Disable to avoid actual network calls
	tester := createTestTester(cfg)

	ctx := context.Background()

	// Test with invalid counts - when disabled, RunTest returns nil, so no results are added
	results, aggregate, err := tester.RunMultipleTests(ctx, 0)
	assert.NoError(t, err, "Should not error on invalid count")
	assert.Equal(t, 0, len(results), "Should have 0 results when disabled")
	assert.Equal(t, 1, aggregate.TotalTests, "Should record 1 total test")
	assert.Equal(t, 0, aggregate.SuccessfulTests, "Should have 0 successful tests when disabled")
	assert.Equal(t, 1, aggregate.FailedTests, "Should have 1 failed test when disabled")

	results, aggregate, err = tester.RunMultipleTests(ctx, -5)
	assert.NoError(t, err, "Should not error on negative count")
	assert.Equal(t, 0, len(results), "Should have 0 results when disabled")
	assert.Equal(t, 1, aggregate.TotalTests, "Should record 1 total test")
	assert.Equal(t, 0, aggregate.SuccessfulTests, "Should have 0 successful tests when disabled")
	assert.Equal(t, 1, aggregate.FailedTests, "Should have 1 failed test when disabled")
}

func TestValidateEndpoints(t *testing.T) {
	cfg := createTestConfig()
	tester := createTestTester(cfg)

	// Use very short timeout to avoid long-running network calls in tests
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	results := tester.ValidateEndpoints(ctx)
	assert.NotEmpty(t, results, "Should return validation results")

	// ValidateEndpoints returns results for each endpoint-size combination, not just endpoints
	// Each endpoint has multiple sizes (1MB, 5MB, 10MB), so we expect more results
	assert.Greater(t, len(results), 6, "Should have more results than just endpoint count due to size combinations")

	// Verify that all results are boolean values
	for key, result := range results {
		assert.IsType(t, false, result, "Validation result for %s should be boolean", key)
		// Keys should be in format "EndpointName (size)"
		assert.Contains(t, key, "(", "Key should contain size in parentheses: %s", key)
		assert.Contains(t, key, ")", "Key should contain closing parenthesis: %s", key)
	}
}

func TestDownloadTest(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse string
		statusCode     int
		expectedBytes  int64
		expectError    bool
		errorContains  string
	}{
		{
			name:           "Successful download",
			serverResponse: "1234567890", // 10 bytes
			statusCode:     http.StatusOK,
			expectedBytes:  10,
			expectError:    false,
		},
		{
			name:           "Large download",
			serverResponse: strings.Repeat("x", 1024), // 1KB
			statusCode:     http.StatusOK,
			expectedBytes:  1024,
			expectError:    false,
		},
		{
			name:          "HTTP 404 error",
			statusCode:    http.StatusNotFound,
			expectError:   true,
			errorContains: "HTTP 404",
		},
		{
			name:          "HTTP 500 error",
			statusCode:    http.StatusInternalServerError,
			expectError:   true,
			errorContains: "HTTP 500",
		},
		{
			name:           "Empty response",
			serverResponse: "",
			statusCode:     http.StatusOK,
			expectedBytes:  0,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check headers
				assert.Equal(t, "no-cache", r.Header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", r.Header.Get("Pragma"))

				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					fmt.Fprint(w, tt.serverResponse)
				}
			}))
			defer server.Close()

			cfg := createTestConfig()
			tester := createTestTester(cfg)
			// Replace HTTP client with test server client
			tester.httpClient = server.Client()

			ctx := context.Background()
			bytesRead, err := tester.downloadTest(ctx, server.URL)

			if tt.expectError {
				assert.Error(t, err, "Expected error for test case: %s", tt.name)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains, "Error should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Unexpected error for test case: %s", tt.name)
				assert.Equal(t, tt.expectedBytes, bytesRead, "Bytes read mismatch")
			}
		})
	}
}

func TestDownloadTest_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, "response")
	}))
	defer server.Close()

	cfg := createTestConfig()
	tester := createTestTester(cfg)
	tester.httpClient = server.Client()

	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := tester.downloadTest(ctx, server.URL)
	assert.Error(t, err, "Expected error due to context cancellation")
}

func TestRunTest_Success(t *testing.T) {
	// Create test server that returns test data
	testData := strings.Repeat("x", 1024*1024) // 1MB of data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, testData)
	}))
	defer server.Close()

	cfg := createTestConfig()
	cfg.Enabled = true
	cfg.TestSizes = []string{"1MB"}
	cfg.RandomizeEndpoints = false

	tester := createTestTester(cfg)
	tester.httpClient = server.Client()

	// Mock the selectRandomEndpoint to return our test server
	originalEndpoints := builtInEndpoints
	builtInEndpoints = []SpeedTestEndpoint{
		{
			Name: "TestEndpoint",
			URLs: map[string]string{
				"1MB": server.URL,
			},
		},
	}
	defer func() { builtInEndpoints = originalEndpoints }()

	ctx := context.Background()
	result, err := tester.RunTest(ctx)

	assert.NoError(t, err, "Expected successful test")
	assert.NotNil(t, result, "Result should not be nil")
	assert.True(t, result.Success, "Test should be successful")
	assert.Equal(t, "TestEndpoint", result.Endpoint)
	assert.Equal(t, "1MB", result.TestSize)
	assert.Equal(t, server.URL, result.URL)
	assert.Equal(t, int64(1024*1024), result.BytesRead)
	assert.Greater(t, result.SpeedMbps, float64(0), "Speed should be greater than 0")
	assert.Greater(t, result.Duration, time.Duration(0), "Duration should be greater than 0")
	assert.Empty(t, result.Error, "Error should be empty on success")
}

func TestRunTest_Failure(t *testing.T) {
	// Create test server that returns 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := createTestConfig()
	cfg.Enabled = true
	cfg.TestSizes = []string{"1MB"}
	cfg.RandomizeEndpoints = false

	tester := createTestTester(cfg)
	tester.httpClient = server.Client()

	// Mock the selectRandomEndpoint to return our test server
	originalEndpoints := builtInEndpoints
	builtInEndpoints = []SpeedTestEndpoint{
		{
			Name: "TestEndpoint",
			URLs: map[string]string{
				"1MB": server.URL,
			},
		},
	}
	defer func() { builtInEndpoints = originalEndpoints }()

	ctx := context.Background()
	result, err := tester.RunTest(ctx)

	assert.Error(t, err, "Expected error for failed test")
	assert.NotNil(t, result, "Result should not be nil even on failure")
	assert.False(t, result.Success, "Test should not be successful")
	assert.Equal(t, "TestEndpoint", result.Endpoint)
	assert.Equal(t, "1MB", result.TestSize)
	assert.Equal(t, server.URL, result.URL)
	assert.NotEmpty(t, result.Error, "Error should be populated on failure")
	assert.Greater(t, result.Duration, time.Duration(0), "Duration should be recorded even on failure")
}

func TestRunMultipleTests_Success(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, strings.Repeat("x", 1024)) // 1KB
	}))
	defer server.Close()

	cfg := createTestConfig()
	cfg.Enabled = true
	cfg.TestSizes = []string{"1MB"}
	cfg.RandomizeEndpoints = false

	tester := createTestTester(cfg)
	tester.httpClient = server.Client()

	// Mock endpoints
	originalEndpoints := builtInEndpoints
	builtInEndpoints = []SpeedTestEndpoint{
		{
			Name: "TestEndpoint",
			URLs: map[string]string{
				"1MB": server.URL,
			},
		},
	}
	defer func() { builtInEndpoints = originalEndpoints }()

	ctx := context.Background()
	results, aggregate, err := tester.RunMultipleTests(ctx, 3)

	assert.NoError(t, err, "Expected successful multiple tests")
	assert.Equal(t, 3, len(results), "Should have 3 results")
	assert.NotNil(t, aggregate, "Aggregate should not be nil")
	assert.Equal(t, 3, aggregate.TotalTests, "Should record 3 total tests")
	assert.Equal(t, 3, aggregate.SuccessfulTests, "Should have 3 successful tests")
	assert.Equal(t, 0, aggregate.FailedTests, "Should have 0 failed tests")
	assert.Equal(t, float64(100), aggregate.SuccessRate, "Success rate should be 100%")
	assert.Greater(t, aggregate.AverageSpeedMbps, float64(0), "Average speed should be > 0")
	assert.Greater(t, aggregate.FastestSpeedMbps, float64(0), "Fastest speed should be > 0")
	assert.Greater(t, aggregate.SlowestSpeedMbps, float64(0), "Slowest speed should be > 0")
}
