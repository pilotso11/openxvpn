// Package speedtest provides bandwidth speed testing functionality for VPN connections.
// It supports multiple test endpoints, randomized testing, and comprehensive result aggregation
// to measure network performance and validate VPN connection quality.
package speedtest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openxvpn/pkg/config"
)

// SpeedTestEndpoint represents a speed test endpoint configuration with URLs for different test sizes.
// Each endpoint provides multiple file sizes to allow bandwidth testing with varying data volumes.
type SpeedTestEndpoint struct {
	// Name is the human-readable identifier for the speed test endpoint
	Name string `json:"name"`
	// URLs maps test size identifiers (e.g., "1MB", "10MB") to their corresponding download URLs
	URLs map[string]string `json:"urls"`
}

// builtInEndpoints contains the default set of speed test endpoints from various providers.
// These endpoints are used when no custom endpoints are specified in the configuration.
var builtInEndpoints = []SpeedTestEndpoint{
	{
		Name: "ThinkBroadband",
		URLs: map[string]string{
			"1MB":   "http://ipv4.download.thinkbroadband.com/1MB.zip",
			"5MB":   "http://ipv4.download.thinkbroadband.com/5MB.zip",
			"10MB":  "http://ipv4.download.thinkbroadband.com/10MB.zip",
			"100MB": "http://ipv4.download.thinkbroadband.com/100MB.zip",
		},
	},
	{
		Name: "Speedtest.net",
		URLs: map[string]string{
			"1MB":   "http://speedtest.ftp.otenet.gr/files/test1Mb.db",
			"5MB":   "http://speedtest.ftp.otenet.gr/files/test5Mb.db",
			"10MB":  "http://speedtest.ftp.otenet.gr/files/test10Mb.db",
			"100MB": "http://speedtest.ftp.otenet.gr/files/test100Mb.db",
		},
	},
	{
		Name: "Fast.com Mirror",
		URLs: map[string]string{
			"1MB":   "http://proof.ovh.net/files/1Mb.dat",
			"5MB":   "http://proof.ovh.net/files/5Mb.dat",
			"10MB":  "http://proof.ovh.net/files/10Mb.dat",
			"100MB": "http://proof.ovh.net/files/100Mb.dat",
		},
	},
	{
		Name: "Cachefly CDN",
		URLs: map[string]string{
			"1MB":   "http://cachefly.cachefly.net/1mb.test",
			"5MB":   "http://cachefly.cachefly.net/5mb.test",
			"10MB":  "http://cachefly.cachefly.net/10mb.test",
			"100MB": "http://cachefly.cachefly.net/100mb.test",
		},
	},
	{
		Name: "DigitalOcean Speedtest",
		URLs: map[string]string{
			"1MB":   "http://speedtest-nyc1.digitalocean.com/1mb.test",
			"5MB":   "http://speedtest-nyc1.digitalocean.com/5mb.test",
			"10MB":  "http://speedtest-nyc1.digitalocean.com/10mb.test",
			"100MB": "http://speedtest-nyc1.digitalocean.com/100mb.test",
		},
	},
	{
		Name: "Linode Speedtest",
		URLs: map[string]string{
			"1MB":   "http://speedtest.newark.linode.com/1MB-newark.bin",
			"5MB":   "http://speedtest.newark.linode.com/5MB-newark.bin",
			"10MB":  "http://speedtest.newark.linode.com/10MB-newark.bin",
			"100MB": "http://speedtest.newark.linode.com/100MB-newark.bin",
		},
	},
}

// Result represents the comprehensive result of a bandwidth speed test execution.
// It contains all metrics and metadata about the test including performance measurements,
// endpoint information, and success/failure status.
type Result struct {
	// Endpoint is the name of the speed test endpoint that was used
	Endpoint string `json:"endpoint"`
	// TestSize is the size identifier of the test file (e.g., "1MB", "10MB")
	TestSize string `json:"test_size"`
	// URL is the complete download URL that was tested
	URL string `json:"url"`
	// Duration is the total time taken to complete the download test
	Duration time.Duration `json:"duration"`
	// BytesRead is the actual number of bytes downloaded during the test
	BytesRead int64 `json:"bytes_read"`
	// SpeedMbps is the calculated download speed in megabits per second
	SpeedMbps float64 `json:"speed_mbps"`
	// Success indicates whether the speed test completed successfully
	Success bool `json:"success"`
	// Error contains the error message if the test failed (only present on failure)
	Error string `json:"error,omitempty"`
	// Timestamp records when the speed test was initiated
	Timestamp time.Time `json:"timestamp"`
}

// Tester defines the interface for bandwidth speed testing operations.
// It provides methods for single and multiple test execution, endpoint management,
// and validation of speed test endpoints for network performance measurement.
type Tester interface {
	// RunTest performs a single randomized speed test and returns the result
	RunTest(ctx context.Context) (*Result, error)
	// RunMultipleTests executes multiple speed tests and returns individual results plus aggregated statistics
	RunMultipleTests(ctx context.Context, count int) ([]*Result, *AggregateResult, error)
	// GetAvailableEndpoints returns the names of all available speed test endpoints
	GetAvailableEndpoints() []string
	// GetAvailableSizes returns the test file sizes supported by the endpoints
	GetAvailableSizes() []string
	// GetEndpointInfo provides detailed information about endpoints and their supported test sizes
	GetEndpointInfo() map[string]map[string]string
	// ValidateEndpoints checks the availability and reachability of configured endpoints
	ValidateEndpoints(ctx context.Context) map[string]bool
}

// TesterImpl is the concrete implementation of the Tester interface for bandwidth speed testing.
// It manages HTTP client configuration, endpoint selection, randomization, and result calculation.
type TesterImpl struct {
	// config holds the speed test configuration including endpoints, timeouts, and test parameters
	config *config.SpeedTestConfig
	// httpClient is the HTTP client used for downloading test files with configured timeouts
	httpClient *http.Client
	// logger provides structured logging for speed test operations and results
	logger *slog.Logger
	// rand provides randomization for endpoint and test size selection when enabled
	rand *rand.Rand
}

// NewTester creates a new speed test instance with the provided configuration and logger.
// It initializes an HTTP client with the configured timeout, sets up structured logging
// with a component identifier, and creates a randomizer for endpoint selection.
func NewTester(cfg *config.SpeedTestConfig, logger *slog.Logger) *TesterImpl {
	return &TesterImpl{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.MaxDuration,
		},
		logger: logger.With("component", "speedtest"),
		rand:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// getEffectiveEndpoints determines which speed test endpoints should be used for testing.
// If SelectedEndpoints are specified in the configuration, it filters the built-in endpoints
// to include only those selected. If no valid selections are found or none are specified,
// it returns all built-in endpoints as a fallback to ensure testing can proceed.
func (t *TesterImpl) getEffectiveEndpoints() []SpeedTestEndpoint {
	// If SelectedEndpoints is specified, filter built-in endpoints
	if len(t.config.SelectedEndpoints) > 0 {
		var selectedEndpoints []SpeedTestEndpoint
		for _, selectedName := range t.config.SelectedEndpoints {
			for _, builtIn := range builtInEndpoints {
				if builtIn.Name == selectedName {
					selectedEndpoints = append(selectedEndpoints, builtIn)
					break
				}
			}
		}
		if len(selectedEndpoints) > 0 {
			return selectedEndpoints
		}
		// If no valid selections found, log warning and fall through to use all built-in
		t.logger.Warn("No valid endpoints found in selection, using all built-in endpoints",
			"selected_endpoints", t.config.SelectedEndpoints)
	}

	// Default: use all built-in endpoints
	return builtInEndpoints
}

// RunTest performs a single bandwidth speed test using randomized endpoint and file size selection.
// It selects a random test size and endpoint (if randomization is enabled), downloads the test file,
// measures the transfer time and bandwidth, and returns comprehensive test results including
// speed calculations, success status, and any error information.
func (t *TesterImpl) RunTest(ctx context.Context) (*Result, error) {
	if !t.config.Enabled {
		return nil, fmt.Errorf("speed test is disabled")
	}

	// Select random test size
	testSize := t.selectRandomTestSize()

	// Select random endpoint
	endpoint, url := t.selectRandomEndpoint(testSize)

	t.logger.Info("Starting speed test",
		"endpoint", endpoint,
		"test_size", testSize,
		"url", url)

	result := &Result{
		Endpoint:  endpoint,
		TestSize:  testSize,
		URL:       url,
		Timestamp: time.Now(),
	}

	// Perform the download test
	start := time.Now()
	bytesRead, err := t.downloadTest(ctx, url)
	duration := time.Since(start)

	result.Duration = duration
	result.BytesRead = bytesRead

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		t.logger.Error("Speed test failed", "error", err, "endpoint", endpoint)
		return result, err
	}

	// Calculate speed in Mbps
	speedMbps := t.calculateSpeedMbps(bytesRead, duration)
	result.SpeedMbps = speedMbps
	result.Success = true

	t.logger.Info("Speed test completed",
		"endpoint", endpoint,
		"test_size", testSize,
		"duration", duration,
		"bytes_read", bytesRead,
		"speed_mbps", fmt.Sprintf("%.2f", speedMbps))

	return result, nil
}

// selectRandomTestSize chooses a test file size from the configured options.
// If randomization is enabled, it randomly selects from available test sizes.
// Otherwise, it uses the first configured test size or defaults to "1MB".
func (t *TesterImpl) selectRandomTestSize() string {
	if len(t.config.TestSizes) == 0 {
		return "1MB" // Default fallback
	}

	if !t.config.RandomizeEndpoints {
		return t.config.TestSizes[0] // Use first size if randomization is disabled
	}

	return t.config.TestSizes[t.rand.Intn(len(t.config.TestSizes))]
}

// selectRandomEndpoint chooses a random endpoint that supports the given test size
func (t *TesterImpl) selectRandomEndpoint(testSize string) (string, string) {
	var availableEndpoints []SpeedTestEndpoint
	effectiveEndpoints := t.getEffectiveEndpoints()

	// Filter endpoints that have the requested test size
	for _, endpoint := range effectiveEndpoints {
		if url, exists := endpoint.URLs[testSize]; exists && url != "" {
			availableEndpoints = append(availableEndpoints, endpoint)
		}
	}

	if len(availableEndpoints) == 0 {
		// Fallback to first endpoint with any available size
		if len(effectiveEndpoints) > 0 {
			endpoint := effectiveEndpoints[0]
			for size, url := range endpoint.URLs {
				if url != "" {
					t.logger.Warn("No endpoints available for requested test size, using fallback",
						"requested_size", testSize, "fallback_size", size)
					return endpoint.Name, url
				}
			}
		}
		return "unknown", ""
	}

	var selectedEndpoint SpeedTestEndpoint
	if t.config.RandomizeEndpoints {
		selectedEndpoint = availableEndpoints[t.rand.Intn(len(availableEndpoints))]
	} else {
		selectedEndpoint = availableEndpoints[0]
	}

	return selectedEndpoint.Name, selectedEndpoint.URLs[testSize]
}

// downloadTest performs the actual download and measures bytes transferred
func (t *TesterImpl) downloadTest(ctx context.Context, url string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers to prevent caching
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to download test file: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d from speed test endpoint", resp.StatusCode)
	}

	// Read the response body and count bytes
	bytesRead, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return bytesRead, fmt.Errorf("failed to read response body: %w", err)
	}

	return bytesRead, nil
}

// calculateSpeedMbps calculates download speed in Mbps
func (t *TesterImpl) calculateSpeedMbps(bytesRead int64, duration time.Duration) float64 {
	if duration.Seconds() == 0 {
		return 0
	}

	// Convert bytes to megabits (1 byte = 8 bits, 1 megabit = 1,000,000 bits)
	megabits := float64(bytesRead) * 8 / 1_000_000
	seconds := duration.Seconds()

	return megabits / seconds
}

// RunMultipleTests runs multiple speed tests and returns averaged results
func (t *TesterImpl) RunMultipleTests(ctx context.Context, count int) ([]*Result, *AggregateResult, error) {
	if count <= 0 {
		count = 1
	}

	results := make([]*Result, 0, count)
	var totalSpeed float64
	var successCount int

	for i := 0; i < count; i++ {
		result, err := t.RunTest(ctx)
		if result != nil {
			results = append(results, result)
			if result.Success {
				totalSpeed += result.SpeedMbps
				successCount++
			}
		}

		// Log error but continue with other tests
		if err != nil {
			t.logger.Warn("Speed test iteration failed", "iteration", i+1, "error", err)
		}

		// Small delay between tests to avoid overwhelming endpoints
		if i < count-1 {
			time.Sleep(time.Second)
		}
	}

	aggregate := &AggregateResult{
		TotalTests:      count,
		SuccessfulTests: successCount,
		FailedTests:     count - successCount,
		SuccessRate:     float64(successCount) / float64(count) * 100,
		Timestamp:       time.Now(),
	}

	if successCount > 0 {
		aggregate.AverageSpeedMbps = totalSpeed / float64(successCount)
		aggregate.FastestSpeedMbps = t.findFastestSpeed(results)
		aggregate.SlowestSpeedMbps = t.findSlowestSpeed(results)
	}

	return results, aggregate, nil
}

// AggregateResult represents aggregated results from multiple speed tests
type AggregateResult struct {
	TotalTests       int       `json:"total_tests"`
	SuccessfulTests  int       `json:"successful_tests"`
	FailedTests      int       `json:"failed_tests"`
	SuccessRate      float64   `json:"success_rate"`
	AverageSpeedMbps float64   `json:"average_speed_mbps"`
	FastestSpeedMbps float64   `json:"fastest_speed_mbps"`
	SlowestSpeedMbps float64   `json:"slowest_speed_mbps"`
	Timestamp        time.Time `json:"timestamp"`
}

// findFastestSpeed finds the fastest successful speed from results
func (t *TesterImpl) findFastestSpeed(results []*Result) float64 {
	var fastest float64
	for _, result := range results {
		if result.Success && result.SpeedMbps > fastest {
			fastest = result.SpeedMbps
		}
	}
	return fastest
}

// findSlowestSpeed finds the slowest successful speed from results
func (t *TesterImpl) findSlowestSpeed(results []*Result) float64 {
	var slowest float64 = -1
	for _, result := range results {
		if result.Success && (slowest == -1 || result.SpeedMbps < slowest) {
			slowest = result.SpeedMbps
		}
	}
	if slowest == -1 {
		return 0
	}
	return slowest
}

// GetAvailableEndpoints returns a list of available endpoints
func (t *TesterImpl) GetAvailableEndpoints() []string {
	effectiveEndpoints := t.getEffectiveEndpoints()
	endpoints := make([]string, len(effectiveEndpoints))
	for i, endpoint := range effectiveEndpoints {
		endpoints[i] = endpoint.Name
	}
	return endpoints
}

// GetAvailableSizes returns a list of available test sizes
func (t *TesterImpl) GetAvailableSizes() []string {
	return t.config.TestSizes
}

// GetEndpointInfo returns detailed information about available endpoints
func (t *TesterImpl) GetEndpointInfo() map[string]map[string]string {
	info := make(map[string]map[string]string)
	effectiveEndpoints := t.getEffectiveEndpoints()
	for _, endpoint := range effectiveEndpoints {
		info[endpoint.Name] = endpoint.URLs
	}
	return info
}

// ValidateEndpoints checks if configured endpoints are reachable
func (t *TesterImpl) ValidateEndpoints(ctx context.Context) map[string]bool {
	results := make(map[string]bool)

	// Create a quick HTTP client with shorter timeout for validation
	client := &http.Client{Timeout: 10 * time.Second}

	effectiveEndpoints := t.getEffectiveEndpoints()
	for _, endpoint := range effectiveEndpoints {
		for size, url := range endpoint.URLs {
			if url == "" {
				continue
			}

			key := fmt.Sprintf("%s (%s)", endpoint.Name, size)

			// Make a HEAD request to check if endpoint is reachable
			req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
			if err != nil {
				results[key] = false
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				results[key] = false
				continue
			}
			_ = resp.Body.Close()

			results[key] = resp.StatusCode == http.StatusOK
		}
	}

	return results
}

// ParseTestSize converts test size string to bytes (for validation)
func ParseTestSize(sizeStr string) (int64, error) {
	sizeStr = strings.ToUpper(strings.TrimSpace(sizeStr))

	var multiplier int64 = 1
	var numStr string

	if strings.HasSuffix(sizeStr, "MB") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "MB")
	} else if strings.HasSuffix(sizeStr, "KB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(sizeStr, "KB")
	} else if strings.HasSuffix(sizeStr, "GB") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "GB")
	} else {
		// Assume bytes if no suffix
		numStr = sizeStr
	}

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid test size format: %s", sizeStr)
	}

	return num * multiplier, nil
}
