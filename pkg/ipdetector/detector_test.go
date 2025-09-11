package ipdetector

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"openxvpn/pkg/metrics"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDetector(t *testing.T) {
	cfg := Config{
		Timeout:        5 * time.Second,
		IP2LocationKey: "test-key",
		CacheTTL:       time.Hour,
	}

	detector := NewDetector(cfg)

	assert.Equal(t, cfg.Timeout, detector.timeout, "Expected timeout to match config")
	assert.Equal(t, cfg.IP2LocationKey, detector.ip2LocationKey, "Expected IP2Location key to match config")
	assert.Equal(t, cfg.CacheTTL, detector.cacheTTL, "Expected cache TTL to match config")
}

func TestNewDetectorDefaults(t *testing.T) {
	cfg := Config{} // Empty config to test defaults

	detector := NewDetector(cfg)

	assert.Equal(t, 5*time.Second, detector.timeout, "Expected default timeout 5s")
	assert.Equal(t, 24*time.Hour, detector.cacheTTL, "Expected default cache TTL 24h")
	assert.NotNil(t, detector.logger, "Expected default logger to be set")
}

func TestGetCurrentIP(t *testing.T) {
	tests := []struct {
		name          string
		responseCode  int
		responseBody  string
		expectedIP    string
		expectedError string
	}{
		{
			name:         "success with valid IP",
			responseCode: http.StatusOK,
			responseBody: "192.0.2.1",
			expectedIP:   "192.0.2.1",
		},
		{
			name:         "success with IP and whitespace",
			responseCode: http.StatusOK,
			responseBody: "  192.0.2.1\n  ",
			expectedIP:   "192.0.2.1",
		},
		{
			name:          "HTTP 404 error",
			responseCode:  http.StatusNotFound,
			responseBody:  "Not Found",
			expectedError: "all IP sources failed",
		},
		{
			name:          "HTTP 500 error",
			responseCode:  http.StatusInternalServerError,
			responseBody:  "Internal Server Error",
			expectedError: "all IP sources failed",
		},
		{
			name:          "empty response body",
			responseCode:  http.StatusOK,
			responseBody:  "",
			expectedError: "all IP sources failed",
		},
		{
			name:          "whitespace only response",
			responseCode:  http.StatusOK,
			responseBody:  "   \n\t   ",
			expectedError: "all IP sources failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Accept different URL paths for different IP services
				// "/" for ifconfig.co, "/text" for wtfismyip.com, "/" for icanhazip.com
				assert.True(t, r.URL.Path == "/" || r.URL.Path == "/text")
				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer mockServer.Close()

			detector := createTestDetector()
			detector = overrideIfconfigURL(detector, mockServer.URL)

			ctx := context.Background()
			ip, err := detector.GetCurrentIP(ctx)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Empty(t, ip)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedIP, ip)
			}
		})
	}
}

// Helper function to create a test detector with reasonable defaults
func createTestDetector() *DetectorImpl {
	return NewDetector(Config{
		Timeout:        5 * time.Second,
		IP2LocationKey: "test-api-key",
		Logger:         slog.Default(),
		CacheTTL:       time.Hour,
	})
}

// Helper function to override ifconfig.co URL for testing
// Since we can't easily change the hardcoded URL, we'll use a custom HTTP client
func overrideIfconfigURL(detector *DetectorImpl, baseURL string) *DetectorImpl {
	// Create a custom RoundTripper that redirects ifconfig.co requests to our test server
	originalTransport := detector.httpClient.Transport
	if originalTransport == nil {
		originalTransport = http.DefaultTransport
	}

	detector.httpClient.Transport = &mockTransport{
		original:      originalTransport,
		testServerURL: baseURL,
	}
	return detector
}

// mockTransport intercepts requests to external APIs and redirects them to our test servers
type mockTransport struct {
	original       http.RoundTripper
	testServerURL  string // For ifconfig.co
	ip2LocationURL string // For ip2location.io
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect all IP detection sources to our test server
	if (strings.Contains(req.URL.Host, "ifconfig.co") ||
		strings.Contains(req.URL.Host, "wtfismyip.com") ||
		strings.Contains(req.URL.Host, "icanhazip.com") ||
		strings.Contains(req.URL.Host, "ip.me")) && m.testServerURL != "" {
		// Redirect IP detection services to our test server
		newURL := fmt.Sprintf("%s%s", m.testServerURL, req.URL.Path)
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
		if err != nil {
			return nil, err
		}
		newReq.Header = req.Header
		req = newReq
	} else if strings.Contains(req.URL.Host, "api.ip2location.io") && m.ip2LocationURL != "" {
		// Redirect ip2location.io to our test server, preserve query params
		newURL := fmt.Sprintf("%s%s?%s", m.ip2LocationURL, req.URL.Path, req.URL.RawQuery)
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
		if err != nil {
			return nil, err
		}
		newReq.Header = req.Header
		req = newReq
	}
	return m.original.RoundTrip(req)
}

func TestGetIPInfo_WithoutAPIKey(t *testing.T) {
	tests := []struct {
		name               string
		ifconfigStatusCode int
		ifconfigResponse   string
		expectedError      string
		expectedCountry    string
		expectedCity       string
	}{
		{
			name:               "successful ifconfig.co fallback",
			ifconfigStatusCode: http.StatusOK,
			ifconfigResponse: `{
				"ip": "192.0.2.1",
				"country": "Australia",
				"city": "Sydney",
				"latitude": -33.8688,
				"longitude": 151.2093,
				"asn_org": "Test ISP"
			}`,
			expectedCountry: "Australia",
			expectedCity:    "Sydney",
		},
		{
			name:               "ifconfig.co HTTP error - returns basic IP info",
			ifconfigStatusCode: http.StatusInternalServerError,
			ifconfigResponse:   "Internal Server Error",
			expectedCountry:    "", // Basic IP info has no geolocation
			expectedCity:       "",
		},
		{
			name:               "ifconfig.co JSON parse error - returns basic IP info",
			ifconfigStatusCode: http.StatusOK,
			ifconfigResponse:   "invalid json",
			expectedCountry:    "",
			expectedCity:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/json" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.ifconfigStatusCode)
					w.Write([]byte(tt.ifconfigResponse))
				}
			}))
			defer mockServer.Close()

			// Create detector without API key to force ifconfig fallback
			detector := NewDetector(Config{
				Timeout: 5 * time.Second,
				Logger:  slog.Default(),
				// No IP2LocationKey set
			})
			detector = overrideIfconfigURL(detector, mockServer.URL)

			ctx := context.Background()
			info, err := detector.GetIPInfo(ctx, "192.0.2.1")

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, info)
				assert.Equal(t, "192.0.2.1", info.IP)
				assert.Equal(t, tt.expectedCountry, info.Country)
				assert.Equal(t, tt.expectedCity, info.City)
				assert.False(t, info.Timestamp.IsZero())
			}
		})
	}
}

func TestGetIPInfo_WithAPIKey(t *testing.T) {
	tests := []struct {
		name                  string
		ip2LocationStatusCode int
		ip2LocationResponse   string
		ifconfigStatusCode    int
		ifconfigResponse      string
		expectedError         string
		expectedCountry       string
		expectedCity          string
		expectedRegion        string
		expectedISP           string
	}{
		{
			name:                  "successful IP2Location response",
			ip2LocationStatusCode: http.StatusOK,
			ip2LocationResponse: `{
				"ip": "192.0.2.1",
				"country_name": "Australia",
				"region_name": "New South Wales",
				"city_name": "Sydney",
				"latitude": -33.8688,
				"longitude": 151.2093,
				"isp": "Test ISP Pty Ltd"
			}`,
			ifconfigStatusCode: http.StatusOK, // Not used since IP2Location succeeds
			ifconfigResponse:   `{}`,          // Not used since IP2Location succeeds
			expectedCountry:    "Australia",
			expectedCity:       "Sydney",
			expectedRegion:     "New South Wales",
			expectedISP:        "Test ISP Pty Ltd",
		},
		{
			name:                  "IP2Location fails, ifconfig succeeds",
			ip2LocationStatusCode: http.StatusUnauthorized,
			ip2LocationResponse:   `{"error":"Invalid API key"}`,
			ifconfigStatusCode:    http.StatusOK,
			ifconfigResponse: `{
				"ip": "192.0.2.1",
				"country": "Australia",
				"city": "Sydney",
				"asn_org": "Fallback ISP"
			}`,
			expectedCountry: "Australia",
			expectedCity:    "Sydney",
			expectedISP:     "Fallback ISP",
		},
		{
			name:                  "IP2Location JSON parse error, ifconfig succeeds",
			ip2LocationStatusCode: http.StatusOK,
			ip2LocationResponse:   "invalid json",
			ifconfigStatusCode:    http.StatusOK,
			ifconfigResponse: `{
				"ip": "192.0.2.1",
				"country": "Australia",
				"city": "Sydney",
				"asn_org": "Fallback ISP"
			}`,
			expectedCountry: "Australia",
			expectedCity:    "Sydney",
			expectedISP:     "Fallback ISP",
		},
		{
			name:                  "both IP2Location and ifconfig fail - returns basic IP info",
			ip2LocationStatusCode: http.StatusInternalServerError,
			ip2LocationResponse:   "Server Error",
			ifconfigStatusCode:    http.StatusInternalServerError,
			ifconfigResponse:      "Server Error",
			expectedCountry:       "", // Basic IP info
			expectedCity:          "",
			expectedISP:           "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock servers
			ip2LocationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.RawQuery, "key=test-api-key") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.ip2LocationStatusCode)
					w.Write([]byte(tt.ip2LocationResponse))
				} else {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"error":"Invalid API key"}`))
				}
			}))
			defer ip2LocationServer.Close()

			ifconfigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/json" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.ifconfigStatusCode)
					w.Write([]byte(tt.ifconfigResponse))
				}
			}))
			defer ifconfigServer.Close()

			detector := createTestDetector()
			detector = overrideIP2LocationURL(detector, ip2LocationServer.URL)
			detector = overrideIfconfigURL(detector, ifconfigServer.URL)

			ctx := context.Background()
			info, err := detector.GetIPInfo(ctx, "192.0.2.1")

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, info)
				assert.Equal(t, "192.0.2.1", info.IP)
				assert.Equal(t, tt.expectedCountry, info.Country)
				assert.Equal(t, tt.expectedCity, info.City)
				assert.Equal(t, tt.expectedRegion, info.Region)
				assert.Equal(t, tt.expectedISP, info.ISP)
				assert.False(t, info.Timestamp.IsZero())
			}
		})
	}
}

// Helper function to override IP2Location URL for testing
func overrideIP2LocationURL(detector *DetectorImpl, baseURL string) *DetectorImpl {
	// Enhance our mock transport to handle IP2Location URLs too
	if transport, ok := detector.httpClient.Transport.(*mockTransport); ok {
		transport.ip2LocationURL = baseURL
	} else {
		originalTransport := detector.httpClient.Transport
		if originalTransport == nil {
			originalTransport = http.DefaultTransport
		}
		detector.httpClient.Transport = &mockTransport{
			original:       originalTransport,
			testServerURL:  "", // Keep existing ifconfig override
			ip2LocationURL: baseURL,
		}
	}
	return detector
}

func TestGetIPInfo_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		inputIP       string
		expectedError string
	}{
		{
			name:          "empty IP address",
			inputIP:       "",
			expectedError: "empty IP address",
		},
		{
			name:    "valid IP with successful processing",
			inputIP: "192.0.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock server for successful ifconfig fallback
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/json" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"ip": "192.0.2.1",
						"country": "Australia",
						"city": "Sydney",
						"asn_org": "Test ISP"
					}`))
				}
			}))
			defer mockServer.Close()

			detector := NewDetector(Config{
				Timeout: 5 * time.Second,
				Logger:  slog.Default(),
				// No API key to force ifconfig fallback
			})
			detector = overrideIfconfigURL(detector, mockServer.URL)

			ctx := context.Background()
			info, err := detector.GetIPInfo(ctx, tt.inputIP)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, info)
			} else {
				require.NoError(t, err)
				require.NotNil(t, info)
				assert.Equal(t, "192.0.2.1", info.IP)
				assert.False(t, info.Timestamp.IsZero())
			}
		})
	}
}

func TestGetIPInfo_CacheIntegration(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"ip": "192.0.2.1",
				"country": "Australia",
				"city": "Sydney",
				"asn_org": "Test ISP"
			}`))
		}
	}))
	defer mockServer.Close()

	detector := NewDetector(Config{
		Timeout:  5 * time.Second,
		CacheTTL: time.Hour,
		Logger:   slog.Default(),
	})
	detector = overrideIfconfigURL(detector, mockServer.URL)

	ctx := context.Background()
	testIP := "192.0.2.1"

	// First call - should hit the API
	info1, err := detector.GetIPInfo(ctx, testIP)
	require.NoError(t, err)
	require.NotNil(t, info1)
	assert.Equal(t, testIP, info1.IP)
	assert.Equal(t, "Australia", info1.Country)

	// Verify it's cached
	stats := detector.GetCacheStats()
	assert.Equal(t, 1, stats["total_entries"].(int))
	assert.Equal(t, 1, stats["valid_entries"].(int))

	// Second call - should use cache (no additional API call)
	info2, err := detector.GetIPInfo(ctx, testIP)
	require.NoError(t, err)
	assert.Equal(t, info1.IP, info2.IP)
	assert.Equal(t, info1.Country, info2.Country)
	assert.Equal(t, info1.Timestamp, info2.Timestamp) // Same timestamp confirms cache hit
}

func TestCaching(t *testing.T) {
	detector := NewDetector(Config{
		Timeout:  5 * time.Second,
		CacheTTL: time.Hour,
		Logger:   slog.Default(),
	})

	testIP := "192.0.2.1"
	testInfo := &IPInfo{
		IP:        testIP,
		Country:   "Australia",
		City:      "Sydney",
		Timestamp: time.Now(),
	}

	// Test cache miss
	cached := detector.getCachedIPInfo(testIP)
	assert.Nil(t, cached)

	// Test cache set
	detector.setCachedIPInfo(testIP, testInfo, time.Hour)

	// Test cache hit
	cached = detector.getCachedIPInfo(testIP)
	require.NotNil(t, cached)

	assert.Equal(t, testInfo.IP, cached.IP)

	// Test cache expiration
	detector.setCachedIPInfo(testIP, testInfo, 1*time.Millisecond)
	time.Sleep(2 * time.Millisecond)

	cached = detector.getCachedIPInfo(testIP)
	require.Nil(t, cached)
}

func TestClearCache(t *testing.T) {
	detector := NewDetector(Config{
		Timeout:  5 * time.Second,
		CacheTTL: time.Hour,
		Logger:   slog.Default(),
	})

	// Add some test data
	testInfo := &IPInfo{
		IP:        "192.0.2.1",
		Timestamp: time.Now(),
	}
	detector.setCachedIPInfo("192.0.2.1", testInfo, time.Hour)
	detector.setCachedIPInfo("192.0.2.2", testInfo, time.Hour)

	// Verify cache has entries
	stats := detector.GetCacheStats()
	totalEntries := stats["total_entries"].(int)
	assert.Equal(t, 2, totalEntries, "cache entries")

	// Clear cache
	detector.ClearCache()

	// Verify cache is empty
	stats = detector.GetCacheStats()
	totalEntries = stats["total_entries"].(int)
	assert.Equal(t, 0, totalEntries, "cache entries")
}

func TestGetCacheStats(t *testing.T) {
	detector := NewDetector(Config{
		Timeout:  5 * time.Second,
		CacheTTL: time.Hour,
		Logger:   slog.Default(),
	})

	// Add valid entry
	testInfo := &IPInfo{IP: "192.0.2.1", Timestamp: time.Now()}
	detector.setCachedIPInfo("192.0.2.1", testInfo, time.Hour)

	// Add expired entry
	detector.setCachedIPInfo("192.0.2.2", testInfo, 1*time.Millisecond)
	time.Sleep(2 * time.Millisecond)

	stats := detector.GetCacheStats()

	totalEntries := stats["total_entries"].(int)
	expiredEntries := stats["expired_entries"].(int)
	validEntries := stats["valid_entries"].(int)

	assert.Equal(t, 2, totalEntries, "cache entries")
	assert.Equal(t, 1, expiredEntries, "expired cache entries")
	assert.Equal(t, 1, validEntries, "valid cache entries")
}

func TestHealthCheck(t *testing.T) {
	detector := NewDetector(Config{
		Timeout: 1 * time.Millisecond, // Very short timeout to force failure
		Logger:  slog.Default(),
	})

	ctx := context.Background()
	err := detector.HealthCheck(ctx)

	assert.Error(t, err, "expected error with short timeout")
}

func TestCheckIPChange(t *testing.T) {
	detector := NewDetector(Config{
		Timeout: 1 * time.Millisecond, // Very short timeout to force failure
		Logger:  slog.Default(),
	})

	ctx := context.Background()
	previousIP := "192.0.2.1"

	changed, currentIP, err := detector.CheckIPChange(ctx, previousIP)

	assert.Error(t, err, "expected error with short timeout")
	assert.False(t, changed, "changed")
	assert.Equal(t, "", currentIP, "currentIP")
}

func TestGetCurrentIPInfo_Failure(t *testing.T) {
	detector := NewDetector(Config{
		Timeout: 1 * time.Millisecond, // Very short timeout to force failure
		Logger:  slog.Default(),
	})

	ctx := context.Background()
	info, err := detector.GetCurrentIPInfo(ctx)

	assert.Error(t, err, "expected error with short timeout")
	assert.Nil(t, info, "info")
}

func TestGetCurrentIPInfo_Comprehensive(t *testing.T) {
	tests := []struct {
		name                string
		currentIPStatusCode int
		currentIPResponse   string
		geolocationFailure  bool
		expectedError       string
		expectBasicIPInfo   bool // true if we expect basic IP info when geolocation fails
	}{
		{
			name:                "successful current IP and geolocation",
			currentIPStatusCode: http.StatusOK,
			currentIPResponse:   "192.0.2.1",
			geolocationFailure:  false,
		},
		{
			name:                "successful current IP, geolocation fails gracefully",
			currentIPStatusCode: http.StatusOK,
			currentIPResponse:   "192.0.2.1",
			geolocationFailure:  true,
			expectBasicIPInfo:   true,
		},
		{
			name:                "current IP fetch fails",
			currentIPStatusCode: http.StatusInternalServerError,
			currentIPResponse:   "Server Error",
			expectedError:       "failed to get current IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock servers
			ifconfigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					// Current IP endpoint
					w.WriteHeader(tt.currentIPStatusCode)
					w.Write([]byte(tt.currentIPResponse))
				} else if r.URL.Path == "/json" {
					// Geolocation endpoint
					if tt.geolocationFailure {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("Server Error"))
					} else {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{
							"ip": "192.0.2.1",
							"country": "Australia",
							"city": "Sydney",
							"asn_org": "Test ISP"
						}`))
					}
				}
			}))
			defer ifconfigServer.Close()

			detector := NewDetector(Config{
				Timeout: 5 * time.Second,
				Logger:  slog.Default(),
				// No API key to force ifconfig fallback
			})
			detector = overrideIfconfigURL(detector, ifconfigServer.URL)

			ctx := context.Background()
			info, err := detector.GetCurrentIPInfo(ctx)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, info)
			} else {
				require.NoError(t, err)
				require.NotNil(t, info)
				assert.Equal(t, "192.0.2.1", info.IP)
				assert.False(t, info.Timestamp.IsZero())

				if tt.expectBasicIPInfo {
					// When geolocation fails, we should get basic IP info
					assert.Empty(t, info.Country, "Country should be empty for basic IP info")
					assert.Empty(t, info.City, "City should be empty for basic IP info")
				} else {
					// When geolocation succeeds, we should get full info
					assert.Equal(t, "Australia", info.Country)
					assert.Equal(t, "Sydney", info.City)
				}
			}
		})
	}
}

func TestGetRawIP2LocationData_NoAPIKey(t *testing.T) {
	detector := NewDetector(Config{
		Timeout: 5 * time.Second,
		Logger:  slog.Default(),
		// No API key set
	})

	ctx := context.Background()
	data, err := detector.GetRawIP2LocationData(ctx, "192.0.2.1")

	assert.Error(t, err, "expected error with no API key")
	assert.Nil(t, data, "data")

	expectedError := "IP2Location API key not configured"
	assert.Contains(t, err.Error(), expectedError, "error")
}

func TestGetRawIP2LocationData_Comprehensive(t *testing.T) {
	tests := []struct {
		name          string
		hasAPIKey     bool
		responseCode  int
		responseBody  string
		expectedError string
		expectedData  bool // true if we expect data to be returned
	}{
		{
			name:          "no API key configured",
			hasAPIKey:     false,
			expectedError: "IP2Location API key not configured",
		},
		{
			name:         "successful API response",
			hasAPIKey:    true,
			responseCode: http.StatusOK,
			responseBody: `{
				"ip": "192.0.2.1",
				"country_name": "Australia",
				"city_name": "Sydney"
			}`,
			expectedData: true,
		},
		{
			name:          "HTTP 401 Unauthorized",
			hasAPIKey:     true,
			responseCode:  http.StatusUnauthorized,
			responseBody:  `{"error":"Invalid API key"}`,
			expectedError: "HTTP 401 from ip2location.io",
		},
		{
			name:          "HTTP 500 Server Error",
			hasAPIKey:     true,
			responseCode:  http.StatusInternalServerError,
			responseBody:  "Internal Server Error",
			expectedError: "HTTP 500 from ip2location.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var detector *DetectorImpl
			if tt.hasAPIKey {
				// Create mock server for IP2Location
				mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify API key is present
					assert.Contains(t, r.URL.RawQuery, "key=test-api-key")
					assert.Contains(t, r.URL.RawQuery, "ip=192.0.2.1")

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.responseCode)
					w.Write([]byte(tt.responseBody))
				}))
				defer mockServer.Close()

				detector = createTestDetector()
				detector = overrideIP2LocationURL(detector, mockServer.URL)
			} else {
				// Create detector without API key
				detector = NewDetector(Config{
					Timeout: 5 * time.Second,
					Logger:  slog.Default(),
					// No IP2LocationKey
				})
			}

			ctx := context.Background()
			data, err := detector.GetRawIP2LocationData(ctx, "192.0.2.1")

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, data)
			} else if tt.expectedData {
				require.NoError(t, err)
				require.NotNil(t, data)
				// Verify the response contains expected fields
				var response map[string]interface{}
				err = json.Unmarshal(data, &response)
				require.NoError(t, err)
				assert.Equal(t, "192.0.2.1", response["ip"])
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetRawIP2LocationData_InvalidIP(t *testing.T) {
	detector := NewDetector(Config{
		Timeout:        5 * time.Second,
		Logger:         slog.Default(),
		IP2LocationKey: "test-api-key",
	})

	ctx := context.Background()
	data, err := detector.GetRawIP2LocationData(ctx, "invalid-ip")

	// Should fail due to invalid IP or API error
	assert.Error(t, err, "expected error with invalid IP")
	assert.Nil(t, data, "data")
}

func TestCheckIPChange_Comprehensive(t *testing.T) {
	tests := []struct {
		name           string
		previousIP     string
		currentIP      string
		responseCode   int
		expectedChange bool
		expectedError  string
	}{
		{
			name:           "IP changed",
			previousIP:     "192.0.2.1",
			currentIP:      "192.0.2.100",
			responseCode:   http.StatusOK,
			expectedChange: true,
		},
		{
			name:           "IP unchanged",
			previousIP:     "192.0.2.1",
			currentIP:      "192.0.2.1",
			responseCode:   http.StatusOK,
			expectedChange: false,
		},
		{
			name:          "current IP fetch fails",
			previousIP:    "192.0.2.1",
			responseCode:  http.StatusInternalServerError,
			expectedError: "all IP sources failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseCode)
				if tt.responseCode == http.StatusOK && tt.currentIP != "" {
					w.Write([]byte(tt.currentIP))
				} else {
					w.Write([]byte("Server Error"))
				}
			}))
			defer mockServer.Close()

			detector := createTestDetector()
			detector = overrideIfconfigURL(detector, mockServer.URL)

			ctx := context.Background()
			changed, currentIP, err := detector.CheckIPChange(ctx, tt.previousIP)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.False(t, changed)
				assert.Empty(t, currentIP)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedChange, changed)
				assert.Equal(t, tt.currentIP, currentIP)
			}
		})
	}
}

func TestGetCurrentIP_EdgeCases(t *testing.T) {
	detector := NewDetector(Config{
		Timeout: 5 * time.Second,
		Logger:  slog.Default(),
	})

	ctx := context.Background()

	// Test context cancellation
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel() // Cancel immediately

	ip, err := detector.GetCurrentIP(cancelCtx)
	assert.Error(t, err, "error expected with cancelled context")
	assert.Equal(t, "", ip, "ip")
}

func TestHealthCheck_Comprehensive(t *testing.T) {
	tests := []struct {
		name          string
		responseCode  int
		responseBody  string
		expectedError string
	}{
		{
			name:         "successful health check",
			responseCode: http.StatusOK,
			responseBody: "192.0.2.1",
		},
		{
			name:          "health check fails with HTTP error",
			responseCode:  http.StatusInternalServerError,
			responseBody:  "Server Error",
			expectedError: "IP detection health check failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer mockServer.Close()

			detector := createTestDetector()
			detector = overrideIfconfigURL(detector, mockServer.URL)

			ctx := context.Background()
			err := detector.HealthCheck(ctx)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCacheCleanup(t *testing.T) {
	detector := NewDetector(Config{
		Timeout:  5 * time.Second,
		CacheTTL: time.Hour,
		Logger:   slog.Default(),
	})

	// Add multiple entries with different expiration times
	testInfo := &IPInfo{
		IP:        "192.0.2.1",
		Timestamp: time.Now(),
	}

	// Add valid entry
	detector.setCachedIPInfo("192.0.2.1", testInfo, time.Hour)

	// Add entries that will expire soon
	for i := 2; i <= 15; i++ { // Add 14 entries that will expire
		ip := fmt.Sprintf("192.0.2.%d", i)
		detector.setCachedIPInfo(ip, testInfo, 1*time.Millisecond)
	}

	// Wait for expiration
	time.Sleep(5 * time.Millisecond)

	// Add another entry to trigger cleanup (max 10 cleanups per call)
	detector.setCachedIPInfo("192.0.2.100", testInfo, time.Hour)

	// Verify cleanup occurred (should clean up 10 expired entries)
	stats := detector.GetCacheStats()
	totalEntries := stats["total_entries"].(int)
	expiredEntries := stats["expired_entries"].(int)

	// We should have fewer total entries due to cleanup
	// Original: 1 valid + 14 expired + 1 new valid = 16 total
	// After cleanup: should have removed 10 expired entries
	assert.LessOrEqual(t, totalEntries, 6, "cleanup should have removed some expired entries")
	assert.LessOrEqual(t, expiredEntries, 4, "some expired entries should remain after partial cleanup")
}

func TestContextCancellation(t *testing.T) {
	// Test context cancellation for various methods
	t.Run("GetCurrentIP with cancelled context", func(t *testing.T) {
		detector := createTestDetector()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		ip, err := detector.GetCurrentIP(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
		assert.Empty(t, ip)
	})

	t.Run("GetIPInfo with cancelled context", func(t *testing.T) {
		detector := createTestDetector()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		info, err := detector.GetIPInfo(ctx, "192.0.2.1")
		// This should either return cached info or fail with context error
		if err != nil {
			assert.Contains(t, err.Error(), "context canceled")
			assert.Nil(t, info)
		}
	})

	t.Run("GetRawIP2LocationData with cancelled context", func(t *testing.T) {
		detector := createTestDetector()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		data, err := detector.GetRawIP2LocationData(ctx, "192.0.2.1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
		assert.Nil(t, data)
	})
}

func TestTimeoutHandling(t *testing.T) {
	// Test timeout handling with slow server
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // Slow response - much longer than timeout
		w.Write([]byte("192.0.2.1"))
	}))
	defer slowServer.Close()

	detector := NewDetector(Config{
		Timeout: 50 * time.Millisecond, // Shorter than server response time
		Logger:  slog.Default(),
	})
	detector = overrideIfconfigURL(detector, slowServer.URL)

	ctx := context.Background()
	ip, err := detector.GetCurrentIP(ctx)

	require.Error(t, err)
	res := strings.Contains(err.Error(), "Timeout") ||
		strings.Contains(err.Error(), "deadline exceeded")
	assert.True(t, res, "expected timeout error")
	assert.Empty(t, ip)
}

func TestJSONParsingEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		jsonResponse string
		expectedIP   string
	}{
		{
			name:         "malformed JSON falls back to basic IP",
			jsonResponse: `{"ip": "192.0.2.1", malformed json`,
			expectedIP:   "192.0.2.1", // Should fallback to basic IP info
		},
		{
			name:         "empty JSON object",
			jsonResponse: `{}`,
			expectedIP:   "192.0.2.1", // Should fallback to basic IP info
		},
		{
			name:         "null values in JSON",
			jsonResponse: `{"ip": null, "country": null}`,
			expectedIP:   "192.0.2.1", // Should fallback to basic IP info
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/json" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(tt.jsonResponse))
				}
			}))
			defer mockServer.Close()

			detector := NewDetector(Config{
				Timeout: 5 * time.Second,
				Logger:  slog.Default(),
			})
			detector = overrideIfconfigURL(detector, mockServer.URL)

			ctx := context.Background()
			info, err := detector.GetIPInfo(ctx, tt.expectedIP)

			// Should not error, should fall back gracefully
			require.NoError(t, err)
			require.NotNil(t, info)
			assert.Equal(t, tt.expectedIP, info.IP)
			// When JSON parsing fails, should get basic IP info
			assert.False(t, info.Timestamp.IsZero())
		})
	}
}

// TestJSONValidationChanges tests the new JSON validation functionality
func TestHTMLResponseValidation(t *testing.T) {
	tests := []struct {
		name          string
		response      string
		contentType   string
		expectError   bool
		errorContains string
	}{
		{
			name:          "HTML response with doctype",
			response:      "<!DOCTYPE html><html><body>Error</body></html>",
			contentType:   "text/html",
			expectError:   true,
			errorContains: "received HTML response",
		},
		{
			name:          "HTML response with html tag",
			response:      "<html><head><title>Error</title></head></html>",
			contentType:   "text/plain",
			expectError:   true,
			errorContains: "received HTML response",
		},
		{
			name:          "Response with HTML tags",
			response:      "<h1>Service Unavailable</h1>",
			contentType:   "text/plain",
			expectError:   true,
			errorContains: "received HTML response",
		},
		{
			name:          "Invalid IP format",
			response:      "not.an.ip.address",
			contentType:   "text/plain",
			expectError:   true,
			errorContains: "invalid IP address format",
		},
		{
			name:        "Valid IPv4",
			response:    "192.0.2.1",
			contentType: "text/plain",
			expectError: false,
		},
		{
			name:        "Valid IPv6",
			response:    "2001:db8::1",
			contentType: "text/plain",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			detector := NewDetector(Config{
				Timeout:  time.Second,
				CacheTTL: time.Minute,
				Logger:   slog.Default(),
			})

			ctx := context.Background()
			ip, err := detector.fetchIPFromSource(ctx, server.URL)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing %q, got: %s", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %s", err.Error())
					return
				}
				if ip != tt.response {
					t.Errorf("Expected IP %q, got %q", tt.response, ip)
				}
			}
		})
	}
}

func TestCurrentIPCaching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// Return different IPs to test caching
		if callCount == 1 {
			w.Write([]byte("192.0.2.1"))
		} else {
			w.Write([]byte("203.0.113.1"))
		}
	}))
	defer server.Close()

	detector := NewDetector(Config{
		Timeout:  time.Second,
		CacheTTL: time.Hour,
		Logger:   slog.Default(),
	})

	// Replace the sources with our test server
	detector.httpClient = &http.Client{Timeout: time.Second}

	ctx := context.Background()

	// Manually test the caching by calling fetchIPFromSource and then the cache mechanism
	ip1, err := detector.fetchIPFromSource(ctx, server.URL)
	if err != nil {
		t.Fatalf("First fetch failed: %s", err.Error())
	}

	// Cache the result
	ipInfo := &IPInfo{
		IP:        ip1,
		Timestamp: time.Now(),
	}
	detector.setCachedIPInfo(currentIPCacheKey, ipInfo, currentIPCacheDuration)

	// Second call should use cache
	if cached := detector.getCachedIPInfo(currentIPCacheKey); cached == nil {
		t.Errorf("Expected cached IP but cache was empty")
	} else if cached.IP != ip1 {
		t.Errorf("Expected cached IP %s, got %s", ip1, cached.IP)
	}

	// Clear cache
	detector.ClearCache()

	// After clear, cache should be empty
	if cached := detector.getCachedIPInfo(currentIPCacheKey); cached != nil {
		t.Errorf("Expected empty cache after clear, but got IP: %s", cached.IP)
	}
}

func TestJSONValidationChanges(t *testing.T) {
	t.Run("IP2Location non-JSON content-type fallback", func(t *testing.T) {
		// Mock servers
		ip2LocationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return HTML instead of JSON
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Error page</body></html>"))
		}))
		defer ip2LocationServer.Close()

		ifconfigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/json" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"ip": "192.0.2.1",
					"country": "Australia",
					"city": "Sydney",
					"asn_org": "Test ISP"
				}`))
			}
		}))
		defer ifconfigServer.Close()

		detector := createTestDetector()
		detector = overrideIP2LocationURL(detector, ip2LocationServer.URL)
		detector = overrideIfconfigURL(detector, ifconfigServer.URL)

		ctx := context.Background()
		info, err := detector.GetIPInfo(ctx, "192.0.2.1")

		require.NoError(t, err)
		require.NotNil(t, info)
		assert.Equal(t, "192.0.2.1", info.IP)
		assert.Equal(t, "Australia", info.Country)
		assert.Equal(t, "Sydney", info.City)
		assert.Equal(t, "Test ISP", info.ISP)
	})

	t.Run("IP2Location invalid JSON fallback", func(t *testing.T) {
		// Mock servers
		ip2LocationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return invalid JSON
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ip": "192.0.2.1", "country": malformed`))
		}))
		defer ip2LocationServer.Close()

		ifconfigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/json" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"ip": "192.0.2.1",
					"country": "Australia",
					"city": "Sydney",
					"asn_org": "Test ISP"
				}`))
			}
		}))
		defer ifconfigServer.Close()

		detector := createTestDetector()
		detector = overrideIP2LocationURL(detector, ip2LocationServer.URL)
		detector = overrideIfconfigURL(detector, ifconfigServer.URL)

		ctx := context.Background()
		info, err := detector.GetIPInfo(ctx, "192.0.2.1")

		require.NoError(t, err)
		require.NotNil(t, info)
		assert.Equal(t, "192.0.2.1", info.IP)
		assert.Equal(t, "Australia", info.Country)
		assert.Equal(t, "Sydney", info.City)
		assert.Equal(t, "Test ISP", info.ISP)
	})

	t.Run("ifconfig.co non-JSON content-type fallback", func(t *testing.T) {
		ifconfigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/json" {
				// Return plain text instead of JSON
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("192.0.2.1"))
			}
		}))
		defer ifconfigServer.Close()

		detector := NewDetector(Config{
			Timeout: 5 * time.Second,
			Logger:  slog.Default(),
		})
		detector = overrideIfconfigURL(detector, ifconfigServer.URL)

		ctx := context.Background()
		info, err := detector.GetIPInfo(ctx, "192.0.2.1")

		require.NoError(t, err)
		require.NotNil(t, info)
		assert.Equal(t, "192.0.2.1", info.IP)
		// Should fall back to basic IP info when content-type is not JSON
		assert.Empty(t, info.Country)
		assert.Empty(t, info.City)
		assert.False(t, info.Timestamp.IsZero())
	})

	t.Run("ifconfig.co invalid JSON fallback", func(t *testing.T) {
		ifconfigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/json" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				// Return invalid JSON
				w.Write([]byte(`{"ip": "192.0.2.1", invalid json`))
			}
		}))
		defer ifconfigServer.Close()

		detector := NewDetector(Config{
			Timeout: 5 * time.Second,
			Logger:  slog.Default(),
		})
		detector = overrideIfconfigURL(detector, ifconfigServer.URL)

		ctx := context.Background()
		info, err := detector.GetIPInfo(ctx, "192.0.2.1")

		require.NoError(t, err)
		require.NotNil(t, info)
		assert.Equal(t, "192.0.2.1", info.IP)
		// Should fall back to basic IP info when JSON is invalid
		assert.Empty(t, info.Country)
		assert.Empty(t, info.City)
		assert.False(t, info.Timestamp.IsZero())
	})

	t.Run("GetRawIP2LocationData non-JSON content-type error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return HTML instead of JSON
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Error page</body></html>"))
		}))
		defer mockServer.Close()

		detector := createTestDetector()
		detector = overrideIP2LocationURL(detector, mockServer.URL)

		ctx := context.Background()
		data, err := detector.GetRawIP2LocationData(ctx, "192.0.2.1")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "returned non-JSON response")
		assert.Contains(t, err.Error(), "text/html")
		assert.Nil(t, data)
	})

	t.Run("GetRawIP2LocationData invalid JSON returned as-is", func(t *testing.T) {
		invalidJSON := `{"ip": "192.0.2.1", invalid json`
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Return invalid JSON
			w.Write([]byte(invalidJSON))
		}))
		defer mockServer.Close()

		detector := createTestDetector()
		detector = overrideIP2LocationURL(detector, mockServer.URL)

		ctx := context.Background()
		data, err := detector.GetRawIP2LocationData(ctx, "192.0.2.1")

		require.NoError(t, err) // No longer validates JSON - returns raw data
		require.NotNil(t, data)
		assert.Equal(t, invalidJSON, string(data))
	})

	t.Run("GetRawIP2LocationData valid JSON success", func(t *testing.T) {
		validJSON := `{
			"ip": "192.0.2.1",
			"country_name": "Australia",
			"city_name": "Sydney",
			"isp": "Test ISP"
		}`

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(validJSON))
		}))
		defer mockServer.Close()

		detector := createTestDetector()
		detector = overrideIP2LocationURL(detector, mockServer.URL)

		ctx := context.Background()
		data, err := detector.GetRawIP2LocationData(ctx, "192.0.2.1")

		require.NoError(t, err)
		require.NotNil(t, data)

		// Verify the returned data is valid JSON
		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.1", result["ip"])
		assert.Equal(t, "Australia", result["country_name"])
		assert.Equal(t, "Sydney", result["city_name"])
		assert.Equal(t, "Test ISP", result["isp"])
	})

	t.Run("both services return non-JSON - fallback to basic IP info", func(t *testing.T) {
		// Both servers return HTML error pages
		ip2LocationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>IP2Location Error</body></html>"))
		}))
		defer ip2LocationServer.Close()

		ifconfigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/json" {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<html><body>ifconfig Error</body></html>"))
			}
		}))
		defer ifconfigServer.Close()

		detector := createTestDetector()
		detector = overrideIP2LocationURL(detector, ip2LocationServer.URL)
		detector = overrideIfconfigURL(detector, ifconfigServer.URL)

		ctx := context.Background()
		info, err := detector.GetIPInfo(ctx, "192.0.2.1")

		require.NoError(t, err)
		require.NotNil(t, info)
		assert.Equal(t, "192.0.2.1", info.IP)
		// Should fall back to basic IP info when both services fail
		assert.Empty(t, info.Country)
		assert.Empty(t, info.City)
		assert.Empty(t, info.ISP)
		assert.False(t, info.Timestamp.IsZero())
	})
}

func TestSetMetricsCollector(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ip": "1.2.3.4", "country": "Test Country", "city": "Test City", "asn_org": "Test ISP"}`))
	}))
	defer mockServer.Close()

	detector := NewDetector(Config{
		Timeout: 5 * time.Second,
		Logger:  slog.Default(),
	})
	detector = overrideIfconfigURL(detector, mockServer.URL)

	collector := metrics.NewCollector()
	detector.SetMetricsCollector(collector)

	// Make an API call that should trigger metrics collection
	_, err := detector.GetIPInfo(context.Background(), "1.2.3.4")
	require.NoError(t, err)

	stats := collector.GetStats()
	// Verify that an outgoing call was recorded for geo_lookup
	geoLookups := stats.OutgoingAPICalls[metrics.GeoLookup]
	assert.Len(t, geoLookups, 1)
	// Check that the geo_lookup endpoint was called
	assert.Contains(t, geoLookups, "geo_lookup")
	assert.Equal(t, 1, geoLookups["geo_lookup"].TotalCalls)
}
