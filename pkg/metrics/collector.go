package metrics

import (
	"sync"
	"time"
)

// Lookup type constants
const (
	// IPOnlyLookup represents simple IP lookups without geolocation data
	IPOnlyLookup = "ip_only"

	// GeoLookup represents lookups that include geolocation data
	GeoLookup = "geo_lookup"
)

// VPN event type constants
const (
	// VPNConnect represents VPN connection events
	VPNConnect = "vpn_connect"

	// VPNDisconnect represents VPN disconnection events
	VPNDisconnect = "vpn_disconnect"

	// VPNReconnect represents VPN reconnection events
	VPNReconnect = "vpn_reconnect"
)

// EndpointStats tracks stats for a specific endpoint
type EndpointStats struct {
	Endpoint   string    `json:"endpoint"`
	TotalCalls int       `json:"total_calls"`
	LastCalled time.Time `json:"last_called"`
}

// SpeedTestStats tracks speed test results and statistics
type SpeedTestStats struct {
	TotalTests       int       `json:"total_tests"`
	SuccessfulTests  int       `json:"successful_tests"`
	FailedTests      int       `json:"failed_tests"`
	SuccessRate      float64   `json:"success_rate"`
	AverageSpeedMbps float64   `json:"average_speed_mbps"`
	FastestSpeedMbps float64   `json:"fastest_speed_mbps"`
	SlowestSpeedMbps float64   `json:"slowest_speed_mbps"`
	LastTest         time.Time `json:"last_test"`
}

// StatsResponse represents the response structure for the /stats.json endpoint.
// This directly mirrors the collector's internal structure for simplicity.
// Response data is copied in via the mutex for safety.
type StatsResponse struct {
	IncomingAPICalls map[string]*EndpointStats            `json:"incoming_api_calls"`
	OutgoingAPICalls map[string]map[string]*EndpointStats `json:"outgoing_api_calls"`
	VPNEvents        map[string]*EndpointStats            `json:"vpn_events"`
	SpeedTestResults *SpeedTestStats                      `json:"speed_test_results"`
	ApplicationStart time.Time                            `json:"application_start"`
	LastUpdated      time.Time                            `json:"last_updated"`
}

// Collector tracks API call metrics
type Collector struct {
	mu            sync.RWMutex
	incomingCalls map[string]*EndpointStats
	outgoingCalls map[string]map[string]*EndpointStats
	vpnEvents     map[string]*EndpointStats
	speedTests    *SpeedTestStats
	appStartTime  time.Time
	lastUpdated   time.Time
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{
		incomingCalls: make(map[string]*EndpointStats),
		outgoingCalls: map[string]map[string]*EndpointStats{
			IPOnlyLookup: make(map[string]*EndpointStats),
			GeoLookup:    make(map[string]*EndpointStats),
		},
		vpnEvents: make(map[string]*EndpointStats),
		speedTests: &SpeedTestStats{
			TotalTests:       0,
			SuccessfulTests:  0,
			FailedTests:      0,
			SuccessRate:      0.0,
			AverageSpeedMbps: 0.0,
			FastestSpeedMbps: 0.0,
			SlowestSpeedMbps: 0.0,
			LastTest:         time.Time{},
		},
		appStartTime: time.Now(),
		lastUpdated:  time.Now(),
	}
}

// RecordIncomingCall records an API call made to this service
func (c *Collector) RecordIncomingCall(endpoint string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get or create stats for this endpoint
	stats, exists := c.incomingCalls[endpoint]
	if !exists {
		stats = &EndpointStats{
			Endpoint: endpoint,
		}
		c.incomingCalls[endpoint] = stats
	}

	// Update stats
	stats.TotalCalls++
	stats.LastCalled = time.Now()
	c.lastUpdated = time.Now()
}

// RecordOutgoingCall records an API call made by this service to an external service
func (c *Collector) RecordOutgoingCall(lookupType string, endpoint string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure lookup type map exists
	if _, exists := c.outgoingCalls[lookupType]; !exists {
		c.outgoingCalls[lookupType] = make(map[string]*EndpointStats)
	}

	// Get or create stats for this endpoint
	stats, exists := c.outgoingCalls[lookupType][endpoint]
	if !exists {
		stats = &EndpointStats{
			Endpoint: endpoint,
		}
		c.outgoingCalls[lookupType][endpoint] = stats
	}

	// Update stats
	stats.TotalCalls++
	stats.LastCalled = time.Now()
	c.lastUpdated = time.Now()
}

// RecordVPNEvent records a VPN-related event (connect, disconnect, reconnect)
func (c *Collector) RecordVPNEvent(eventType string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get or create stats for this event type
	stats, exists := c.vpnEvents[eventType]
	if !exists {
		stats = &EndpointStats{
			Endpoint: eventType,
		}
		c.vpnEvents[eventType] = stats
	}

	// Update stats
	stats.TotalCalls++
	stats.LastCalled = time.Now()
	c.lastUpdated = time.Now()
}

// RecordSpeedTestResult records the result of a speed test
func (c *Collector) RecordSpeedTestResult(speedMbps float64, success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.speedTests.TotalTests++
	c.speedTests.LastTest = time.Now()

	if success {
		c.speedTests.SuccessfulTests++

		// Update speed statistics
		if c.speedTests.FastestSpeedMbps == 0 || speedMbps > c.speedTests.FastestSpeedMbps {
			c.speedTests.FastestSpeedMbps = speedMbps
		}

		if c.speedTests.SlowestSpeedMbps == 0 || speedMbps < c.speedTests.SlowestSpeedMbps {
			c.speedTests.SlowestSpeedMbps = speedMbps
		}

		// Calculate new average speed (simple running average)
		if c.speedTests.SuccessfulTests == 1 {
			c.speedTests.AverageSpeedMbps = speedMbps
		} else {
			c.speedTests.AverageSpeedMbps = ((c.speedTests.AverageSpeedMbps * float64(c.speedTests.SuccessfulTests-1)) + speedMbps) / float64(c.speedTests.SuccessfulTests)
		}
	} else {
		c.speedTests.FailedTests++
	}

	// Update success rate
	c.speedTests.SuccessRate = float64(c.speedTests.SuccessfulTests) / float64(c.speedTests.TotalTests) * 100.0

	c.lastUpdated = time.Now()
}

// GetStats returns the current stats for both incoming and outgoing API calls
func (c *Collector) GetStats() StatsResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	response := StatsResponse{
		IncomingAPICalls: make(map[string]*EndpointStats),
		OutgoingAPICalls: make(map[string]map[string]*EndpointStats),
		VPNEvents:        make(map[string]*EndpointStats),
		SpeedTestResults: &SpeedTestStats{
			TotalTests:       c.speedTests.TotalTests,
			SuccessfulTests:  c.speedTests.SuccessfulTests,
			FailedTests:      c.speedTests.FailedTests,
			SuccessRate:      c.speedTests.SuccessRate,
			AverageSpeedMbps: c.speedTests.AverageSpeedMbps,
			FastestSpeedMbps: c.speedTests.FastestSpeedMbps,
			SlowestSpeedMbps: c.speedTests.SlowestSpeedMbps,
			LastTest:         c.speedTests.LastTest,
		},
		ApplicationStart: c.appStartTime,
		LastUpdated:      c.lastUpdated,
	}

	// Copy incoming call stats
	for endpoint, stats := range c.incomingCalls {
		response.IncomingAPICalls[endpoint] = &EndpointStats{
			Endpoint:   stats.Endpoint,
			TotalCalls: stats.TotalCalls,
			LastCalled: stats.LastCalled,
		}
	}

	// Copy outgoing call stats
	for lookupType, endpoints := range c.outgoingCalls {
		response.OutgoingAPICalls[lookupType] = make(map[string]*EndpointStats)

		for endpoint, stats := range endpoints {
			response.OutgoingAPICalls[lookupType][endpoint] = &EndpointStats{
				Endpoint:   stats.Endpoint,
				TotalCalls: stats.TotalCalls,
				LastCalled: stats.LastCalled,
			}
		}
	}

	// Copy VPN event stats
	for eventType, stats := range c.vpnEvents {
		response.VPNEvents[eventType] = &EndpointStats{
			Endpoint:   stats.Endpoint,
			TotalCalls: stats.TotalCalls,
			LastCalled: stats.LastCalled,
		}
	}

	return response
}

// Reset clears all collected metrics
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.incomingCalls = make(map[string]*EndpointStats)
	c.outgoingCalls = map[string]map[string]*EndpointStats{
		IPOnlyLookup: make(map[string]*EndpointStats),
		GeoLookup:    make(map[string]*EndpointStats),
	}
	c.vpnEvents = make(map[string]*EndpointStats)
	c.speedTests = &SpeedTestStats{
		TotalTests:       0,
		SuccessfulTests:  0,
		FailedTests:      0,
		SuccessRate:      0.0,
		AverageSpeedMbps: 0.0,
		FastestSpeedMbps: 0.0,
		SlowestSpeedMbps: 0.0,
		LastTest:         time.Time{},
	}
	// Note: we don't reset appStartTime as it should remain the original start time
	c.lastUpdated = time.Now()
}
