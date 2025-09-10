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

// EndpointStats tracks stats for a specific endpoint
type EndpointStats struct {
	Endpoint   string    `json:"endpoint"`
	TotalCalls int       `json:"total_calls"`
	LastCalled time.Time `json:"last_called"`
}

// StatsResponse represents the response structure for the /stats.json endpoint.
// This directly mirrors the collector's internal structure for simplicity.
// Response data is copied in via the mutex for safety.
type StatsResponse struct {
	IncomingAPICalls map[string]*EndpointStats            `json:"incoming_api_calls"`
	OutgoingAPICalls map[string]map[string]*EndpointStats `json:"outgoing_api_calls"`
	LastUpdated      time.Time                            `json:"last_updated"`
}

// Collector tracks API call metrics
type Collector struct {
	mu            sync.RWMutex
	incomingCalls map[string]*EndpointStats
	outgoingCalls map[string]map[string]*EndpointStats
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
		lastUpdated: time.Now(),
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

// GetStats returns the current stats for both incoming and outgoing API calls
func (c *Collector) GetStats() StatsResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	response := StatsResponse{
		IncomingAPICalls: make(map[string]*EndpointStats),
		OutgoingAPICalls: make(map[string]map[string]*EndpointStats),
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
	c.lastUpdated = time.Now()
}
