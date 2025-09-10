package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewCollector(t *testing.T) {
	// Create new collector
	collector := NewCollector()
	assert.NotNil(t, collector)

	// Verify that collector is created properly
	assert.NotNil(t, collector)

	// We can verify the stats response to check if maps are initialized
	stats := collector.GetStats()
	assert.NotNil(t, stats.IncomingAPICalls)
	assert.NotNil(t, stats.OutgoingAPICalls)
	assert.NotNil(t, stats.OutgoingAPICalls[IPOnlyLookup])
	assert.NotNil(t, stats.OutgoingAPICalls[GeoLookup])
}

func TestRecordIncomingCall(t *testing.T) {
	collector := NewCollector()

	// Record a single call
	collector.RecordIncomingCall("/health")

	// Get stats to verify the call was recorded
	stats := collector.GetStats()
	assert.Len(t, stats.IncomingAPICalls, 1)
	assert.Contains(t, stats.IncomingAPICalls, "/health")
	assert.Equal(t, 1, stats.IncomingAPICalls["/health"].TotalCalls)
	assert.NotEqual(t, time.Time{}, stats.IncomingAPICalls["/health"].LastCalled)

	// Record another call to the same endpoint
	collector.RecordIncomingCall("/health")

	// Get stats to verify the counter was incremented
	stats = collector.GetStats()
	assert.Equal(t, 2, stats.IncomingAPICalls["/health"].TotalCalls)

	// Record a call to a different endpoint
	collector.RecordIncomingCall("/")

	// Get stats to verify both endpoints are tracked
	stats = collector.GetStats()
	assert.Len(t, stats.IncomingAPICalls, 2)
	assert.Contains(t, stats.IncomingAPICalls, "/")
	assert.Equal(t, 1, stats.IncomingAPICalls["/"].TotalCalls)
}

func TestRecordOutgoingCall(t *testing.T) {
	collector := NewCollector()

	// Record a call with IP-only lookup
	collector.RecordOutgoingCall(IPOnlyLookup, "ifconfig.me")

	// Get stats to verify the call was recorded
	stats := collector.GetStats()
	assert.Len(t, stats.OutgoingAPICalls[IPOnlyLookup], 1)
	assert.Contains(t, stats.OutgoingAPICalls[IPOnlyLookup], "ifconfig.me")
	assert.Equal(t, 1, stats.OutgoingAPICalls[IPOnlyLookup]["ifconfig.me"].TotalCalls)

	// Record a call with geo lookup
	collector.RecordOutgoingCall(GeoLookup, "ip2location.io")

	// Get stats to verify the geo lookup call was recorded
	stats = collector.GetStats()
	assert.Len(t, stats.OutgoingAPICalls[GeoLookup], 1)
	assert.Contains(t, stats.OutgoingAPICalls[GeoLookup], "ip2location.io")
	assert.Equal(t, 1, stats.OutgoingAPICalls[GeoLookup]["ip2location.io"].TotalCalls)

	// Record another call to the same endpoint
	collector.RecordOutgoingCall(GeoLookup, "ip2location.io")

	// Get stats to verify the counter was incremented
	stats = collector.GetStats()
	assert.Equal(t, 2, stats.OutgoingAPICalls[GeoLookup]["ip2location.io"].TotalCalls)

	// Record call with a custom lookup type that doesn't exist yet
	collector.RecordOutgoingCall("custom_lookup", "api.example.com")

	// Get stats to verify the custom lookup was created and call was recorded
	stats = collector.GetStats()
	assert.Contains(t, stats.OutgoingAPICalls, "custom_lookup")
	assert.Len(t, stats.OutgoingAPICalls["custom_lookup"], 1)
	assert.Contains(t, stats.OutgoingAPICalls["custom_lookup"], "api.example.com")
	assert.Equal(t, 1, stats.OutgoingAPICalls["custom_lookup"]["api.example.com"].TotalCalls)
}

func TestGetStats(t *testing.T) {
	collector := NewCollector()

	// Record some calls
	collector.RecordIncomingCall("/health")
	collector.RecordIncomingCall("/health")
	collector.RecordIncomingCall("/")
	collector.RecordOutgoingCall(IPOnlyLookup, "ifconfig.me")
	collector.RecordOutgoingCall(GeoLookup, "ip2location.io")

	// Get stats
	stats := collector.GetStats()

	// Verify stats are as expected
	assert.NotEqual(t, time.Time{}, stats.LastUpdated)

	// Check incoming calls
	assert.Len(t, stats.IncomingAPICalls, 2)
	assert.Contains(t, stats.IncomingAPICalls, "/health")
	assert.Contains(t, stats.IncomingAPICalls, "/")
	assert.Equal(t, 2, stats.IncomingAPICalls["/health"].TotalCalls)
	assert.Equal(t, 1, stats.IncomingAPICalls["/"].TotalCalls)

	// Check outgoing calls
	assert.Len(t, stats.OutgoingAPICalls, 2)
	assert.Contains(t, stats.OutgoingAPICalls, IPOnlyLookup)
	assert.Contains(t, stats.OutgoingAPICalls, GeoLookup)

	assert.Contains(t, stats.OutgoingAPICalls[IPOnlyLookup], "ifconfig.me")
	assert.Equal(t, 1, stats.OutgoingAPICalls[IPOnlyLookup]["ifconfig.me"].TotalCalls)

	assert.Contains(t, stats.OutgoingAPICalls[GeoLookup], "ip2location.io")
	assert.Equal(t, 1, stats.OutgoingAPICalls[GeoLookup]["ip2location.io"].TotalCalls)

	// Verify that the stats are copies and not references
	collector.RecordIncomingCall("/health")
	assert.Equal(t, 2, stats.IncomingAPICalls["/health"].TotalCalls)
}

func TestReset(t *testing.T) {
	collector := NewCollector()

	// Record some calls
	collector.RecordIncomingCall("/health")
	collector.RecordOutgoingCall(IPOnlyLookup, "ifconfig.me")

	// Reset the collector
	collector.Reset()

	// Verify everything is cleared
	stats := collector.GetStats()
	assert.Len(t, stats.IncomingAPICalls, 0)
	assert.Len(t, stats.OutgoingAPICalls[IPOnlyLookup], 0)
	assert.Len(t, stats.OutgoingAPICalls[GeoLookup], 0)
}
