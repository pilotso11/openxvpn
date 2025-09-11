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
	assert.NotNil(t, stats.VPNEvents)
	assert.NotNil(t, stats.SpeedTestResults)
	assert.NotNil(t, stats.OutgoingAPICalls[IPOnlyLookup])
	assert.NotNil(t, stats.OutgoingAPICalls[GeoLookup])
	assert.False(t, stats.ApplicationStart.IsZero())
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
	assert.Len(t, stats.VPNEvents, 0)
}

func TestRecordVPNEvent(t *testing.T) {
	collector := NewCollector()

	// Record VPN connect event
	collector.RecordVPNEvent(VPNConnect)

	// Get stats and verify
	stats := collector.GetStats()
	assert.Contains(t, stats.VPNEvents, VPNConnect)
	assert.Equal(t, 1, stats.VPNEvents[VPNConnect].TotalCalls)
	assert.Equal(t, VPNConnect, stats.VPNEvents[VPNConnect].Endpoint)
	assert.False(t, stats.VPNEvents[VPNConnect].LastCalled.IsZero())

	// Record same event again
	collector.RecordVPNEvent(VPNConnect)

	stats = collector.GetStats()
	assert.Equal(t, 2, stats.VPNEvents[VPNConnect].TotalCalls)

	// Record different VPN events
	collector.RecordVPNEvent(VPNDisconnect)
	collector.RecordVPNEvent(VPNReconnect)

	stats = collector.GetStats()
	assert.Contains(t, stats.VPNEvents, VPNDisconnect)
	assert.Contains(t, stats.VPNEvents, VPNReconnect)
	assert.Equal(t, 1, stats.VPNEvents[VPNDisconnect].TotalCalls)
	assert.Equal(t, 1, stats.VPNEvents[VPNReconnect].TotalCalls)
}

func TestApplicationStartTime(t *testing.T) {
	startTime := time.Now()

	// Create collector after recording start time
	time.Sleep(1 * time.Millisecond) // Ensure some time passes
	collector := NewCollector()

	stats := collector.GetStats()

	// Application start time should be set and be after our recorded start time
	assert.False(t, stats.ApplicationStart.IsZero())
	assert.True(t, stats.ApplicationStart.After(startTime))

	// Application start time should not change after reset (but VPN events should be cleared)
	originalStartTime := stats.ApplicationStart
	collector.RecordVPNEvent(VPNConnect)

	time.Sleep(1 * time.Millisecond)
	collector.Reset()

	stats = collector.GetStats()
	assert.Equal(t, originalStartTime, stats.ApplicationStart)
	assert.Len(t, stats.VPNEvents, 0)
}

func TestRecordSpeedTestResult(t *testing.T) {
	collector := NewCollector()

	// Test successful speed test
	collector.RecordSpeedTestResult(50.5, true)

	stats := collector.GetStats()
	assert.Equal(t, 1, stats.SpeedTestResults.TotalTests)
	assert.Equal(t, 1, stats.SpeedTestResults.SuccessfulTests)
	assert.Equal(t, 0, stats.SpeedTestResults.FailedTests)
	assert.Equal(t, 100.0, stats.SpeedTestResults.SuccessRate)
	assert.Equal(t, 50.5, stats.SpeedTestResults.AverageSpeedMbps)
	assert.Equal(t, 50.5, stats.SpeedTestResults.FastestSpeedMbps)
	assert.Equal(t, 50.5, stats.SpeedTestResults.SlowestSpeedMbps)
	assert.False(t, stats.SpeedTestResults.LastTest.IsZero())

	// Test another successful speed test with different speed
	collector.RecordSpeedTestResult(75.0, true)

	stats = collector.GetStats()
	assert.Equal(t, 2, stats.SpeedTestResults.TotalTests)
	assert.Equal(t, 2, stats.SpeedTestResults.SuccessfulTests)
	assert.Equal(t, 0, stats.SpeedTestResults.FailedTests)
	assert.Equal(t, 100.0, stats.SpeedTestResults.SuccessRate)
	assert.Equal(t, 62.75, stats.SpeedTestResults.AverageSpeedMbps) // (50.5 + 75.0) / 2
	assert.Equal(t, 75.0, stats.SpeedTestResults.FastestSpeedMbps)
	assert.Equal(t, 50.5, stats.SpeedTestResults.SlowestSpeedMbps)

	// Test failed speed test
	collector.RecordSpeedTestResult(0.0, false)

	stats = collector.GetStats()
	assert.Equal(t, 3, stats.SpeedTestResults.TotalTests)
	assert.Equal(t, 2, stats.SpeedTestResults.SuccessfulTests)
	assert.Equal(t, 1, stats.SpeedTestResults.FailedTests)
	assert.InDelta(t, 66.67, stats.SpeedTestResults.SuccessRate, 0.01) // 2/3 * 100
	assert.Equal(t, 62.75, stats.SpeedTestResults.AverageSpeedMbps)    // Average should not change
	assert.Equal(t, 75.0, stats.SpeedTestResults.FastestSpeedMbps)
	assert.Equal(t, 50.5, stats.SpeedTestResults.SlowestSpeedMbps)

	// Test speed test that's slower than current slowest
	collector.RecordSpeedTestResult(25.0, true)

	stats = collector.GetStats()
	assert.Equal(t, 4, stats.SpeedTestResults.TotalTests)
	assert.Equal(t, 3, stats.SpeedTestResults.SuccessfulTests)
	assert.Equal(t, 1, stats.SpeedTestResults.FailedTests)
	assert.Equal(t, 75.0, stats.SpeedTestResults.SuccessRate)               // 3/4 * 100
	assert.InDelta(t, 50.17, stats.SpeedTestResults.AverageSpeedMbps, 0.01) // (50.5 + 75.0 + 25.0) / 3
	assert.Equal(t, 75.0, stats.SpeedTestResults.FastestSpeedMbps)
	assert.Equal(t, 25.0, stats.SpeedTestResults.SlowestSpeedMbps)
}
