package ipdetector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IPInfo represents comprehensive information about an IP address, including
// geolocation data obtained from external IP geolocation services.
// The Timestamp field indicates when this information was retrieved.
type IPInfo struct {
	IP        string    `json:"ip"`
	Country   string    `json:"country,omitempty"`
	Region    string    `json:"region,omitempty"`
	City      string    `json:"city,omitempty"`
	ISP       string    `json:"isp,omitempty"`
	Latitude  float64   `json:"latitude,omitempty"`
	Longitude float64   `json:"longitude,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// IP2LocationResponse represents the complete response structure from ip2location.io API.
// This includes detailed geolocation and ISP information. The API is a premium service
// that provides more comprehensive data than free alternatives.
type IP2LocationResponse struct {
	IP              string  `json:"ip"`
	CountryCode     string  `json:"country_code"`
	CountryName     string  `json:"country_name"`
	RegionName      string  `json:"region_name"`
	CityName        string  `json:"city_name"`
	Latitude        float64 `json:"latitude"`
	Longitude       float64 `json:"longitude"`
	ZipCode         string  `json:"zip_code"`
	TimeZone        string  `json:"time_zone"`
	ASN             string  `json:"asn"`
	AS              string  `json:"as"`
	ISP             string  `json:"isp"`
	Domain          string  `json:"domain"`
	NetSpeed        string  `json:"net_speed"`
	IDDCode         string  `json:"idd_code"`
	AreaCode        string  `json:"area_code"`
	WeatherCode     string  `json:"weather_station_code"`
	WeatherName     string  `json:"weather_station_name"`
	MCC             string  `json:"mcc"`
	MNC             string  `json:"mnc"`
	MobileBrand     string  `json:"mobile_brand"`
	Elevation       int     `json:"elevation"`
	UsageType       string  `json:"usage_type"`
	AddressType     string  `json:"address_type"`
	Category        string  `json:"category"`
	CategoryName    string  `json:"category_name"`
	CreditsConsumed int     `json:"credits_consumed"`
}

// IfconfigResponse represents the response structure from ifconfig.co/json API.
// This service is used as a fallback when IP2Location is unavailable or fails.
// It provides basic geolocation information without requiring an API key.
type IfconfigResponse struct {
	IP         string  `json:"ip"`
	IPDecimal  int64   `json:"ip_decimal"`
	Country    string  `json:"country"`
	CountryEU  bool    `json:"country_eu"`
	CountryISO string  `json:"country_iso"`
	City       string  `json:"city"`
	Hostname   string  `json:"hostname"`
	Latitude   float64 `json:"latitude"`
	Longitude  float64 `json:"longitude"`
	ASN        string  `json:"asn"`
	ASNOrg     string  `json:"asn_org"`
	UserAgent  string  `json:"user_agent"`
	Port       int     `json:"port"`
	Language   string  `json:"language"`
	Encoding   string  `json:"encoding"`
	MimeType   string  `json:"mime"`
	Via        string  `json:"via"`
	Forwarded  string  `json:"forwarded"`
}

// CachedIPInfo wraps IPInfo with expiration metadata for cache management.
// This allows efficient caching of geolocation data to reduce API calls and improve performance.
type CachedIPInfo struct {
	Info      *IPInfo
	ExpiresAt time.Time
}

var _ Detector = (*DetectorImpl)(nil)

// Cache constants for IP detection
const (
	// currentIPCacheKey is the cache key used for storing the current IP address
	currentIPCacheKey = "_current_ip"

	// currentIPCacheDuration is how long to cache successful IP detection results
	// This reduces inconsistency from concurrent requests to different services
	currentIPCacheDuration = 30 * time.Second
)

// Detector defines the interface for IP address detection and geolocation services.
// It provides methods for obtaining current external IP, detailed geolocation info,
// change detection, and cache management. Implementations should be thread-safe.
type Detector interface {
	GetCurrentIP(ctx context.Context) (string, error)
	GetIPInfo(ctx context.Context, ip string) (*IPInfo, error)
	GetCurrentIPInfo(ctx context.Context) (*IPInfo, error)
	CheckIPChange(ctx context.Context, previousIP string) (bool, string, error)
	HealthCheck(ctx context.Context) error
	GetRawIP2LocationData(ctx context.Context, ip string) ([]byte, error)
	GetCacheStats() map[string]any
	ClearCache()
}

// DetectorImpl provides IP detection and geolocation services with intelligent fallback mechanisms.
// It primarily uses IP2Location.io API (when configured) with ifconfig.co as a fallback.
// Features include:
//   - Automatic fallback between multiple geolocation services
//   - Intelligent caching with configurable TTL to minimize API calls
//   - Thread-safe operations with proper mutex protection
//   - Graceful degradation when services are unavailable
type DetectorImpl struct {
	timeout        time.Duration
	ip2LocationKey string
	logger         *slog.Logger
	httpClient     *http.Client

	// Cache for IP geolocation data
	cache    map[string]*CachedIPInfo
	cacheMu  sync.RWMutex
	cacheTTL time.Duration
}

// Config holds configuration parameters for the IP detector.
// All fields are optional with sensible defaults applied during construction.
type Config struct {
	Timeout        time.Duration
	IP2LocationKey string
	Logger         *slog.Logger
	CacheTTL       time.Duration // How long to cache IP geolocation data
}

// NewDetector creates a new IP detector with the provided configuration.
// Default values are applied for zero-value fields:
//   - Timeout: 5 seconds for HTTP requests
//   - CacheTTL: 24 hours for IP2Location data, 1 hour for ifconfig.co
//   - Logger: slog.Default() if not provided
//
// Returns a fully initialized detector ready for use.
func NewDetector(cfg Config) *DetectorImpl {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second // Default to 5 seconds for HTTP calls
	}

	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 24 * time.Hour // Default cache TTL of 24 hours
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &DetectorImpl{
		timeout:        cfg.Timeout,
		ip2LocationKey: cfg.IP2LocationKey,
		logger:         cfg.Logger,
		cache:          make(map[string]*CachedIPInfo),
		cacheTTL:       cfg.CacheTTL,
		httpClient: &http.Client{
			Timeout: cfg.Timeout, // Use 5-second timeout for all HTTP calls
		},
	}
}

// GetCurrentIP retrieves the current external IP address using multiple sources.
// This method randomly selects from available IP detection services and implements
// failover logic to try different sources if one fails.
// Supported sources: ifconfig.co, wtfismyip.com/text, icanhazip.com
// Returns an error if all sources fail.
func (d *DetectorImpl) GetCurrentIP(ctx context.Context) (string, error) {
	d.logger.Debug("Fetching current IP address")

	// Check cache first for recent successful IP detection
	if cached := d.getCachedIPInfo(currentIPCacheKey); cached != nil {
		d.logger.Debug("Using cached current IP", "ip", cached.IP)
		return cached.IP, nil
	}

	// Define available IP detection sources
	sources := []string{
		"https://ifconfig.co",
		"https://wtfismyip.com/text",
		"https://icanhazip.com/",
		"https://ip.me/",
	}

	// Create a shuffled copy of sources for random selection
	shuffledSources := make([]string, len(sources))
	copy(shuffledSources, sources)
	rand.Shuffle(len(shuffledSources), func(i, j int) {
		shuffledSources[i], shuffledSources[j] = shuffledSources[j], shuffledSources[i]
	})

	var lastErr error

	// Try each source until one succeeds
	for _, source := range shuffledSources {
		d.logger.Debug("Trying IP source", "source", source)

		ip, err := d.fetchIPFromSource(ctx, source)
		if err != nil {
			d.logger.Debug("IP source failed, trying next", "source", source, "error", err)
			lastErr = err
			continue
		}

		d.logger.Debug("Current IP detected", "ip", ip, "source", source)

		// Cache successful IP detection to reduce inconsistency
		ipInfo := &IPInfo{
			IP:        ip,
			Timestamp: time.Now(),
		}
		d.setCachedIPInfo(currentIPCacheKey, ipInfo, currentIPCacheDuration)

		return ip, nil
	}

	return "", fmt.Errorf("all IP sources failed, last error: %w", lastErr)
}

// fetchIPFromSource fetches IP from a specific source URL
func (d *DetectorImpl) fetchIPFromSource(ctx context.Context, sourceURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", sourceURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch IP: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, sourceURL)
	}

	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	ip := strings.TrimSpace(string(ipBytes))
	if ip == "" {
		return "", fmt.Errorf("empty IP response from %s", sourceURL)
	}

	// Validate that response looks like an IP address, not HTML
	if strings.Contains(strings.ToLower(ip), "<html") ||
		strings.Contains(strings.ToLower(ip), "<!doctype") ||
		strings.Contains(ip, "<") {
		return "", fmt.Errorf("received HTML response instead of IP from %s", sourceURL)
	}

	// Basic IP address validation (IPv4 or IPv6)
	if !d.isValidIPAddress(ip) {
		return "", fmt.Errorf("invalid IP address format: %s from %s", ip, sourceURL)
	}

	return ip, nil
}

// isValidIPAddress validates that the string is a valid IPv4 or IPv6 address
func (d *DetectorImpl) isValidIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// GetIPInfo retrieves comprehensive geolocation information for the specified IP address.
// The method implements a multi-tier fallback strategy:
//  1. Check local cache first (if not expired)
//  2. Use IP2Location.io API (if API key is configured)
//  3. Fallback to ifconfig.co/json (free service with limited data)
//  4. Final fallback: return basic IP info only
//
// Results are cached with appropriate TTL based on the data source quality.
func (d *DetectorImpl) GetIPInfo(ctx context.Context, ip string) (*IPInfo, error) {
	// Check if IP is valid
	if ip == "" {
		return nil, fmt.Errorf("empty IP address")
	}

	// Check cache first to avoid unnecessary API calls
	if cached := d.getCachedIPInfo(ip); cached != nil {
		d.logger.Debug("Using cached IP geolocation info", "ip", ip)
		return cached, nil
	}

	// If no IP2Location key, skip premium service and use free fallback immediately
	if d.ip2LocationKey == "" {
		d.logger.Debug("No IP2Location key configured, using ifconfig.co/json fallback", "ip", ip)
		return d.getInfoFromIfconfig(ctx, ip)
	}

	d.logger.Debug("Fetching IP geolocation info from IP2Location API", "ip", ip)

	// Define fallback closure to reduce code duplication
	fallbackToIfconfig := func(logMsg string, logArgs ...any) (*IPInfo, error) {
		d.logger.Warn(logMsg, logArgs...)
		return d.getInfoFromIfconfig(ctx, ip)
	}

	url := fmt.Sprintf("https://api.ip2location.io/?key=%s&ip=%s", d.ip2LocationKey, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		// Network errors or service unavailability - try free alternative
		return fallbackToIfconfig("IP2Location API failed, trying ifconfig.co/json fallback", "error", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// API errors (rate limiting, invalid key, etc.) - fallback to free service
		return fallbackToIfconfig("IP2Location API returned non-200 status, trying ifconfig.co/json fallback",
			"status", resp.StatusCode)
	}

	// Validate response is JSON before attempting to decode
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "application/json") {
		return fallbackToIfconfig("IP2Location API returned non-JSON response, trying ifconfig.co/json fallback",
			"content_type", contentType)
	}

	// Read response body to validate JSON format
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fallbackToIfconfig("Failed to read IP2Location response body, trying ifconfig.co/json fallback", "error", err)
	}

	var ip2LocResp IP2LocationResponse
	if err := json.Unmarshal(bodyBytes, &ip2LocResp); err != nil {
		// JSON parsing errors - response format may have changed
		return fallbackToIfconfig("Failed to decode IP2Location response, trying ifconfig.co/json fallback", "error", err)
	}

	info := &IPInfo{
		IP:        ip2LocResp.IP,
		Country:   ip2LocResp.CountryName,
		Region:    ip2LocResp.RegionName,
		City:      ip2LocResp.CityName,
		ISP:       ip2LocResp.ISP,
		Latitude:  ip2LocResp.Latitude,
		Longitude: ip2LocResp.Longitude,
		Timestamp: time.Now(),
	}

	// Cache the result with full TTL since IP2Location is premium/reliable
	d.setCachedIPInfo(ip, info, d.cacheTTL)

	d.logger.Debug("IP geolocation info retrieved from IP2Location and cached",
		"ip", info.IP,
		"country", info.Country,
		"city", info.City,
		"isp", info.ISP,
		"cache_ttl", d.cacheTTL)

	return info, nil
}

// GetCurrentIPInfo combines GetCurrentIP() and GetIPInfo() for convenience.
// First retrieves the current external IP address, then fetches geolocation data.
// If geolocation fails, returns basic IP information with current timestamp.
// This method ensures you always get some information, even if geolocation services fail.
func (d *DetectorImpl) GetCurrentIPInfo(ctx context.Context) (*IPInfo, error) {
	ip, err := d.GetCurrentIP(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current IP: %w", err)
	}

	info, err := d.GetIPInfo(ctx, ip)
	if err != nil {
		// If geolocation fails, still return basic IP info to avoid total failure
		// This ensures callers always get at least the IP address
		d.logger.Warn("Failed to get IP geolocation info", "error", err)
		return &IPInfo{
			IP:        ip,
			Timestamp: time.Now(),
		}, nil
	}

	return info, nil
}

// CheckIPChange compares the current external IP address with a previously known IP.
// Returns:
//   - bool: whether the IP has changed
//   - string: the current IP address
//   - error: any error that occurred during IP detection
//
// This method is useful for VPN monitoring to detect when the external IP changes.
func (d *DetectorImpl) CheckIPChange(ctx context.Context, previousIP string) (bool, string, error) {
	currentIP, err := d.GetCurrentIP(ctx)
	if err != nil {
		return false, "", err
	}

	changed := currentIP != previousIP

	d.logger.Debug("IP change check",
		"previous_ip", previousIP,
		"current_ip", currentIP,
		"changed", changed)

	return changed, currentIP, nil
}

// HealthCheck performs a basic connectivity test by attempting to retrieve the current IP.
// This method is used by health monitoring systems to verify that external IP detection
// is functional. Returns an error if the basic IP detection service is unavailable.
func (d *DetectorImpl) HealthCheck(ctx context.Context) error {
	_, err := d.GetCurrentIP(ctx)
	if err != nil {
		return fmt.Errorf("IP detection health check failed: %w", err)
	}
	return nil
}

// getInfoFromIfconfig retrieves geolocation information from ifconfig.co/json service.
// This method serves as the fallback when IP2Location.io is unavailable or fails.
// It implements multiple fallback levels:
//  1. Parse full JSON response from ifconfig.co/json
//  2. If that fails, return basic IP-only information
//
// Results are cached with a shorter TTL (1 hour) since it's a free service with less reliability.
func (d *DetectorImpl) getInfoFromIfconfig(ctx context.Context, ip string) (*IPInfo, error) {
	d.logger.Debug("Fetching IP geolocation info from ifconfig.co/json", "ip", ip)

	// Define fallback closure for basic IP info to reduce code duplication
	returnBasicInfo := func(logMsg string, logArgs ...any) (*IPInfo, error) {
		d.logger.Warn(logMsg, logArgs...)
		info := &IPInfo{
			IP:        ip,
			Timestamp: time.Now(),
		}
		d.setCachedIPInfo(ip, info, time.Minute) // Short cache for basic info
		return info, nil
	}

	// Use ifconfig.co/json to get basic geolocation data
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ifconfig.co/json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ifconfig.co request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		// Final fallback: return basic IP info only when all services fail
		// Cache briefly in case network issues are temporary
		return returnBasicInfo("ifconfig.co/json also failed, returning basic IP info", "error", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return returnBasicInfo("ifconfig.co/json returned non-200 status, returning basic IP info",
			"status", resp.StatusCode)
	}

	// Validate response is JSON before attempting to decode
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "application/json") {
		return returnBasicInfo("ifconfig.co/json returned non-JSON response, returning basic IP info",
			"content_type", contentType)
	}

	// Read response body to validate JSON format
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return returnBasicInfo("Failed to read ifconfig.co response body, returning basic IP info", "error", err)
	}

	// Try to unmarshal directly - skip json.Valid() as it seems to have issues
	var ifconfigResp IfconfigResponse
	if err := json.Unmarshal(bodyBytes, &ifconfigResp); err != nil {
		return returnBasicInfo("Failed to decode ifconfig.co response, returning basic IP info", "error", err)
	}

	info := &IPInfo{
		IP:        ifconfigResp.IP,
		Country:   ifconfigResp.Country,
		City:      ifconfigResp.City,
		ISP:       ifconfigResp.ASNOrg, // Use ASN organization as ISP approximation
		Latitude:  ifconfigResp.Latitude,
		Longitude: ifconfigResp.Longitude,
		Timestamp: time.Now(),
	}

	if ifconfigResp.IP == "" {
		// Service returned empty IP - use the requested IP as fallback
		info.IP = ip
		return info, nil
	}

	// Cache the result with shorter TTL for free service (less reliable than premium)
	cacheTTL := time.Hour // 1 hour for ifconfig.co data vs 24 hours for IP2Location
	d.setCachedIPInfo(ip, info, cacheTTL)

	d.logger.Debug("IP geolocation info retrieved from ifconfig.co and cached",
		"ip", info.IP,
		"country", info.Country,
		"city", info.City,
		"isp", info.ISP,
		"cache_ttl", cacheTTL)

	return info, nil
}

// GetRawIP2LocationData returns the complete, unprocessed JSON response from IP2Location.io API.
// This method is primarily used by web interfaces that need to display all available
// geolocation fields beyond what IPInfo contains (weather, mobile carrier, etc.).
// Requires IP2Location API key to be configured, otherwise returns an error.
func (d *DetectorImpl) GetRawIP2LocationData(ctx context.Context, ip string) ([]byte, error) {
	if d.ip2LocationKey == "" {
		return nil, fmt.Errorf("IP2Location API key not configured")
	}

	url := fmt.Sprintf("https://api.ip2location.io/?key=%s&ip=%s", d.ip2LocationKey, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IP info: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from ip2location.io", resp.StatusCode)
	}

	// Validate response is JSON before returning
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "application/json") {
		return nil, fmt.Errorf("ip2location.io returned non-JSON response: %s", contentType)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Skip json.Valid() check - if it's not valid JSON, the caller will handle it

	return data, nil
}

// getCachedIPInfo retrieves IP information from the local cache if available and not expired.
// Returns nil if no cache entry exists or if the entry has expired.
// This method uses read locks for thread safety and doesn't perform cache cleanup
// to avoid lock upgrades. Expired entries are cleaned up opportunistically during writes.
func (d *DetectorImpl) getCachedIPInfo(ip string) *IPInfo {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()

	cached, exists := d.cache[ip]
	if !exists {
		return nil
	}

	// Check if cache entry has expired
	if time.Now().After(cached.ExpiresAt) {
		// Don't delete here to avoid upgrading read lock to write lock
		// Expired entries will be cleaned up opportunistically during writes
		return nil
	}

	return cached.Info
}

// setCachedIPInfo stores IP geolocation information in the local cache with the specified TTL.
// The method also performs opportunistic cleanup of expired entries (up to 10) to prevent
// unbounded cache growth. Cleanup is limited to avoid blocking other operations.
// Thread-safe operation using write locks.
func (d *DetectorImpl) setCachedIPInfo(ip string, info *IPInfo, ttl time.Duration) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	d.cache[ip] = &CachedIPInfo{
		Info:      info,
		ExpiresAt: time.Now().Add(ttl),
	}

	// Opportunistic cleanup of expired entries to prevent unbounded growth
	// Limited to 10 entries to avoid long-running operations that block other cache access
	d.cleanupExpiredEntries(10)
}

// cleanupExpiredEntries removes up to maxCleanup expired cache entries.
// This method should only be called while holding the cache write lock.
// Limited cleanup prevents long-running operations that could block other cache access.
// Logs the number of entries cleaned for observability.
func (d *DetectorImpl) cleanupExpiredEntries(maxCleanup int) {
	now := time.Now()
	cleaned := 0

	for ip, cached := range d.cache {
		if cleaned >= maxCleanup {
			break
		}

		if now.After(cached.ExpiresAt) {
			delete(d.cache, ip)
			cleaned++
		}
	}

	if cleaned > 0 {
		d.logger.Debug("Cleaned up expired cache entries", "count", cleaned)
	}
}

// ClearCache removes all cached IP geolocation information.
// This method is useful for testing or when cache invalidation is needed.
// The operation is atomic and thread-safe. Logs the number of entries removed.
func (d *DetectorImpl) ClearCache() {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	entryCount := len(d.cache)
	d.cache = make(map[string]*CachedIPInfo)

	d.logger.Debug("Cache cleared", "entries_removed", entryCount)
}

// GetCacheStats returns comprehensive cache statistics for monitoring and debugging.
// Provides real-time information about cache health including:
//   - total_entries: total number of cached items
//   - expired_entries: number of expired but not yet cleaned entries
//   - valid_entries: number of currently valid cached items
//   - cache_ttl: configured cache time-to-live duration
//
// Thread-safe operation using read locks.
func (d *DetectorImpl) GetCacheStats() map[string]any {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()

	now := time.Now()
	total := len(d.cache)
	expired := 0

	for _, cached := range d.cache {
		if now.After(cached.ExpiresAt) {
			expired++
		}
	}

	return map[string]interface{}{
		"total_entries":   total,
		"expired_entries": expired,
		"valid_entries":   total - expired,
		"cache_ttl":       d.cacheTTL.String(),
	}
}
