// Package web provides HTTP API server functionality for monitoring and managing
// VPN connections, health status, and related services through REST endpoints.
package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"openxvpn/pkg/config"
	"openxvpn/pkg/health"
	"openxvpn/pkg/ipdetector"
	"openxvpn/pkg/vpn"
)

//go:embed templates/index.html
var indexHTML string

// Server provides HTTP API endpoints for monitoring and managing
// the VPN connection, health status, and related services.
type Server struct {
	// config holds the application configuration
	config *config.Config

	// vpnManager provides VPN management operations
	vpnManager vpn.Manager

	// monitor provides health monitoring functionality
	monitor health.Monitor

	// logger provides structured logging
	logger *slog.Logger

	// server is the underlying HTTP server instance
	server *http.Server

	// ipDetector provides IP detection and geolocation services
	ipDetector ipdetector.Detector
}

// StatusResponse represents the unified status information returned by API endpoints.
// It combines VPN status, network information, health metrics, and reliability data.
type StatusResponse struct {
	// Status indicates the overall VPN connection state
	Status string `json:"status"`

	// Uptime shows how long the VPN has been running
	Uptime string `json:"uptime"`

	// Server identifies the currently connected VPN server
	Server string `json:"server"`

	// Network contains IP address information
	Network Network `json:"network"`

	// Health contains health monitoring statistics
	Health Health `json:"health"`

	// Reliability contains restart and failure information
	Reliability Reliability `json:"reliability"`

	// Timestamp indicates when this status was generated
	Timestamp time.Time `json:"timestamp"`
}

// Network represents network-related status information including IP addresses.
type Network struct {
	// CurrentIP is the currently detected public IP address
	CurrentIP string `json:"current_ip"`

	// OriginalIP is the public IP address before VPN connection
	OriginalIP string `json:"original_ip"`
}

// Health represents health monitoring status and metrics.
type Health struct {
	// LastCheck is the timestamp of the most recent health check
	LastCheck time.Time `json:"last_check"`

	// Status indicates the health state ("healthy", "unhealthy", "degraded")
	Status string `json:"status"`

	// ConsecutiveFails tracks consecutive health check failures
	ConsecutiveFails int `json:"consecutive_fails"`

	// SuccessRate is the percentage of successful health checks (0-100)
	SuccessRate float64 `json:"success_rate"`
}

// Reliability represents VPN restart and reliability metrics.
type Reliability struct {
	// RestartCount tracks how many times the VPN has been restarted
	RestartCount int `json:"restart_count"`

	// LastRestart is the timestamp of the most recent restart
	LastRestart time.Time `json:"last_restart,omitempty"`
}

// NewServer creates a new HTTP server instance with the provided dependencies.
// The server provides REST API endpoints for VPN management and monitoring.
func NewServer(cfg *config.Config, vpnMgr vpn.Manager, monitor health.Monitor, logger *slog.Logger) *Server {
	return &Server{
		config:     cfg,
		vpnManager: vpnMgr,
		monitor:    monitor,
		logger:     logger,
		ipDetector: vpnMgr.GetIPDetector(), // Reuse the VPN manager's IP detector
	}
}

// Start initializes and starts the HTTP server with all configured endpoints.
// It sets up REST API routes for VPN management, health monitoring, and IP detection,
// then starts the server in the background. The server gracefully shuts down when the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Health endpoint for Docker
	mux.HandleFunc("/health", s.handleHealth)

	// Status endpoints
	mux.HandleFunc("/status", s.handleLegacyStatus)
	mux.HandleFunc("/api/v1/status", s.handleStatus)

	// Management endpoints
	mux.HandleFunc("/api/v1/reconnect", s.handleReconnect)
	mux.HandleFunc("/api/v1/healthcheck", s.handleForceHealthCheck)

	// IP geolocation endpoints
	mux.HandleFunc("/api/v1/ipinfo", s.handleIPInfo)
	mux.HandleFunc("/ip2location.json", s.handleIP2LocationCompat) // Shell script compatibility
	mux.HandleFunc("/api/v1/cache/stats", s.handleCacheStats)
	mux.HandleFunc("/api/v1/cache/clear", s.handleCacheClear)

	// Static content (for compatibility with existing web interface)
	mux.HandleFunc("/", s.handleIndex)

	s.server = &http.Server{
		Addr:    s.config.API.Listen,
		Handler: s.withLogging(s.withAuth(mux)),
	}

	s.logger.Info("Starting web server", "listen", s.config.API.Listen)

	go func() {
		<-ctx.Done()
		s.logger.Info("Shutting down web server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()

	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to start web server: %w", err)
	}

	return nil
}

// handleHealth provides a Docker-compatible health check endpoint.
// It returns HTTP 200 when both VPN is connected and health monitoring reports healthy status,
// otherwise returns HTTP 503 with a descriptive error message.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vpnStatus := s.vpnManager.GetStatus()
	healthStatus := s.monitor.GetStatus()

	// Docker health check: return 200 if VPN is connected and health is good
	if vpnStatus.State == "connected" && healthStatus.Status == "healthy" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(http.StatusText(http.StatusOK)))
	} else {
		http.Error(w, fmt.Sprintf("VPN: %s, Health: %s", vpnStatus.State, healthStatus.Status),
			http.StatusServiceUnavailable)
	}
}

// handleStatus provides comprehensive VPN status information via REST API.
// It returns a JSON response containing VPN state, network details, health metrics,
// and reliability statistics for monitoring and dashboard applications.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vpnStatus := s.vpnManager.GetStatus()
	healthStatus := s.monitor.GetStatus()

	response := StatusResponse{
		Status:    vpnStatus.State,
		Uptime:    vpnStatus.Uptime,
		Server:    vpnStatus.Server,
		Timestamp: time.Now(),
		Network: Network{
			CurrentIP:  vpnStatus.CurrentIP,
			OriginalIP: vpnStatus.OriginalIP,
		},
		Health: Health{
			LastCheck:        healthStatus.LastCheck,
			Status:           healthStatus.Status,
			ConsecutiveFails: healthStatus.ConsecutiveFails,
			SuccessRate:      healthStatus.SuccessRate,
		},
		Reliability: Reliability{
			RestartCount: healthStatus.RestartCount,
			LastRestart:  healthStatus.LastRestart,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// handleLegacyStatus provides backward compatibility with shell script web interface.
// It returns a simplified JSON response with basic status information in the format
// expected by existing monitoring scripts and legacy web interfaces.
func (s *Server) handleLegacyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vpnStatus := s.vpnManager.GetStatus()
	healthStatus := s.monitor.GetStatus()

	// Legacy format for compatibility with shell script web interface
	legacyResponse := map[string]interface{}{
		"status": healthStatus.Status,
		"ip":     vpnStatus.CurrentIP,
		"at":     time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(legacyResponse)
}

// handleReconnect initiates a VPN reconnection process via REST API.
// It accepts an optional "server" form parameter to change the VPN server configuration
// and performs the reconnection asynchronously, returning an immediate response.
func (s *Server) handleReconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_ = r.ParseForm()
	newServerGlob := r.Form.Get("server")
	if newServerGlob > "" {
		s.config.VPN.Server = newServerGlob
		s.logger.Info("Manual reconnect requested with new server", "server", newServerGlob)
	} else {
		s.logger.Info("Manual reconnect requested")
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if err := s.vpnManager.Restart(ctx); err != nil {
			s.logger.Error("Failed to restart VPN", "error", err)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "reconnecting",
		"message": "VPN reconnection initiated",
	})
}

// handleForceHealthCheck triggers an immediate health check via REST API.
// It bypasses the normal health check schedule and returns the current health status
// after performing a fresh connectivity and IP verification test.
func (s *Server) handleForceHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.logger.Info("Manual health check requested")

	status := s.monitor.ForceCheck()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

// handleIPInfo provides detailed IP address information including geolocation data.
// It returns the current public IP address along with geographic location, ISP details,
// and other metadata obtained from the IP2Location service.
func (s *Server) handleIPInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get current IP info with geolocation
	ipInfo, err := s.ipDetector.GetCurrentIPInfo(ctx)
	if err != nil {
		s.logger.Error("Failed to get IP info", "error", err)
		http.Error(w, "Failed to get IP information", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ipInfo)
}

// handleIP2LocationCompat provides raw IP2Location API compatibility for shell scripts.
// It returns unprocessed JSON data from the IP2Location service, maintaining compatibility
// with existing shell-based monitoring scripts that expect the original API format.
func (s *Server) handleIP2LocationCompat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get current IP first
	currentIP, err := s.ipDetector.GetCurrentIP(ctx)
	if err != nil {
		s.logger.Error("Failed to get current IP", "error", err)
		http.Error(w, "Failed to get current IP", http.StatusInternalServerError)
		return
	}

	// Get raw IP2Location data for shell script compatibility
	rawData, err := s.ipDetector.GetRawIP2LocationData(ctx, currentIP)
	if err != nil {
		s.logger.Error("Failed to get IP2Location data", "error", err)
		// Return basic IP info if geolocation fails
		basicResponse := map[string]interface{}{
			"ip":    currentIP,
			"error": "Geolocation service unavailable",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(basicResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rawData)
}

// handleCacheStats provides statistics about the IP detector's internal cache.
// It returns metrics including cache hit rates, entry counts, and performance data
// for monitoring the effectiveness of IP geolocation caching.
func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := s.ipDetector.GetCacheStats()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// handleCacheClear clears the IP detector's internal cache via REST API.
// This forces fresh lookups for subsequent IP geolocation requests and can be useful
// for troubleshooting or when cached data becomes stale or incorrect.
func (s *Server) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.logger.Info("Cache clear requested")
	s.ipDetector.ClearCache()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Cache cleared successfully",
	})
}

// StatusData contains the data passed to the HTML template
type StatusData struct {
	Status       string
	StatusClass  string
	CurrentIP    string
	OriginalIP   string
	Server       string
	Uptime       string
	HealthStatus string
	SuccessRate  float64
	LastUpdated  string
}

// handleIndex serves the main HTML status page for web browser access.
// It provides a user-friendly dashboard displaying VPN connection status, IP addresses,
// health metrics, and automatically refreshes every 30 seconds for real-time monitoring.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Get status information
	vpnStatus := s.vpnManager.GetStatus()
	healthStatus := s.monitor.GetStatus()

	// Determine status class for CSS styling
	statusClass := "error"
	switch strings.ToLower(vpnStatus.State) {
	case "connected":
		statusClass = "ok"
	case "connecting":
		statusClass = "connecting"
	}

	// Prepare template data
	data := StatusData{
		Status:       strings.ToUpper(vpnStatus.State),
		StatusClass:  statusClass,
		CurrentIP:    vpnStatus.CurrentIP,
		OriginalIP:   vpnStatus.OriginalIP,
		Server:       vpnStatus.Server,
		Uptime:       vpnStatus.Uptime,
		HealthStatus: healthStatus.Status,
		SuccessRate:  healthStatus.SuccessRate,
		LastUpdated:  time.Now().Format("2006-01-02 15:04:05"),
	}

	// Parse and execute template
	tmpl, err := template.New("index").Parse(indexHTML)
	if err != nil {
		s.logger.Error("Failed to parse template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		s.logger.Error("Failed to execute template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// withAuth provides authentication middleware for API endpoints.
// Health-related endpoints are exempt from authentication to allow
// monitoring systems and Docker health checks to function without tokens.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication if disabled
		if !s.config.API.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Allow health endpoints without authentication
		healthEndpoints := []string{
			"/health",
			"/api/v1/status",
			"/status",
			"/api/v1/healthcheck",
		}

		for _, endpoint := range healthEndpoints {
			if r.URL.Path == endpoint {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Check for API token in Authorization header for other endpoints
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		if token != s.config.API.Auth.Token {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// withLogging provides HTTP request logging middleware for all endpoints.
// It logs request details including method, path, duration, and remote address
// for debugging and monitoring purposes using structured logging.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		s.logger.Debug("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start),
			"remote_addr", r.RemoteAddr,
		)
	})
}
