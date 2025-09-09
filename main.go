package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"openxvpn/pkg/config"
	"openxvpn/pkg/health"
	"openxvpn/pkg/logging"
	"openxvpn/pkg/vpn"
	"openxvpn/pkg/web"
)

type Application struct {
	config     *config.Config
	logger     *slog.Logger
	vpnManager vpn.Manager
	monitor    health.Monitor
	webServer  *web.Server
	ctx        context.Context
	cancel     context.CancelFunc
}

func main() {
	app, err := setupApplication()
	if err != nil {
		slog.Error("Failed to setup application", "error", err)
		os.Exit(1)
	}

	if err := app.run(); err != nil {
		app.logger.Error("Application failed", "error", err)
		os.Exit(1)
	}
}

func setupApplication() (*Application, error) {
	// Setup structured logging with credential redaction
	baseHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	redactorHandler := logging.NewRedactorHandler(baseHandler)
	logger := slog.New(redactorHandler)
	slog.SetDefault(logger)

	logger.Info("Starting OpenXVPN Go implementation")

	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		return nil, err
	}

	// Update redactor with secrets from config
	sensitiveStrings := []string{}
	if cfg.VPN.Username != "" {
		sensitiveStrings = append(sensitiveStrings, cfg.VPN.Username)
	}
	if cfg.VPN.Password != "" {
		sensitiveStrings = append(sensitiveStrings, cfg.VPN.Password)
	}
	if cfg.Network.IP2LocationKey != "" {
		sensitiveStrings = append(sensitiveStrings, cfg.Network.IP2LocationKey)
	}
	if cfg.API.Auth.Token != "" {
		sensitiveStrings = append(sensitiveStrings, cfg.API.Auth.Token)
	}
	redactorHandler.UpdateSecrets(sensitiveStrings)

	logger.Info("Configuration loaded",
		"provider", cfg.VPN.Provider,
		"config_path", cfg.VPN.ConfigPath,
		"health_interval", cfg.Health.CheckInterval)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Create components
	vpnManager := vpn.NewManager(cfg, logger.With("component", "vpn"))
	monitor := health.NewMonitor(cfg, vpnManager, logger.With("component", "health"))
	webServer := web.NewServer(cfg, vpnManager, monitor, logger.With("component", "web"))

	app := &Application{
		config:     cfg,
		logger:     logger,
		vpnManager: vpnManager,
		monitor:    monitor,
		webServer:  webServer,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Setup recovery logic
	app.setupRecoveryCallbacks()

	return app, nil
}

func (app *Application) setupRecoveryCallbacks() {
	app.monitor.AddFailureCallback(func(status health.Status, shouldRestart bool, shouldExitContainer bool) error {
		app.logger.Error("Health failure callback triggered",
			"consecutive_fails", status.ConsecutiveFails,
			"threshold", app.config.Health.FailureThreshold)

		if shouldExitContainer && app.config.Recovery.ContainerExit {
			app.logger.Error("Maximum restarts reached, exiting container",
				"restart_count", status.RestartCount,
				"max_retries", app.config.Recovery.MaxRetries)
			app.cancel()
			return nil
		}

		if shouldRestart {
			// Record restart attempt
			app.monitor.HandleRestart()

			// Try to restart VPN
			app.logger.Info("Attempting VPN restart due to health failures")
			restartCtx, restartCancel := context.WithTimeout(app.ctx, 15*time.Second)
			defer restartCancel()

			return app.vpnManager.Restart(restartCtx)
		}

		return nil
	})
}

func (app *Application) run() error {
	defer app.cancel()

	// Start all components
	var wg sync.WaitGroup
	if err := app.startComponents(&wg); err != nil {
		return fmt.Errorf("failed to start application components: %w", err)
	}

	// Wait for shutdown signal
	app.waitForShutdown()

	// Graceful shutdown
	app.shutdown(&wg)

	return nil
}

// waitForVPNReady waits for the VPN to reach a stable state before proceeding.
// This replaces the fixed sleep with proper synchronization based on VPN status.
func (app *Application) waitForVPNReady() {
	app.logger.Info("Waiting for VPN to be ready")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeout := time.After(30 * time.Second)

	for {
		select {
		case <-app.ctx.Done():
			app.logger.Info("Context cancelled while waiting for VPN")
			return
		case <-timeout:
			app.logger.Warn("Timeout waiting for VPN to be ready, proceeding anyway")
			return
		case <-ticker.C:
			status := app.vpnManager.GetStatus()
			if status.State == "connected" || status.State == "connecting" {
				app.logger.Info("VPN is ready", "state", status.State)
				// Give it a moment to stabilize
				time.Sleep(2 * time.Second)
				return
			}
			app.logger.Debug("VPN not ready yet", "state", status.State)
		}
	}
}

func (app *Application) startComponents(wg *sync.WaitGroup) error {
	app.logger.Info("Starting application components")

	// Start VPN manager
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := app.vpnManager.Start(app.ctx); err != nil {
			app.logger.Error("VPN manager failed to start", "error", err)
			app.cancel()
		}
	}()

	// Wait for VPN to be ready before starting health monitor
	app.waitForVPNReady()

	// Start health monitor
	wg.Add(1)
	go func() {
		defer wg.Done()
		app.monitor.Start(app.ctx)
	}()

	// Start web server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := app.webServer.Start(app.ctx); err != nil {
			app.logger.Error("Web server failed to start", "error", err)
			app.cancel()
		}
	}()

	app.logger.Info("All components started successfully")
	return nil
}

func (app *Application) waitForShutdown() {
	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal or context cancellation
	select {
	case sig := <-sigCh:
		app.logger.Info("Received shutdown signal", "signal", sig)
	case <-app.ctx.Done():
		app.logger.Info("Context cancelled, shutting down")
	}
}

// shutdown performs graceful application shutdown by cancelling the context
// and waiting for all goroutines to complete. The health monitor will stop
// automatically when the context is cancelled.
func (app *Application) shutdown(wg *sync.WaitGroup) {
	app.logger.Info("Initiating graceful shutdown")

	// Cancel context to signal all goroutines to stop
	app.cancel()

	// Stop VPN manager (health monitor stops via context cancellation)
	if err := app.vpnManager.Stop(); err != nil {
		app.logger.Error("Error stopping VPN manager", "error", err)
	}

	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		app.logger.Info("Graceful shutdown completed")
	case <-time.After(30 * time.Second):
		app.logger.Warn("Shutdown timeout reached, forcing exit")
	}
}
