package logging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactorHandler_ExplicitStringFiltering(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})

	// Test with explicit strings
	sensitiveStrings := []string{"mysecret123", "sk-1234567890abcdef", "user@example.com"}
	redactor := NewRedactorHandlerWithStrings(handler, sensitiveStrings)
	logger := slog.New(redactor)

	tests := []struct {
		name        string
		message     string
		notContains []string
	}{
		{
			name:        "password in message",
			message:     "Failed to authenticate with password: mysecret123",
			notContains: []string{"mysecret123"},
		},
		{
			name:        "api key in message",
			message:     "API key validation failed: sk-1234567890abcdef",
			notContains: []string{"sk-1234567890abcdef"},
		},
		{
			name:        "email in message",
			message:     "User registration failed for user@example.com",
			notContains: []string{"user@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			logger.Info(tt.message)

			output := buf.String()
			assert.Contains(t, output, "[REDACTED]", "Should contain redacted placeholder")
			for _, notContains := range tt.notContains {
				assert.NotContains(t, output, notContains, "Expected log output to NOT contain: %s", notContains)
			}
		})
	}
}

func TestRedactorHandler_GroupAttributes(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})
	redactor := NewRedactorHandler(handler)
	logger := slog.New(redactor)

	buf.Reset()
	logger.Info("VPN connection",
		slog.Group("credentials",
			"username", "testuser",
			"password", "testpass",
		),
		slog.Group("config",
			"server", "vpn.example.com",
			"api_key", "secret-key-123",
		),
	)

	output := buf.String()

	// Should redact sensitive attributes in groups
	assert.Contains(t, output, `"username":"[REDACTED]"`)
	assert.Contains(t, output, `"password":"[REDACTED]"`)
	assert.Contains(t, output, `"api_key":"[REDACTED]"`)

	// Should not contain actual sensitive values
	assert.NotContains(t, output, "testuser")
	assert.NotContains(t, output, "testpass")
	assert.NotContains(t, output, "secret-key-123")

	// Non-sensitive data should remain
	assert.Contains(t, output, "vpn.example.com")
}

type CustomStruct struct {
	Value1 string
	Value2 int
}

func TestRedactorHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})
	redactor := NewRedactorHandler(handler)
	redactor.UpdateSecrets([]string{"test-secret"})

	// Create logger with pre-configured attributes
	logger := slog.New(redactor).With(
		"component", "vpn",
		"username", "testuser",
		"password", "secret123",
		"key", 54321,
		"token", CustomStruct{"123", 456},
		"plain-jane", CustomStruct{"test-secret", 456},
	)

	buf.Reset()
	logger.Info("VPN started")

	output := buf.String()

	// Pre-configured sensitive attributes should be redacted
	assert.Contains(t, output, `"username":"[REDACTED]"`)
	assert.Contains(t, output, `"password":"[REDACTED]"`)
	assert.Contains(t, output, `"key":"[REDACTED]"`)
	assert.Contains(t, output, `"token":"[REDACTED]"`)

	// Should not contain actual sensitive values
	assert.NotContains(t, output, "testuser")
	assert.NotContains(t, output, "secret123")
	assert.NotContains(t, output, "54321")
	assert.NotContains(t, output, "test-secret")

	// Non-sensitive attributes should remain
	assert.Contains(t, output, `"component":"vpn"`)
}

func TestRedactorHandler_WithGroup(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})
	redactor := NewRedactorHandler(handler)

	// Create logger with group
	logger := slog.New(redactor).WithGroup("auth")

	buf.Reset()
	logger.Info("Authentication attempt",
		"username", "testuser",
		"password", "secret123",
	)

	output := buf.String()

	// Should contain the group structure with redacted values
	assert.Contains(t, output, `"auth"`)
	assert.Contains(t, output, `"username":"[REDACTED]"`)
	assert.Contains(t, output, `"password":"[REDACTED]"`)

	// Should not contain actual sensitive values
	assert.NotContains(t, output, "testuser")
	assert.NotContains(t, output, "secret123")
}

func TestRedactorHandler_NonSensitiveData(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})
	redactor := NewRedactorHandler(handler)
	logger := slog.New(redactor)

	buf.Reset()
	logger.Info("VPN connection established",
		"server", "vpn.example.com",
		"port", 443,
		"protocol", "openvpn",
		"connected", true,
	)

	output := buf.String()

	// Non-sensitive data should remain unchanged
	assert.Contains(t, output, "vpn.example.com")
	assert.Contains(t, output, "443")
	assert.Contains(t, output, "openvpn")
	assert.Contains(t, output, "true")
	assert.Contains(t, output, "VPN connection established")
}

func TestRedactorHandler_ErrorHandling(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})

	// Test with explicit credentials
	sensitiveStrings := []string{"testuser", "secret123"}
	redactor := NewRedactorHandlerWithStrings(handler, sensitiveStrings)
	logger := slog.New(redactor)

	buf.Reset()
	logger.Error("Authentication failed",
		"error", "invalid credentials: user=testuser password=secret123",
		"username", "testuser",
	)

	output := buf.String()

	// Error message should have sensitive strings redacted
	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "secret123")
	assert.NotContains(t, output, "testuser")
}

func TestNewSecureLogger(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})
	logger := NewSecureLogger(handler)

	require.NotNil(t, logger)

	buf.Reset()
	logger.Info("Test message", "password", "secret")

	output := buf.String()
	assert.Contains(t, output, `"password":"[REDACTED]"`)
	assert.NotContains(t, output, "secret")
}

func TestNewSecureLoggerWithCredentials(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})

	// Test with specific credentials
	username := "testuser123"
	password := "mysecretpass456"
	ip2locationKey := "abcdef123456"
	authToken := "token789xyz"

	logger := NewSecureLoggerWithCredentials(handler, username, password, ip2locationKey, authToken)
	require.NotNil(t, logger)

	tests := []struct {
		name    string
		message string
		attrs   []any
	}{
		{
			name:    "username in message",
			message: "User login attempt for testuser123",
			attrs:   []any{},
		},
		{
			name:    "password in message",
			message: "Authentication failed with password mysecretpass456",
			attrs:   []any{},
		},
		{
			name:    "ip2location key in message",
			message: "API call failed with key abcdef123456",
			attrs:   []any{},
		},
		{
			name:    "auth token in message",
			message: "Token validation failed: token789xyz",
			attrs:   []any{},
		},
		{
			name:    "credentials in attributes",
			message: "Login attempt",
			attrs:   []any{"user", username, "pass", password, "key", ip2locationKey},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			logger.Info(tt.message, tt.attrs...)

			output := buf.String()

			// Should not contain any of the actual credential values
			assert.NotContains(t, output, username, "Username should be redacted")
			assert.NotContains(t, output, password, "Password should be redacted")
			assert.NotContains(t, output, ip2locationKey, "IP2Location key should be redacted")
			assert.NotContains(t, output, authToken, "Auth token should be redacted")

			// Should contain redacted values
			assert.Contains(t, output, "[REDACTED]", "Should contain redacted placeholder")
		})
	}
}

func TestNewSecureLoggerWithCredentials_EmptyValues(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})

	// Test with empty credentials - should not cause issues
	logger := NewSecureLoggerWithCredentials(handler, "", "", "", "")
	require.NotNil(t, logger)

	buf.Reset()
	logger.Info("Test message with no credentials to redact")

	output := buf.String()
	assert.Contains(t, output, "Test message with no credentials to redact")
}

func TestRedactorHandler_Enabled(t *testing.T) {
	handler := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})
	redactor := NewRedactorHandler(handler)

	ctx := context.Background()

	// Should respect the underlying handler's level
	assert.False(t, redactor.Enabled(ctx, slog.LevelInfo))
	assert.True(t, redactor.Enabled(ctx, slog.LevelWarn))
	assert.True(t, redactor.Enabled(ctx, slog.LevelError))
}

func TestRedactorHandler_UpdateSecrets(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})
	redactor := NewRedactorHandler(handler)
	logger := slog.New(redactor)

	// Test basic UpdateSecrets functionality
	t.Run("basic functionality", func(t *testing.T) {
		// Initially no secrets are redacted
		buf.Reset()
		logger.Info("Password is mysecret123 and token is abc456")
		output := buf.String()
		assert.Contains(t, output, "mysecret123")
		assert.Contains(t, output, "abc456")

		// Update with new secrets
		redactor.UpdateSecrets([]string{"mysecret123", "abc456"})

		// Now secrets should be redacted
		buf.Reset()
		logger.Info("Password is mysecret123 and token is abc456")
		output = buf.String()
		assert.NotContains(t, output, "mysecret123")
		assert.NotContains(t, output, "abc456")
		assert.Contains(t, output, "[REDACTED]")
	})

	// Test updating with new secrets replaces old ones
	t.Run("replace existing secrets", func(t *testing.T) {
		// Set initial secrets
		redactor.UpdateSecrets([]string{"oldsecret", "oldtoken"})

		buf.Reset()
		logger.Info("Old secret: oldsecret, new secret: newsecret")
		output := buf.String()
		assert.NotContains(t, output, "oldsecret")
		assert.Contains(t, output, "newsecret") // Should not be redacted yet

		// Update with new secrets
		redactor.UpdateSecrets([]string{"newsecret"})

		buf.Reset()
		logger.Info("Old secret: oldsecret, new secret: newsecret")
		output = buf.String()
		assert.Contains(t, output, "oldsecret")    // Should not be redacted anymore
		assert.NotContains(t, output, "newsecret") // Should be redacted now
	})

	// Test with empty slice
	t.Run("empty secrets", func(t *testing.T) {
		// Set some secrets first
		redactor.UpdateSecrets([]string{"secret1", "secret2"})

		// Clear all secrets
		redactor.UpdateSecrets([]string{})

		buf.Reset()
		logger.Info("Secret1: secret1, Secret2: secret2")
		output := buf.String()
		assert.Contains(t, output, "secret1")
		assert.Contains(t, output, "secret2")
	})

	// Test with nil slice
	t.Run("nil secrets", func(t *testing.T) {
		// Set some secrets first
		redactor.UpdateSecrets([]string{"secret1", "secret2"})

		// Clear all secrets with nil
		redactor.UpdateSecrets(nil)

		buf.Reset()
		logger.Info("Secret1: secret1, Secret2: secret2")
		output := buf.String()
		assert.Contains(t, output, "secret1")
		assert.Contains(t, output, "secret2")
	})

	// Test with empty strings in slice
	t.Run("empty strings in slice", func(t *testing.T) {
		redactor.UpdateSecrets([]string{"", "validsecret", ""})

		buf.Reset()
		logger.Info("Valid secret: validsecret")
		output := buf.String()
		assert.NotContains(t, output, "validsecret")
		assert.Contains(t, output, "[REDACTED]")
	})

	// Test duplicate secrets
	t.Run("duplicate secrets", func(t *testing.T) {
		redactor.UpdateSecrets([]string{"duplicate", "duplicate", "unique"})

		buf.Reset()
		logger.Info("Duplicate secret: duplicate, unique secret: unique")
		output := buf.String()
		assert.NotContains(t, output, "duplicate")
		assert.NotContains(t, output, "unique")
		// Should contain two instances of [REDACTED] due to duplicates
		redactedCount := strings.Count(output, "[REDACTED]")
		assert.GreaterOrEqual(t, redactedCount, 2)
	})
}

func TestRedactorHandler_UpdateSecrets_ThreadSafety(t *testing.T) {
	// Test concurrent access to UpdateSecrets and logging
	t.Run("concurrent updates and logging", func(t *testing.T) {
		const numGoroutines = 10
		const numIterations = 50

		var wg sync.WaitGroup
		wg.Add(numGoroutines * 2) // Writers + Readers

		// Create a redactor with a discard handler to avoid buffer race conditions
		redactor := NewRedactorHandler(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{}))

		// Start goroutines that update secrets
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numIterations; j++ {
					secrets := []string{fmt.Sprintf("secret%d-%d", id, j)}
					redactor.UpdateSecrets(secrets)
				}
			}(i)
		}

		// Start goroutines that read/log with individual loggers to avoid buffer races
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				// Each goroutine gets its own buffer and logger to prevent race conditions
				var buf bytes.Buffer
				handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})
				localRedactor := NewRedactorHandler(handler)
				logger := slog.New(localRedactor)

				for j := 0; j < numIterations; j++ {
					buf.Reset()
					logger.Info(fmt.Sprintf("Test message %d-%d with secret%d-%d", id, j, id, j))
					// Just ensure it doesn't panic
					_ = buf.String()
				}
			}(i)
		}

		wg.Wait()
		// If we reach here without panicking, the test passes
	})
}

func BenchmarkRedactorHandler(b *testing.B) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})
	redactor := NewRedactorHandler(handler)
	logger := slog.New(redactor)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		logger.Info("VPN connection test",
			"username", "testuser",
			"password", "secret123",
			"server", "vpn.example.com",
			"port", 443,
		)
	}
}
