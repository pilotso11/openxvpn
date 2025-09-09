// Package logging provides secure logging functionality with automatic redaction
// of sensitive information from log messages and attributes. It implements an
// slog.Handler wrapper that identifies and replaces credentials, tokens, keys,
// and other sensitive data with redacted placeholders to prevent security leaks.
package logging

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// RedactedValue is the constant string used to replace all sensitive data in log messages.
// This provides a consistent and recognizable placeholder for redacted information.
const RedactedValue = "[REDACTED]"

// RedactorHandler wraps an slog.Handler to automatically redact sensitive information
// from log messages and attributes. It supports both pattern-based detection of sensitive
// keys (passwords, tokens, etc.) and explicit string replacement for specific values.
type RedactorHandler struct {
	// handler is the underlying slog.Handler that receives redacted log records
	handler slog.Handler
	// explicitStrings contains specific sensitive strings to be redacted from log content
	explicitStrings []string
	// mutex protects concurrent access to explicitStrings during updates and reads
	mutex sync.RWMutex
}

// NewRedactorHandler creates a new RedactorHandler that wraps the given slog.Handler.
// The returned handler will automatically redact sensitive information based on common
// patterns but will not redact any explicit strings until they are configured separately.
func NewRedactorHandler(handler slog.Handler) *RedactorHandler {
	return &RedactorHandler{handler: handler, explicitStrings: []string{}}
}

// NewRedactorHandlerWithStrings creates a new RedactorHandler with predefined sensitive strings.
// This constructor allows immediate specification of exact strings that should be redacted
// from log messages, in addition to the standard pattern-based sensitive key detection.
func NewRedactorHandlerWithStrings(handler slog.Handler, sensitiveStrings []string) *RedactorHandler {
	return &RedactorHandler{
		handler:         handler,
		explicitStrings: sensitiveStrings,
	}
}

// Enabled implements slog.Handler.Enabled by delegating to the underlying handler.
// This determines whether log records at the given level should be processed.
func (h *RedactorHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

// Handle implements slog.Handler.Handle by redacting sensitive information from log records.
// It creates a new log record with redacted message content and attributes, then passes
// the sanitized record to the underlying handler for actual logging.
func (h *RedactorHandler) Handle(ctx context.Context, record slog.Record) error {
	// Create a new record with redacted message
	newRecord := slog.NewRecord(record.Time, record.Level, h.redactString(record.Message), record.PC)

	// Redact attributes
	record.Attrs(func(attr slog.Attr) bool {
		redactedAttr := h.redactAttr(attr)
		newRecord.AddAttrs(redactedAttr)
		return true
	})

	return h.handler.Handle(ctx, newRecord)
}

// WithAttrs implements slog.Handler.WithAttrs
func (h *RedactorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redactedAttrs := make([]slog.Attr, len(attrs))
	for i, attr := range attrs {
		redactedAttrs[i] = h.redactAttr(attr)
	}
	return &RedactorHandler{handler: h.handler.WithAttrs(redactedAttrs)}
}

// WithGroup implements slog.Handler.WithGroup
func (h *RedactorHandler) WithGroup(name string) slog.Handler {
	return &RedactorHandler{handler: h.handler.WithGroup(name)}
}

// isSensitiveKey checks if an attribute key is considered sensitive
func (h *RedactorHandler) isSensitiveKey(key string) bool {
	sensitiveKeys := []string{
		"password", "passwd", "pwd",
		"token", "auth_token", "access_token", "refresh_token",
		"key", "api_key", "secret_key", "private_key",
		"username", "user", "login",
		"secret", "credential", "auth",
		"ip2location_key",
	}

	keyLower := strings.ToLower(key)
	for _, sensitiveKey := range sensitiveKeys {
		if keyLower == sensitiveKey || strings.Contains(keyLower, sensitiveKey) {
			return true
		}
	}
	return false
}

// redactAttr redacts sensitive information from an slog.Attr
func (h *RedactorHandler) redactAttr(attr slog.Attr) slog.Attr {
	// Redact the value based on its type
	switch attr.Value.Kind() {
	case slog.KindString:
		// Check if the key itself is sensitive
		if h.isSensitiveKey(attr.Key) {
			return slog.String(attr.Key, RedactedValue)
		}
		return slog.String(attr.Key, h.redactString(attr.Value.String()))
	case slog.KindGroup:
		// Recursively redact group attributes
		groupAttrs := attr.Value.Group()
		redactedGroupAttrs := make([]any, 0, len(groupAttrs)*2)
		for _, groupAttr := range groupAttrs {
			redactedAttr := h.redactAttr(groupAttr)
			redactedGroupAttrs = append(redactedGroupAttrs, redactedAttr.Key, redactedAttr.Value)
		}
		return slog.Group(attr.Key, redactedGroupAttrs...)
	case slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindBool:
		// For non-string types, only redact if the key is sensitive
		if h.isSensitiveKey(attr.Key) {
			return slog.String(attr.Key, RedactedValue)
		}
		return attr
	default:
		// For other types, check if key is sensitive first
		if h.isSensitiveKey(attr.Key) {
			return slog.String(attr.Key, RedactedValue)
		}
		// Otherwise convert to string and redact if patterns match
		return slog.String(attr.Key, h.redactString(attr.Value.String()))
	}
}

// redactString redacts explicit sensitive strings from a string
func (h *RedactorHandler) redactString(s string) string {
	result := s

	h.mutex.RLock()
	defer h.mutex.RUnlock()

	// Replace each explicit sensitive string with redacted value
	for _, sensitiveStr := range h.explicitStrings {
		if sensitiveStr != "" && strings.Contains(result, sensitiveStr) {
			result = strings.ReplaceAll(result, sensitiveStr, RedactedValue)
		}
	}

	return result
}

// UpdateSecrets updates the list of sensitive strings to redact
func (h *RedactorHandler) UpdateSecrets(sensitiveStrings []string) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.explicitStrings = make([]string, len(sensitiveStrings))
	copy(h.explicitStrings, sensitiveStrings)
}

// NewSecureLogger creates a new slog.Logger with credential redaction
func NewSecureLogger(handler slog.Handler) *slog.Logger {
	return slog.New(NewRedactorHandler(handler))
}

// NewSecureLoggerWithCredentials creates a new slog.Logger with explicit credential redaction
func NewSecureLoggerWithCredentials(handler slog.Handler, username, password, ip2locationKey, authToken string) *slog.Logger {
	sensitiveStrings := []string{}

	if username != "" {
		sensitiveStrings = append(sensitiveStrings, username)
	}
	if password != "" {
		sensitiveStrings = append(sensitiveStrings, password)
	}
	if ip2locationKey != "" {
		sensitiveStrings = append(sensitiveStrings, ip2locationKey)
	}
	if authToken != "" {
		sensitiveStrings = append(sensitiveStrings, authToken)
	}

	return slog.New(NewRedactorHandlerWithStrings(handler, sensitiveStrings))
}
