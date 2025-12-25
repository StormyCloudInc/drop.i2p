package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"drop-i2p/internal/config"
)

// Event types
const (
	EventReport         = "report"
	EventStorageWarning = "storage_warning"
)

// Notifier sends webhook notifications for configured events
type Notifier struct {
	client    *http.Client
	url       string
	secret    string
	events    map[string]bool
	enabled   bool
	isDiscord bool
}

// Payload represents the webhook payload structure
type Payload struct {
	Event     string    `json:"event"`
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data"`
}

// ReportData contains data for report events
type ReportData struct {
	ReportID     string `json:"report_id"`
	FileID       string `json:"file_id"`
	Reason       string `json:"reason"`
	ReporterDest string `json:"reporter_dest,omitempty"`
}

// StorageData contains data for storage warning events
type StorageData struct {
	CurrentBytes   int64  `json:"current_bytes"`
	ThresholdBytes int64  `json:"threshold_bytes"`
	Formatted      string `json:"formatted"`
}

// DiscordWebhook represents Discord webhook payload format
type DiscordWebhook struct {
	Content string         `json:"content,omitempty"`
	Embeds  []DiscordEmbed `json:"embeds,omitempty"`
}

// DiscordEmbed represents a Discord embed object
type DiscordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Fields      []DiscordEmbedField `json:"fields,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
}

// DiscordEmbedField represents a field in a Discord embed
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// NewNotifier creates a new webhook notifier from config
func NewNotifier(cfg *config.Config) *Notifier {
	// Parse enabled events
	events := make(map[string]bool)
	if cfg.WebhookEvents != "" {
		for _, e := range strings.Split(cfg.WebhookEvents, ",") {
			events[strings.TrimSpace(e)] = true
		}
	}

	timeout := cfg.WebhookTimeout
	if timeout <= 0 {
		timeout = 10
	}

	// Detect if this is a Discord webhook URL
	isDiscord := strings.Contains(cfg.WebhookURL, "discord.com/api/webhooks")

	return &Notifier{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		url:       cfg.WebhookURL,
		secret:    cfg.WebhookSecret,
		events:    events,
		enabled:   cfg.WebhookURL != "",
		isDiscord: isDiscord,
	}
}

// IsEnabled returns true if webhooks are enabled
func (n *Notifier) IsEnabled() bool {
	return n.enabled
}

// IsEventEnabled returns true if the specified event type is enabled
func (n *Notifier) IsEventEnabled(event string) bool {
	return n.enabled && n.events[event]
}

// Send sends a webhook for the specified event
func (n *Notifier) Send(ctx context.Context, event string, data any) error {
	if !n.IsEventEnabled(event) {
		return nil
	}

	payload := Payload{
		Event:     event,
		Timestamp: time.Now().UTC(),
		Data:      data,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "I2P-Secure-Share-Webhook/1.0")

	// Add HMAC signature if secret is configured
	if n.secret != "" {
		sig := n.sign(body)
		req.Header.Set("X-Webhook-Signature", sig)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	return nil
}

// SendAsync sends a webhook asynchronously (fire-and-forget)
func (n *Notifier) SendAsync(event string, data any) {
	if !n.IsEventEnabled(event) {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := n.Send(ctx, event, data); err != nil {
			log.Printf("[webhook] Failed to send %s event: %v", event, err)
		} else {
			log.Printf("[webhook] Successfully sent %s event", event)
		}
	}()
}

// SendReport sends a report webhook notification
func (n *Notifier) SendReport(reportID, fileID, reason, reporterDest string) {
	if n.isDiscord {
		n.SendDiscordAsync(EventReport, DiscordWebhook{
			Embeds: []DiscordEmbed{{
				Title:       "New Abuse Report",
				Description: "A new content report has been submitted.",
				Color:       15158332, // Red
				Fields: []DiscordEmbedField{
					{Name: "Report ID", Value: reportID, Inline: true},
					{Name: "File ID", Value: fileID, Inline: true},
					{Name: "Reason", Value: reason, Inline: false},
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}},
		})
		return
	}
	n.SendAsync(EventReport, ReportData{
		ReportID:     reportID,
		FileID:       fileID,
		Reason:       reason,
		ReporterDest: reporterDest,
	})
}

// SendStorageWarning sends a storage threshold warning webhook
func (n *Notifier) SendStorageWarning(currentBytes, thresholdBytes int64) {
	if n.isDiscord {
		n.SendDiscordAsync(EventStorageWarning, DiscordWebhook{
			Embeds: []DiscordEmbed{{
				Title:       "Storage Warning",
				Description: "Storage threshold has been exceeded.",
				Color:       16776960, // Yellow
				Fields: []DiscordEmbedField{
					{Name: "Current Storage", Value: formatBytes(currentBytes), Inline: true},
					{Name: "Threshold", Value: formatBytes(thresholdBytes), Inline: true},
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}},
		})
		return
	}
	n.SendAsync(EventStorageWarning, StorageData{
		CurrentBytes:   currentBytes,
		ThresholdBytes: thresholdBytes,
		Formatted:      formatBytes(currentBytes),
	})
}

// SendDiscord sends a Discord-formatted webhook
func (n *Notifier) SendDiscord(ctx context.Context, payload DiscordWebhook) error {
	if !n.enabled {
		return nil
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create discord request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "I2P-Secure-Share-Webhook/1.0")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("discord request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord returned error status: %d", resp.StatusCode)
	}

	return nil
}

// SendDiscordAsync sends a Discord webhook asynchronously
func (n *Notifier) SendDiscordAsync(event string, payload DiscordWebhook) {
	if !n.IsEventEnabled(event) {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := n.SendDiscord(ctx, payload); err != nil {
			log.Printf("[webhook] Failed to send Discord %s event: %v", event, err)
		} else {
			log.Printf("[webhook] Successfully sent Discord %s event", event)
		}
	}()
}

// sign creates an HMAC-SHA256 signature for the payload
func (n *Notifier) sign(body []byte) string {
	mac := hmac.New(sha256.New, []byte(n.secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// formatBytes formats bytes into human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
