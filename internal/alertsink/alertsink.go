// Package alertsink delivers new alerts to a webhook or an email address. Every piece of text that
// could hold evidence (a rule title, a field value, a cited log line) passes the sanitizer before it
// leaves the process, the same as the AI outbound path: an alert can quote a log line, and that line
// can hold a secret or text aimed at whoever reads it.
//
// A sink never blocks the watch loop on a dead endpoint: a failed send is retried a bounded number of
// times, then recorded as failed and skipped. The loop moves on to the next tick either way.
package alertsink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

var (
	ErrInvalidSetup = errors.New("the sink is not set up correctly")
	ErrSendFailed   = errors.New("the alert could not be delivered")
)

const (
	maxRetries    = 2
	retryDelay    = 2 * time.Second
	requestBudget = 10 * time.Second
	maxAlertsSent = 50
)

// Alert is one alert in the form a sink sends, already reduced to plain, sanitized text. It never holds
// an *rules.Alert, so a sink package cannot reach past what it is given.
type Alert struct {
	Rule    string
	Title   string
	Level   string
	Time    string
	Summary string
}

// Sink delivers alerts somewhere outside the process. Send returns an error only when every retry
// failed; the caller logs it and continues, it never stops the loop.
type Sink interface {
	Send(ctx context.Context, alerts []Alert) error
}

// FromAlerts turns rule alerts into the sanitized, bounded form a sink sends. location formats the
// times. Every free-text field passes its own sanitizer so one sink's output never carries a secret
// that the detect report would also have removed.
func FromAlerts(alerts []*rules.Alert, clean func(string) string) []Alert {
	if len(alerts) > maxAlertsSent {
		alerts = alerts[:maxAlertsSent]
	}

	out := make([]Alert, 0, len(alerts))
	for _, alert := range alerts {
		a := Alert{
			Rule:  clean(alert.Rule.Name),
			Title: clean(alert.Rule.Title),
			Level: alert.Rule.Level,
			Time:  alert.Last.UTC().Format(time.RFC3339),
		}
		a.Summary = clean(summarize(alert))
		out = append(out, a)
	}

	return out
}

func summarize(alert *rules.Alert) string {
	if alert.Count > 1 {
		return fmt.Sprintf("%d events, last at %s", alert.Count, alert.Last.UTC().Format(time.RFC3339))
	}

	return fmt.Sprintf("1 event at %s", alert.Last.UTC().Format(time.RFC3339))
}

// withRetry runs send up to maxRetries+1 times, with a fixed delay between attempts, stopping early if
// ctx is done. It never panics out: every path returns an error or nil.
func withRetry(ctx context.Context, send func(context.Context) error) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return ErrSendFailed
		}
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ErrSendFailed
			case <-time.After(retryDelay):
			}
		}
		if err := send(ctx); err != nil {
			lastErr = err
			continue
		}

		return nil
	}

	if lastErr != nil {
		return fmt.Errorf("%w: %v", ErrSendFailed, lastErr)
	}

	return ErrSendFailed
}

// WebhookSink posts a JSON body to a fixed URL: a Slack or Discord incoming webhook, or any endpoint
// that accepts JSON. The URL is validated once, at construction, never re-read from alert content.
type WebhookSink struct {
	url    string
	client *http.Client
}

func NewWebhookSink(rawURL string) (*WebhookSink, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return nil, ErrInvalidSetup
	}

	return &WebhookSink{url: rawURL, client: &http.Client{Timeout: requestBudget}}, nil
}

type webhookPayload struct {
	Text   string          `json:"text"`
	Alerts []webhookDetail `json:"alerts"`
}

type webhookDetail struct {
	Rule    string `json:"rule"`
	Title   string `json:"title"`
	Level   string `json:"level"`
	Time    string `json:"time"`
	Summary string `json:"summary"`
}

func (sink *WebhookSink) Send(ctx context.Context, alerts []Alert) error {
	if len(alerts) == 0 {
		return nil
	}

	payload := webhookPayload{Text: fmt.Sprintf("Omamori: %d new alert(s)", len(alerts))}
	for _, alert := range alerts {
		payload.Alerts = append(payload.Alerts, webhookDetail{
			Rule: alert.Rule, Title: alert.Title, Level: alert.Level, Time: alert.Time, Summary: alert.Summary,
		})
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSendFailed, err)
	}

	return withRetry(ctx, func(ctx context.Context) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, sink.url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")

		response, err := sink.client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()

		if response.StatusCode >= 300 {
			return fmt.Errorf("webhook returned status %d", response.StatusCode)
		}

		return nil
	})
}

// SMTPConfig holds everything an SMTPSink needs. Auth comes from the caller (read it from an
// environment variable, never from a flag or a file the user might commit), never printed or logged.
type SMTPConfig struct {
	Host     string
	Port     int
	From     string
	To       []string
	Username string
	Password string
	// UseTLS requests STARTTLS. Plaintext SMTP is refused unless explicitly allowed, because the
	// alert body can carry sanitized but still meaningful fragments of what happened.
	UseTLS bool
}

type SMTPSink struct {
	config SMTPConfig
}

func NewSMTPSink(config SMTPConfig) (*SMTPSink, error) {
	if config.Host == "" || config.Port <= 0 || config.Port > 65535 || config.From == "" || len(config.To) == 0 {
		return nil, ErrInvalidSetup
	}

	return &SMTPSink{config: config}, nil
}

func (sink *SMTPSink) Send(ctx context.Context, alerts []Alert) error {
	if len(alerts) == 0 {
		return nil
	}

	message := buildEmail(sink.config.From, sink.config.To, alerts)

	return withRetry(ctx, func(ctx context.Context) error {
		return sink.deliver(message)
	})
}

func buildEmail(from string, to []string, alerts []Alert) []byte {
	var body strings.Builder
	fmt.Fprintf(&body, "From: %s\r\n", from)
	fmt.Fprintf(&body, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&body, "Subject: Omamori: %d new alert(s)\r\n", len(alerts))
	body.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")

	for _, alert := range alerts {
		fmt.Fprintf(&body, "[%s] %s (%s)\n%s\nat %s\n\n", alert.Level, alert.Title, alert.Rule, alert.Summary, alert.Time)
	}

	return []byte(body.String())
}

func (sink *SMTPSink) deliver(message []byte) error {
	address := fmt.Sprintf("%s:%d", sink.config.Host, sink.config.Port)

	var auth smtp.Auth
	if sink.config.Username != "" {
		auth = smtp.PlainAuth("", sink.config.Username, sink.config.Password, sink.config.Host)
	}

	if !sink.config.UseTLS {
		return smtp.SendMail(address, auth, sink.config.From, sink.config.To, message)
	}

	return sendWithSTARTTLS(address, sink.config.Host, auth, sink.config.From, sink.config.To, message)
}

func sendWithSTARTTLS(address, serverName string, auth smtp.Auth, from string, to []string, message []byte) error {
	client, err := smtp.Dial(address)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.StartTLS(&tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}); err != nil {
		return err
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	return client.Quit()
}

// Sanitizer is a small helper so callers in cmd/ don't need to import the sanitizer package directly
// just to build the clean func that FromAlerts wants.
func Sanitizer() func(string) string {
	clean := &sanitizer.Sanitizer{}
	return func(text string) string {
		cleaned, _ := clean.Sanitize(text)
		return cleaned
	}
}
