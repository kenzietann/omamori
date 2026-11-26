package alertsink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/rules"
)

func rule(t *testing.T, name, title string) *rules.Rule {
	t.Helper()
	parsed, err := rules.Parse([]byte("title: "+title+"\nname: "+name+"\nlogsource: {}\ndetection:\n  s: {action: x}\n  condition: s"), "t.yml")
	if err != nil {
		t.Fatal(err)
	}

	return parsed[0]
}

func TestNewWebhookSinkRejectsBadURL(t *testing.T) {
	for _, bad := range []string{"", "not a url", "ftp://example.com", "javascript:alert(1)"} {
		if _, err := NewWebhookSink(bad); err == nil {
			t.Errorf("NewWebhookSink(%q) must be refused", bad)
		}
	}
}

func TestWebhookSinkSendsAlerts(t *testing.T) {
	var received webhookPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := NewWebhookSink(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	alerts := []Alert{{Rule: "guess", Title: "Password guessing", Level: "high", Time: "2026-11-26T09:00:00Z", Summary: "1 event"}}
	if err := sink.Send(context.Background(), alerts); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(received.Alerts) != 1 || received.Alerts[0].Rule != "guess" {
		t.Fatalf("webhook did not receive the alert, got %+v", received)
	}
}

func TestWebhookSinkSendingNothingIsANoop(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer server.Close()

	sink, err := NewWebhookSink(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Send(context.Background(), nil); err != nil {
		t.Fatalf("Send(nil): %v", err)
	}
	if called {
		t.Error("an empty alert slice must not reach the network")
	}
}

func TestWebhookSinkRetriesThenFails(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sink, err := NewWebhookSink(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	err = sink.Send(context.Background(), []Alert{{Rule: "guess", Level: "high"}})
	if err == nil {
		t.Fatal("a server that always errors must make Send fail")
	}
	if attempts.Load() != maxRetries+1 {
		t.Fatalf("expected %d attempts, got %d", maxRetries+1, attempts.Load())
	}
	if time.Since(start) < retryDelay {
		t.Error("retries must wait between attempts, not hammer the endpoint immediately")
	}
}

func TestWebhookSinkStopsRetryingWhenContextCancelled(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sink, err := NewWebhookSink(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := sink.Send(ctx, []Alert{{Rule: "guess"}}); err == nil {
		t.Fatal("Send with an already-cancelled context must fail, not hang or succeed")
	}
}

func TestNewSMTPSinkRejectsIncompleteConfig(t *testing.T) {
	cases := []SMTPConfig{
		{},
		{Host: "smtp.example.com"},
		{Host: "smtp.example.com", Port: 587},
		{Host: "smtp.example.com", Port: 587, From: "a@example.com"},
	}
	for _, config := range cases {
		if _, err := NewSMTPSink(config); err == nil {
			t.Errorf("NewSMTPSink(%+v) must be refused as incomplete", config)
		}
	}
}

func TestNewSMTPSinkAcceptsCompleteConfig(t *testing.T) {
	config := SMTPConfig{Host: "smtp.example.com", Port: 587, From: "a@example.com", To: []string{"b@example.com"}}
	if _, err := NewSMTPSink(config); err != nil {
		t.Fatalf("a complete config must be accepted: %v", err)
	}
}

func TestBuildEmailIncludesEveryAlert(t *testing.T) {
	alerts := []Alert{
		{Rule: "guess", Title: "Password guessing", Level: "high", Time: "2026-11-26T09:00:00Z", Summary: "12 events"},
		{Rule: "scan", Title: "File scan", Level: "medium", Time: "2026-11-26T09:05:00Z", Summary: "1 event"},
	}
	message := string(buildEmail("alerts@example.com", []string{"you@example.com"}, alerts))

	for _, want := range []string{"Password guessing", "File scan", "alerts@example.com", "you@example.com", "2 new alert"} {
		if !strings.Contains(message, want) {
			t.Errorf("email is missing %q:\n%s", want, message)
		}
	}
}

func TestFromAlertsSanitizesSecretsInTheTitle(t *testing.T) {
	// A rule title is normally fixed text, but FromAlerts must not assume that: whatever clean func
	// it is given is applied, so a value that happens to look like a secret is still removed.
	alert := &rules.Alert{Rule: rule(t, "r", "Key AKIAABCDEFGHIJKLMNOP leaked"), Last: time.Now(), Count: 1}
	out := FromAlerts([]*rules.Alert{alert}, Sanitizer())

	if strings.Contains(out[0].Title, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("a secret-shaped value in the title must be sanitized, got %q", out[0].Title)
	}
}

func TestFromAlertsBoundsHowManyAreSent(t *testing.T) {
	var alerts []*rules.Alert
	for i := 0; i < maxAlertsSent+10; i++ {
		alerts = append(alerts, &rules.Alert{Rule: rule(t, "r", "T"), Last: time.Now(), Count: 1})
	}

	out := FromAlerts(alerts, Sanitizer())
	if len(out) != maxAlertsSent {
		t.Fatalf("got %d alerts, want the bound of %d", len(out), maxAlertsSent)
	}
}

func TestFromAlertsSummarizesCount(t *testing.T) {
	alert := &rules.Alert{Rule: rule(t, "r", "T"), Last: time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC), Count: 12,
		Events: []event.Event{{Fields: map[string]string{}}}}
	out := FromAlerts([]*rules.Alert{alert}, Sanitizer())

	if !strings.Contains(out[0].Summary, "12") {
		t.Errorf("summary must mention the count, got %q", out[0].Summary)
	}
}
