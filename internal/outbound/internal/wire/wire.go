// Package wire holds what every provider client shares: the request and answer types, the
// error kinds, and the safe HTTP settings. A client never sees outbound's own types.
package wire

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxResponseBytes stops a server from filling the memory with one answer.
const MaxResponseBytes = 8 << 20

var (
	ErrNoKey       = errors.New("no API key")
	ErrBadConfig   = errors.New("the client settings are not valid")
	ErrBadRequest  = errors.New("the request cannot be sent in this form")
	ErrRetryable   = errors.New("temporary provider problem")
	ErrAuth        = errors.New("the provider rejected the API key")
	ErrRejected    = errors.New("the provider rejected the request")
	ErrRefused     = errors.New("the provider declined the request")
	ErrBadResponse = errors.New("the provider answer cannot be used")
)

type ToolCall struct {
	ID        string
	Name      string
	Arguments map[string]string
}

type Message struct {
	Role       string
	Text       string
	ToolCalls  []ToolCall
	ToolCallID string
}

type Parameter struct {
	Name        string
	Description string
	Required    bool
}

type Tool struct {
	Name        string
	Description string
	Parameters  []Parameter
}

type Request struct {
	System   string
	Messages []Message
	Tools    []Tool
}

type Response struct {
	Text       string
	ToolCalls  []ToolCall
	TokensUsed int
}

// StatusError turns an HTTP status into an error kind. It never holds the server's text.
func StatusError(status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ErrAuth
	case status == http.StatusRequestTimeout || status == http.StatusConflict || status == http.StatusTooManyRequests || status >= 500:
		return ErrRetryable
	}

	return ErrRejected
}

// SafeBaseURL accepts https, and plain http only to the same machine.
func SafeBaseURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}

	return parsed.Scheme == "http" && IsLoopback(parsed)
}

func IsLoopback(parsed *url.URL) bool {
	host, _, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		host = parsed.Hostname()
	}

	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// NewHTTPClient never follows a redirect, because Go forwards custom headers to the new host
// and the Authorization header could follow them in other settings.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func NonEmpty(text string) string {
	if text == "" {
		return "(empty)"
	}

	return text
}

// ParseArguments reads a tool input. The tools take only text, so a value of another type is
// kept as its JSON text and the gateway, which checks every argument, decides what to do with it.
func ParseArguments(raw string) map[string]string {
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return map[string]string{}
	}

	arguments := make(map[string]string, len(decoded))
	for name, value := range decoded {
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			text = string(value)
		}
		arguments[name] = text
	}

	return arguments
}

const (
	MaxModelChoices = 100
	maxModelIDRunes = 100
)

// notChat are parts of a name that belong to models which cannot answer a chat.
var notChat = []string{"embed", "whisper", "tts", "dall-e", "moderation", "transcribe", "realtime", "image", "audio", "guard", "rerank"}

// CleanModelIDs makes a list from a provider safe to show: the provider is not trusted
// with what appears on the screen. It drops odd names and non-chat models, removes doubles, and sorts.
func CleanModelIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	var cleaned []string

	for _, id := range ids {
		id = strings.TrimPrefix(id, "models/")
		if !usableModelID(id) || seen[id] {
			continue
		}
		seen[id] = true
		cleaned = append(cleaned, id)
	}

	sort.Strings(cleaned)
	if len(cleaned) > MaxModelChoices {
		cleaned = cleaned[:MaxModelChoices]
	}

	return cleaned
}

func usableModelID(id string) bool {
	if id == "" || strings.HasPrefix(id, "models/") || utf8.RuneCountInString(id) > maxModelIDRunes {
		return false
	}
	for _, character := range id {
		if character > unicode.MaxASCII || unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	lower := strings.ToLower(id)
	for _, part := range notChat {
		if strings.Contains(lower, part) {
			return false
		}
	}

	return true
}
