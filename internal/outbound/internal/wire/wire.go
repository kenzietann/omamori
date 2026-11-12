// Package wire holds what every provider client shares: the request and answer types, the
// error kinds, and the safe HTTP settings. A client never sees outbound's own types.
package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

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

// Rejection is a refusal that the provider gave for the request itself, for example an unknown model.
// It holds the HTTP status and a short code and never the text of the provider's message,
// because that text could repeat part of the request.
type Rejection struct {
	Status int
	Code   string
	Param  string
}

func (rejection *Rejection) Error() string {
	return ErrRejected.Error() + " (" + rejection.Detail() + ")"
}
func (rejection *Rejection) Unwrap() error { return ErrRejected }

func (rejection *Rejection) Detail() string {
	detail := fmt.Sprintf("status %d", rejection.Status)
	if rejection.Code != "" {
		detail += ", code " + rejection.Code
	}
	if rejection.Param != "" {
		detail += ", field " + rejection.Param
	}

	return detail
}

var (
	codePattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	paramPattern = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,64}$`)
)

func StatusErrorWithBody(status int, body []byte) error {
	err := StatusError(status)
	if err != ErrRejected {
		return err
	}

	var decoded struct {
		Error struct {
			Code   any    `json:"code"`
			Type   string `json:"type"`
			Status string `json:"status"`
			Param  any    `json:"param"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &decoded)

	candidates := []string{decoded.Error.Type, decoded.Error.Status}
	if code, isText := decoded.Error.Code.(string); isText {
		candidates = []string{code, decoded.Error.Type, decoded.Error.Status}
	}
	rejection := &Rejection{Status: status}
	for _, candidate := range candidates {
		if codePattern.MatchString(candidate) {
			rejection.Code = candidate
			break
		}
	}
	if param, isText := decoded.Error.Param.(string); isText && paramPattern.MatchString(param) {
		rejection.Param = param
	}

	return rejection
}

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
