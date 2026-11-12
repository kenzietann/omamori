package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/kenzietann/omamori/internal/sanitizer"
)

const (
	maxRetries     = 2
	maxTools       = 16
	maxParameters  = 8
	maxDescription = 1000
)

var (
	ErrInvalidSetup    = errors.New("the sender is not set up correctly")
	ErrInvalidRequest  = errors.New("the request is not valid")
	ErrNotAuthorized   = errors.New("the user has not confirmed sending to the provider")
	ErrUnsafeRequest   = errors.New("the request could not be made safe")
	ErrProviderFailed  = errors.New("the provider call failed")
	ErrCancelled       = errors.New("the run was cancelled")
	ErrTemporary       = errors.New("the provider had a temporary problem")
	ErrRefused         = errors.New("the provider declined the request")
	ErrAuth            = errors.New("the provider rejected the API key")
	ErrLogFailed       = errors.New("the request could not be logged")
	validRoles         = []string{"user", "assistant", "tool"}
	validIdentifier    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	validCallID        = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	pathContinuesChars = regexp.MustCompile(`^([A-Za-z0-9_-]|\.[A-Za-z0-9_-])`)
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

type ToolParameter struct {
	Name        string
	Description string
	Required    bool
}

type ToolSpec struct {
	Name        string
	Description string
	Parameters  []ToolParameter
}

type Request struct {
	System   string
	Messages []Message
	Tools    []ToolSpec
}

type Response struct {
	Text       string
	ToolCalls  []ToolCall
	TokensUsed int
}

func ValidToolCall(call ToolCall) bool {
	if !validIdentifier.MatchString(call.Name) || (call.ID != "" && !validCallID.MatchString(call.ID)) {
		return false
	}
	for key := range call.Arguments {
		if !validIdentifier.MatchString(key) {
			return false
		}
	}

	return true
}

type SafeRequest struct {
	request Request
}

func (safe SafeRequest) Request() Request {
	return safe.request
}

type Provider interface {
	Name() string
	Send(ctx context.Context, request SafeRequest) (Response, error)
}

type Sender struct {
	provider   Provider
	roots      []string
	authorized bool
	attempts   int
	observer   func(Request) error
}

func New(provider Provider, projectDirectory string) (*Sender, error) {
	if provider == nil || projectDirectory == "" {
		return nil, ErrInvalidSetup
	}

	absolute, err := filepath.Abs(projectDirectory)
	if err != nil {
		return nil, ErrInvalidSetup
	}
	if filepath.Clean(absolute) == filepath.VolumeName(absolute)+string(filepath.Separator) {
		return nil, ErrInvalidSetup
	}
	roots := []string{filepath.Clean(absolute)}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil && resolved != roots[0] {
		roots = append(roots, resolved)
	}
	slices.SortFunc(roots, func(first, second string) int { return len(second) - len(first) })

	return &Sender{provider: provider, roots: roots}, nil
}

func (sender *Sender) ConsentText() string {
	return "Omamori will send sanitized content to " + sender.provider.Name() + " during this run."
}

func (sender *Sender) Authorize() {
	sender.authorized = true
}

// Observe sets a function that sees every cleaned request before it is sent. If it fails,
// the request is not sent, so nothing leaves without a log entry.
func (sender *Sender) Observe(observer func(Request) error) {
	sender.observer = observer
}

func (sender *Sender) Attempts() int {
	return sender.attempts
}

func (sender *Sender) Preview(request Request) (Request, error) {
	safe, err := sender.prepare(request)
	if err != nil {
		return Request{}, err
	}

	return safe.request, nil
}

func (sender *Sender) Send(ctx context.Context, request Request) (Response, error) {
	if !sender.authorized {
		return Response{}, ErrNotAuthorized
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return Response{}, ErrCancelled
		}

		safe, err := sender.prepare(request)
		if err != nil {
			return Response{}, err
		}

		if sender.observer != nil {
			if observeErr := sender.observer(safe.request); observeErr != nil {
				return Response{}, ErrLogFailed
			}
		}

		sender.attempts++
		response, err := sender.provider.Send(ctx, safe)
		if err == nil {
			return response, nil
		}
		if ctx.Err() != nil {
			return Response{}, ErrCancelled
		}
		switch {
		case errors.Is(err, ErrRefused):
			return Response{}, ErrRefused
		case errors.Is(err, ErrAuth):
			return Response{}, ErrAuth
		case !errors.Is(err, ErrTemporary):
			if DetailOf(err) != "" {
				return Response{}, err
			}

			return Response{}, ErrProviderFailed
		}
	}

	return Response{}, ErrProviderFailed
}

func (sender *Sender) prepare(request Request) (SafeRequest, error) {
	if err := validate(request); err != nil {
		return SafeRequest{}, err
	}

	safe := sender.clean(request, false)
	if !encodingHasFindings(safe) {
		return SafeRequest{request: safe}, nil
	}

	safe = sender.clean(request, true)
	if encodingHasFindings(safe) {
		return SafeRequest{}, ErrUnsafeRequest
	}

	return SafeRequest{request: safe}, nil
}

func (sender *Sender) clean(request Request, neutralize bool) Request {
	textSanitizer := &sanitizer.Sanitizer{}
	clean := func(text string) string {
		text = sender.shortenPaths(text)
		if neutralize {
			text = neutralizeEscapes(text)
		}
		cleaned, _ := textSanitizer.Sanitize(text)

		return cleaned
	}

	safe := Request{System: clean(request.System)}
	for _, message := range request.Messages {
		safeMessage := Message{Role: message.Role, Text: clean(message.Text), ToolCallID: message.ToolCallID}

		for _, call := range message.ToolCalls {
			safeCall := ToolCall{ID: call.ID, Name: call.Name, Arguments: make(map[string]string, len(call.Arguments))}
			for key, value := range call.Arguments {
				safeCall.Arguments[key] = clean(value)
			}
			safeMessage.ToolCalls = append(safeMessage.ToolCalls, safeCall)
		}

		safe.Messages = append(safe.Messages, safeMessage)
	}

	for _, spec := range request.Tools {
		safeSpec := ToolSpec{Name: spec.Name, Description: clean(spec.Description)}
		for _, parameter := range spec.Parameters {
			safeSpec.Parameters = append(safeSpec.Parameters, ToolParameter{Name: parameter.Name, Description: clean(parameter.Description), Required: parameter.Required})
		}
		safe.Tools = append(safe.Tools, safeSpec)
	}

	return safe
}

func neutralizeEscapes(text string) string {
	runes := []rune(text)
	for index, character := range runes {
		if !writtenAsUnicodeEscape(character) {
			continue
		}
		if index > 0 && isDigit(runes[index-1]) || index+1 < len(runes) && isDigit(runes[index+1]) {
			runes[index] = ' '
		}
	}

	return string(runes)
}

func writtenAsUnicodeEscape(character rune) bool {
	switch character {
	case '<', '>', '&', '\u2028', '\u2029':
		return true
	case '\n', '\r', '\t':
		return false
	}

	return character < ' ' || character == 0x7f
}

func isDigit(character rune) bool {
	return character >= '0' && character <= '9' || character >= '\uFF10' && character <= '\uFF19'
}

func validate(request Request) error {
	if len(request.Messages) == 0 {
		return ErrInvalidRequest
	}

	if len(request.Tools) > maxTools {
		return ErrInvalidRequest
	}
	for _, spec := range request.Tools {
		if !validToolSpec(spec) {
			return ErrInvalidRequest
		}
	}

	for _, message := range request.Messages {
		if !slices.Contains(validRoles, message.Role) {
			return ErrInvalidRequest
		}
		if message.ToolCallID != "" && (message.Role != "tool" || !validCallID.MatchString(message.ToolCallID)) {
			return ErrInvalidRequest
		}
		for _, call := range message.ToolCalls {
			if !ValidToolCall(call) {
				return ErrInvalidRequest
			}
		}
	}

	return nil
}

func validToolSpec(spec ToolSpec) bool {
	if !validIdentifier.MatchString(spec.Name) || len(spec.Description) > maxDescription || len(spec.Parameters) > maxParameters {
		return false
	}
	for _, parameter := range spec.Parameters {
		if !validIdentifier.MatchString(parameter.Name) || len(parameter.Description) > maxDescription {
			return false
		}
	}

	return true
}

func encodingHasFindings(request Request) bool {
	for _, escapeHTML := range []bool{true, false} {
		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		encoder.SetEscapeHTML(escapeHTML)
		if err := encoder.Encode(request); err != nil {
			return true
		}

		if _, findings := (&sanitizer.Sanitizer{}).Sanitize(buffer.String()); len(findings) > 0 {
			return true
		}
	}

	return false
}

func (sender *Sender) shortenPaths(text string) string {
	for _, root := range sender.roots {
		text = shortenPath(text, root)
	}

	return text
}

func shortenPath(text, root string) string {
	var builder strings.Builder
	cursor := 0

	for {
		found := strings.Index(text[cursor:], root)
		if found < 0 {
			break
		}
		start := cursor + found
		end := start + len(root)

		builder.WriteString(text[cursor:start])
		switch {
		case strings.HasPrefix(text[end:], "/"):
			end++
		case end < len(text) && pathContinuesChars.MatchString(text[end:]):
			builder.WriteString(root)
		default:
			builder.WriteString(".")
		}
		cursor = end
	}
	builder.WriteString(text[cursor:])

	return builder.String()
}
