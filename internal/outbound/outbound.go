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

const maxRetries = 2

var (
	ErrInvalidSetup    = errors.New("the sender is not set up correctly")
	ErrInvalidRequest  = errors.New("the request is not valid")
	ErrNotAuthorized   = errors.New("the user has not confirmed sending to the provider")
	ErrUnsafeRequest   = errors.New("the request could not be made safe")
	ErrProviderFailed  = errors.New("the provider call failed")
	ErrCancelled       = errors.New("the run was cancelled")
	ErrTemporary       = errors.New("the provider had a temporary problem")
	validRoles         = []string{"user", "assistant", "tool"}
	validIdentifier    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	pathContinuesChars = regexp.MustCompile(`^([A-Za-z0-9_-]|\.[A-Za-z0-9_-])`)
)

type ToolCall struct {
	Name      string
	Arguments map[string]string
}

type Message struct {
	Role      string
	Text      string
	ToolCalls []ToolCall
}

type Request struct {
	System   string
	Messages []Message
}

type Response struct {
	Text      string
	ToolCalls []ToolCall
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

		sender.attempts++
		response, err := sender.provider.Send(ctx, safe)
		if err == nil {
			return response, nil
		}
		if ctx.Err() != nil {
			return Response{}, ErrCancelled
		}
		if !errors.Is(err, ErrTemporary) {
			return Response{}, ErrProviderFailed
		}
	}

	return Response{}, ErrProviderFailed
}

func (sender *Sender) prepare(request Request) (SafeRequest, error) {
	if err := validate(request); err != nil {
		return SafeRequest{}, err
	}

	textSanitizer := &sanitizer.Sanitizer{}
	clean := func(text string) string {
		cleaned, _ := textSanitizer.Sanitize(sender.shortenPaths(text))
		return cleaned
	}

	safe := Request{System: clean(request.System)}
	for _, message := range request.Messages {
		safeMessage := Message{Role: message.Role, Text: clean(message.Text)}

		for _, call := range message.ToolCalls {
			safeCall := ToolCall{Name: call.Name, Arguments: make(map[string]string, len(call.Arguments))}
			for key, value := range call.Arguments {
				safeCall.Arguments[key] = clean(value)
			}
			safeMessage.ToolCalls = append(safeMessage.ToolCalls, safeCall)
		}

		safe.Messages = append(safe.Messages, safeMessage)
	}

	if encodingHasFindings(safe) {
		return SafeRequest{}, ErrUnsafeRequest
	}

	return SafeRequest{request: safe}, nil
}

func validate(request Request) error {
	if len(request.Messages) == 0 {
		return ErrInvalidRequest
	}

	for _, message := range request.Messages {
		if !slices.Contains(validRoles, message.Role) {
			return ErrInvalidRequest
		}
		for _, call := range message.ToolCalls {
			if !validIdentifier.MatchString(call.Name) {
				return ErrInvalidRequest
			}
			for key := range call.Arguments {
				if !validIdentifier.MatchString(key) {
					return ErrInvalidRequest
				}
			}
		}
	}

	return nil
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
