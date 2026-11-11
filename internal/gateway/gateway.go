package gateway

import (
	"context"
	"errors"
	"strings"

	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

// The error texts never contain an argument, a path, or file content.
var (
	ErrUnknownTool      = errors.New("unknown tool")
	ErrInvalidArguments = errors.New("invalid arguments")
	ErrLimitExceeded    = errors.New("limit exceeded")
	ErrPathNotAllowed   = errors.New("path not allowed")
	ErrToolFailed       = errors.New("tool failed")
	ErrCancelled        = errors.New("cancelled")
	ErrLogFailed        = errors.New("the event could not be logged")
)

type Limits struct {
	MaxFileBytes    int64
	MaxLines        int
	MaxResults      int
	MaxFiles        int
	MaxStringLength int
}

var DefaultLimits = Limits{
	MaxFileBytes:    1 << 20,
	MaxLines:        5000,
	MaxResults:      100,
	MaxFiles:        2000,
	MaxStringLength: 500,
}

type Result struct {
	Text      string
	Truncated bool
	Skipped   int
}

// Event holds the tool name and a fixed reason, never an argument value.
type Event struct {
	Tool    string
	Allowed bool
	Reason  string
}

type argumentSpec struct {
	name     string
	required bool
}

type tool struct {
	arguments []argumentSpec
	run       func(ctx context.Context, gateway *Gateway, arguments map[string]string) (Result, error)
}

type Gateway struct {
	root      *pathguard.Root
	limits    Limits
	sanitizer sanitizer.Sanitizer
	tools     map[string]tool
	events    []Event
	observer  func(Event) error
}

func New(root *pathguard.Root, limits Limits) *Gateway {
	return &Gateway{
		root:   root,
		limits: limits,
		tools: map[string]tool{
			"read_file":     {arguments: []argumentSpec{{"path", true}}, run: readFile},
			"list_dir":      {arguments: []argumentSpec{{"path", false}}, run: listDir},
			"search_text":   {arguments: []argumentSpec{{"query", true}, {"path", false}}, run: searchText},
			"run_detectors": {arguments: []argumentSpec{{"path", true}}, run: runDetectors},
		},
	}
}

func (gateway *Gateway) Events() []Event {
	return append([]Event(nil), gateway.events...)
}

// Observe sets the function that sees every event. If it fails, the call fails too,
// so no result leaves the gateway without a log entry.
func (gateway *Gateway) Observe(observer func(Event) error) {
	gateway.observer = observer
}

func (gateway *Gateway) Call(ctx context.Context, toolName string, arguments map[string]any) (Result, error) {
	selected, known := gateway.tools[toolName]
	if !known {
		return gateway.finish("", Result{}, ErrUnknownTool)
	}

	if ctx.Err() != nil {
		return gateway.finish(toolName, Result{}, ErrCancelled)
	}

	validated, err := gateway.validate(selected.arguments, arguments)
	if err != nil {
		return gateway.finish(toolName, Result{}, err)
	}

	result, err := selected.run(ctx, gateway, validated)
	return gateway.finish(toolName, result, err)
}

func (gateway *Gateway) finish(toolName string, result Result, err error) (Result, error) {
	reason := "allowed"
	if err != nil {
		reason = err.Error()
	}

	event := Event{Tool: toolName, Allowed: err == nil, Reason: reason}
	gateway.events = append(gateway.events, event)

	if gateway.observer != nil {
		if observeErr := gateway.observer(event); observeErr != nil {
			return Result{}, ErrLogFailed
		}
	}
	if err != nil {
		return Result{}, err
	}

	return result, nil
}

func (gateway *Gateway) validate(specs []argumentSpec, arguments map[string]any) (map[string]string, error) {
	for name := range arguments {
		if !hasArgument(specs, name) {
			return nil, ErrInvalidArguments
		}
	}

	validated := make(map[string]string)

	for _, spec := range specs {
		value, present := arguments[spec.name]
		if !present {
			if spec.required {
				return nil, ErrInvalidArguments
			}
			continue
		}

		text, isText := value.(string)
		if !isText || len(text) > gateway.limits.MaxStringLength || strings.ContainsRune(text, 0) {
			return nil, ErrInvalidArguments
		}
		if spec.required && text == "" {
			return nil, ErrInvalidArguments
		}

		validated[spec.name] = text
	}

	return validated, nil
}

func hasArgument(specs []argumentSpec, name string) bool {
	for _, spec := range specs {
		if spec.name == name {
			return true
		}
	}

	return false
}
