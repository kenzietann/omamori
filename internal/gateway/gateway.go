package gateway

import (
	"context"
	"errors"
	"slices"
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
	name        string
	description string
	required    bool
}

type tool struct {
	description string
	arguments   []argumentSpec
	run         func(ctx context.Context, gateway *Gateway, arguments map[string]string) (Result, error)
}

type ParameterSpec struct {
	Name        string
	Description string
	Required    bool
}

type Spec struct {
	Name        string
	Description string
	Parameters  []ParameterSpec
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
			"read_file": {
				description: "Read one text file inside the project. The text is cut at a size limit.",
				arguments:   []argumentSpec{{name: "path", description: "File path relative to the project folder.", required: true}},
				run:         readFile,
			},
			"list_dir": {
				description: "List the files and folders in one folder of the project.",
				arguments:   []argumentSpec{{name: "path", description: "Folder path relative to the project folder. The default is the project folder."}},
				run:         listDir,
			},
			"search_text": {
				description: "Search for a text in the files of the project. Returns file names, line numbers and short lines.",
				arguments: []argumentSpec{
					{name: "query", description: "The text to look for.", required: true},
					{name: "path", description: "Folder or file to search in. The default is the project folder."},
				},
				run: searchText,
			},
			"run_detectors": {
				description: "Scan a file or a folder for secrets, My Number and Japanese phone numbers. Returns only placeholders, file names and line numbers, never the values.",
				arguments:   []argumentSpec{{name: "path", description: "File or folder path relative to the project folder. Use \".\" for the whole project.", required: true}},
				run:         runDetectors,
			},
		},
	}
}

// Specs describes the tools in a fixed order. The order must not change between requests,
// because the model's cached prefix includes the tool list.
func (gateway *Gateway) Specs() []Spec {
	names := make([]string, 0, len(gateway.tools))
	for name := range gateway.tools {
		names = append(names, name)
	}
	slices.Sort(names)

	specs := make([]Spec, 0, len(names))
	for _, name := range names {
		selected := gateway.tools[name]
		spec := Spec{Name: name, Description: selected.description}
		for _, argument := range selected.arguments {
			spec.Parameters = append(spec.Parameters, ParameterSpec{Name: argument.name, Description: argument.description, Required: argument.required})
		}
		specs = append(specs, spec)
	}

	return specs
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
