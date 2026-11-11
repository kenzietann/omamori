package anthropicclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

const (
	DefaultBaseURL = "https://api.anthropic.com"
	DefaultModel   = "claude-opus-5-5"

	maxOutputTokens = 16000
	requestTimeout  = 5 * time.Minute
)

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

type Client struct {
	api   anthropic.Client
	model string
}

func New(apiKey, model, baseURL string) (*Client, error) {
	return newClient(apiKey, model, baseURL, requestTimeout)
}

func newClient(apiKey, model, baseURL string, timeout time.Duration) (*Client, error) {
	if apiKey == "" {
		return nil, ErrNoKey
	}
	if model == "" {
		model = DefaultModel
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if !safeBaseURL(baseURL) {
		return nil, ErrBadConfig
	}

	// A redirect would forward the x-api-key header to another host, because Go only
	// removes the Authorization header. So no redirect is followed.
	httpClient := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// WithoutEnvironmentDefaults keeps ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN, the profile
	// files and ANTHROPIC_CUSTOM_HEADERS from changing where the request goes.
	// Retries are off, because the sender owns them: it cleans the request again and counts each one.
	api := anthropic.NewClient(
		option.WithoutEnvironmentDefaults(),
		option.WithAPIKey(apiKey),
		option.WithBaseURL(baseURL),
		option.WithMaxRetries(0),
		option.WithHTTPClient(httpClient),
	)

	return &Client{api: api, model: model}, nil
}

func safeBaseURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}

	host, _, splitErr := net.SplitHostPort(parsed.Host)
	if splitErr != nil {
		host = parsed.Hostname()
	}

	return parsed.Scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1")
}

// String and GoString keep the key out of a log line, because they are what fmt uses.
func (client *Client) String() string   { return "anthropicclient.Client{model: " + client.model + "}" }
func (client *Client) GoString() string { return client.String() }

func (client *Client) Send(ctx context.Context, request Request) (Response, error) {
	params, err := buildParams(client.model, request)
	if err != nil {
		return Response{}, err
	}

	message, err := client.api.Messages.New(ctx, params)
	if err != nil {
		return Response{}, classify(err)
	}

	return parseResponse(message)
}

func classify(err error) error {
	var apiError *anthropic.Error
	if errors.As(err, &apiError) {
		switch status := apiError.StatusCode; {
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			return ErrAuth
		case status == http.StatusRequestTimeout || status == http.StatusConflict || status == http.StatusTooManyRequests || status >= 500:
			return ErrRetryable
		}

		return ErrRejected
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}

	// A timeout or a broken connection is worth another try.
	return ErrRetryable
}

func buildParams(model string, request Request) (anthropic.MessageNewParams, error) {
	messages, err := buildMessages(request.Messages)
	if err != nil {
		return anthropic.MessageNewParams{}, err
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: maxOutputTokens,
		Messages:  messages,
		Tools:     buildTools(request.Tools),
		// Thinking is always on for this model, so only the effort is set, and it is set on purpose
		// because the default changed between models.
		OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffortMedium},
		// The system prompt, the tools and the earlier turns are the same on every request, so the provider can reuse them.
		CacheControl: anthropic.NewCacheControlEphemeralParam(),
	}
	if request.System != "" {
		params.System = []anthropic.TextBlockParam{{Text: request.System}}
	}

	return params, nil
}

func nonEmpty(text string) string {
	if text == "" {
		return "(empty)"
	}

	return text
}

func buildMessages(messages []Message) ([]anthropic.MessageParam, error) {
	var built []anthropic.MessageParam

	for index := 0; index < len(messages); {
		switch message := messages[index]; message.Role {
		case "user":
			built = append(built, anthropic.NewUserMessage(anthropic.NewTextBlock(nonEmpty(message.Text))))
			index++
		case "assistant":
			var blocks []anthropic.ContentBlockParamUnion
			if message.Text != "" {
				blocks = append(blocks, anthropic.NewTextBlock(message.Text))
			}
			for _, call := range message.ToolCalls {
				if call.ID == "" {
					return nil, ErrBadRequest
				}
				blocks = append(blocks, anthropic.NewToolUseBlock(call.ID, stringsToAny(call.Arguments), call.Name))
			}
			if len(blocks) > 0 {
				built = append(built, anthropic.NewAssistantMessage(blocks...))
			}
			index++
		case "tool":
			// All results of one turn go in one user message, and the results come before any text.
			var results, notes []anthropic.ContentBlockParamUnion
			for ; index < len(messages) && messages[index].Role == "tool"; index++ {
				if messages[index].ToolCallID != "" {
					results = append(results, anthropic.NewToolResultBlock(messages[index].ToolCallID, nonEmpty(messages[index].Text), false))
				} else {
					notes = append(notes, anthropic.NewTextBlock(nonEmpty(messages[index].Text)))
				}
			}
			built = append(built, anthropic.NewUserMessage(append(results, notes...)...))
		default:
			return nil, ErrBadRequest
		}
	}

	return built, nil
}

func stringsToAny(arguments map[string]string) map[string]any {
	converted := make(map[string]any, len(arguments))
	for name, value := range arguments {
		converted[name] = value
	}

	return converted
}

func buildTools(tools []Tool) []anthropic.ToolUnionParam {
	var built []anthropic.ToolUnionParam

	for _, tool := range tools {
		properties := make(map[string]any, len(tool.Parameters))
		var required []string
		for _, parameter := range tool.Parameters {
			properties[parameter.Name] = map[string]any{"type": "string", "description": parameter.Description}
			if parameter.Required {
				required = append(required, parameter.Name)
			}
		}

		param := anthropic.ToolParam{
			Name:        tool.Name,
			Description: anthropic.String(tool.Description),
			Strict:      anthropic.Bool(true),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties:  properties,
				Required:    required,
				ExtraFields: map[string]any{"additionalProperties": false},
			},
		}
		built = append(built, anthropic.ToolUnionParam{OfTool: &param})
	}

	return built
}

func parseResponse(message *anthropic.Message) (Response, error) {
	switch message.StopReason {
	case anthropic.StopReasonRefusal:
		return Response{}, ErrRefused
	case anthropic.StopReasonModelContextWindowExceeded:
		return Response{}, ErrRejected
	}

	var response Response
	var texts []string

	for _, block := range message.Content {
		switch variant := block.AsAny().(type) {
		case anthropic.TextBlock:
			texts = append(texts, variant.Text)
		case anthropic.ToolUseBlock:
			response.ToolCalls = append(response.ToolCalls, ToolCall{ID: variant.ID, Name: variant.Name, Arguments: parseArguments(variant.JSON.Input.Raw())})
		}
	}

	// A cut-off answer may hold a tool call with an unfinished input, so it is not used.
	if message.StopReason == anthropic.StopReasonMaxTokens && len(response.ToolCalls) > 0 {
		return Response{}, ErrBadResponse
	}

	response.Text = strings.Join(texts, "\n\n")
	response.TokensUsed = int(message.Usage.InputTokens + message.Usage.OutputTokens + message.Usage.CacheCreationInputTokens + message.Usage.CacheReadInputTokens)

	return response, nil
}

// The tools take only text arguments. A value of another type is kept as its JSON text,
// so the gateway, which checks every argument, decides what to do with it.
func parseArguments(raw string) map[string]string {
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
