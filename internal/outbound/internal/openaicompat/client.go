// Package openaicompat talks to every provider that offers the "chat completions" protocol.
// It uses only the standard library. Each provider is a fixed preset chosen by outbound,
// never an address that a user types.
package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/outbound/internal/wire"
)

const (
	maxOutputTokens = 16000
	requestTimeout  = 5 * time.Minute
	maxFailureBytes = 64 << 10
)

var levelPattern = regexp.MustCompile(`^[a-z]{3,10}$`)

type Config struct {
	BaseURL string
	APIKey  string
	Model   string
	// MaxTokensField is the name of the output limit. Newer OpenAI models want
	// max_completion_tokens, and most other providers still want max_tokens.
	MaxTokensField string
	// ReasoningFallback is a value for reasoning_effort. It is used only when the provider rejects
	// a request and names reasoning_effort as the cause. Some OpenAI models reason by default and
	// then refuse tools on this protocol, unless reasoning is turned off.
	ReasoningFallback string
	// Reasoning is a level the user chose. It is sent as reasoning_effort on every request.
	Reasoning string
	Timeout   time.Duration
}

type Client struct {
	endpoint       string
	apiKey         string
	model          string
	maxTokensField string
	fallbackEffort string
	// effort is set after the fallback worked, so later requests do not fail first.
	effort string
	http   *http.Client
}

func New(config Config) (*Client, error) {
	if config.Model == "" || !wire.SafeBaseURL(config.BaseURL) {
		return nil, wire.ErrBadConfig
	}
	parsed, err := url.Parse(config.BaseURL)
	if err != nil {
		return nil, wire.ErrBadConfig
	}
	// Only a provider on this same machine may work without a key.
	if config.APIKey == "" && !wire.IsLoopback(parsed) {
		return nil, wire.ErrNoKey
	}
	if config.MaxTokensField == "" {
		config.MaxTokensField = "max_tokens"
	}
	if config.Reasoning != "" && !levelPattern.MatchString(config.Reasoning) {
		return nil, wire.ErrBadConfig
	}
	if config.Timeout == 0 {
		config.Timeout = requestTimeout
	}

	return &Client{
		endpoint:       strings.TrimRight(config.BaseURL, "/") + "/chat/completions",
		apiKey:         config.APIKey,
		model:          config.Model,
		maxTokensField: config.MaxTokensField,
		fallbackEffort: config.ReasoningFallback,
		effort:         config.Reasoning,
		http:           wire.NewHTTPClient(config.Timeout),
	}, nil
}

// String and GoString keep the key out of a log line, because they are what fmt uses.
func (client *Client) String() string   { return "openaicompat.Client{model: " + client.model + "}" }
func (client *Client) GoString() string { return client.String() }

type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content   string         `json:"content"`
			Refusal   string         `json:"refusal"`
			ToolCalls []chatToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (client *Client) Send(ctx context.Context, request wire.Request) (wire.Response, error) {
	response, err := client.exchange(ctx, request)

	var rejection *wire.Rejection
	if client.fallbackEffort == "" || client.effort != "" || !errors.As(err, &rejection) || rejection.Param != "reasoning_effort" {
		return response, err
	}

	// The same cleaned request is sent again, with one setting added.
	client.effort = client.fallbackEffort
	response, err = client.exchange(ctx, request)
	if err != nil {
		client.effort = ""
	}

	return response, err
}

func (client *Client) exchange(ctx context.Context, request wire.Request) (wire.Response, error) {
	body, err := client.buildBody(request)
	if err != nil {
		return wire.Response{}, err
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(body))
	if err != nil {
		return wire.Response{}, wire.ErrBadConfig
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	if client.apiKey != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+client.apiKey)
	}

	httpResponse, err := client.http.Do(httpRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return wire.Response{}, context.Canceled
		}

		// A timeout or a broken connection is worth another try.
		return wire.Response{}, wire.ErrRetryable
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 299 {
		failure, _ := io.ReadAll(io.LimitReader(httpResponse.Body, maxFailureBytes))

		return wire.Response{}, wire.StatusErrorWithBody(httpResponse.StatusCode, failure)
	}

	answer, err := io.ReadAll(io.LimitReader(httpResponse.Body, wire.MaxResponseBytes+1))
	if err != nil {
		return wire.Response{}, wire.ErrRetryable
	}
	if len(answer) > wire.MaxResponseBytes {
		return wire.Response{}, wire.ErrBadResponse
	}

	return parseResponse(answer)
}

func (client *Client) buildBody(request wire.Request) ([]byte, error) {
	messages, err := buildMessages(request)
	if err != nil {
		return nil, err
	}

	body := map[string]any{
		"model":               client.model,
		"messages":            messages,
		client.maxTokensField: maxOutputTokens,
	}
	if tools := buildTools(request.Tools); len(tools) > 0 {
		body["tools"] = tools
	}
	if client.effort != "" {
		body["reasoning_effort"] = client.effort
	}

	return json.Marshal(body)
}

func buildMessages(request wire.Request) ([]chatMessage, error) {
	var built []chatMessage
	if request.System != "" {
		built = append(built, chatMessage{Role: "system", Content: request.System})
	}

	var notes []chatMessage
	for _, message := range request.Messages {
		// The results of one turn must stay together, so notes wait until that run is over.
		if message.Role != "tool" {
			built = append(built, flushNotes(&notes)...)
		}

		switch message.Role {
		case "user":
			built = append(built, chatMessage{Role: "user", Content: wire.NonEmpty(message.Text)})
		case "assistant":
			converted := chatMessage{Role: "assistant", Content: message.Text}
			for _, call := range message.ToolCalls {
				if call.ID == "" {
					return nil, wire.ErrBadRequest
				}
				arguments, err := json.Marshal(call.Arguments)
				if err != nil {
					return nil, wire.ErrBadRequest
				}
				toolCall := chatToolCall{ID: call.ID, Type: "function"}
				toolCall.Function.Name = call.Name
				toolCall.Function.Arguments = string(arguments)
				converted.ToolCalls = append(converted.ToolCalls, toolCall)
			}
			if converted.Content != "" || len(converted.ToolCalls) > 0 {
				built = append(built, converted)
			}
		case "tool":
			// A result must answer a real tool call. A note about a call that was dropped
			// goes in as a user message after the results.
			if message.ToolCallID != "" {
				built = append(built, chatMessage{Role: "tool", ToolCallID: message.ToolCallID, Content: wire.NonEmpty(message.Text)})
			} else {
				notes = append(notes, chatMessage{Role: "user", Content: wire.NonEmpty(message.Text)})
			}
		default:
			return nil, wire.ErrBadRequest
		}
	}

	return append(built, flushNotes(&notes)...), nil
}

func flushNotes(notes *[]chatMessage) []chatMessage {
	flushed := *notes
	*notes = nil

	return flushed
}

func buildTools(tools []wire.Tool) []map[string]any {
	var built []map[string]any

	for _, tool := range tools {
		properties := make(map[string]any, len(tool.Parameters))
		required := []string{}
		for _, parameter := range tool.Parameters {
			properties[parameter.Name] = map[string]any{"type": "string", "description": parameter.Description}
			if parameter.Required {
				required = append(required, parameter.Name)
			}
		}

		built = append(built, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        tool.Name,
				"description": tool.Description,
				"parameters": map[string]any{
					"type":                 "object",
					"properties":           properties,
					"required":             required,
					"additionalProperties": false,
				},
			},
		})
	}

	return built
}

func parseResponse(answer []byte) (wire.Response, error) {
	var decoded chatResponse
	if err := json.Unmarshal(answer, &decoded); err != nil || len(decoded.Choices) == 0 {
		return wire.Response{}, wire.ErrBadResponse
	}

	choice := decoded.Choices[0]
	if choice.FinishReason == "content_filter" || choice.Message.Refusal != "" {
		return wire.Response{}, wire.ErrRefused
	}

	response := wire.Response{Text: choice.Message.Content, TokensUsed: decoded.Usage.PromptTokens + decoded.Usage.CompletionTokens}
	for _, call := range choice.Message.ToolCalls {
		response.ToolCalls = append(response.ToolCalls, wire.ToolCall{ID: call.ID, Name: call.Function.Name, Arguments: wire.ParseArguments(call.Function.Arguments)})
	}

	// A cut-off answer may hold a tool call with an unfinished input, so it is not used.
	if choice.FinishReason == "length" && len(response.ToolCalls) > 0 {
		return wire.Response{}, wire.ErrBadResponse
	}

	return response, nil
}

// ListModels asks the provider which models it offers. No project data is sent, only the key.
func ListModels(ctx context.Context, baseURL, apiKey string, timeout time.Duration) ([]string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || !wire.SafeBaseURL(baseURL) {
		return nil, wire.ErrBadConfig
	}
	if apiKey == "" && !wire.IsLoopback(parsed) {
		return nil, wire.ErrNoKey
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/models", nil)
	if err != nil {
		return nil, wire.ErrBadConfig
	}
	httpRequest.Header.Set("Accept", "application/json")
	if apiKey != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+apiKey)
	}

	httpResponse, err := wire.NewHTTPClient(timeout).Do(httpRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}

		return nil, wire.ErrRetryable
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 299 {
		return nil, wire.StatusError(httpResponse.StatusCode)
	}
	answer, err := io.ReadAll(io.LimitReader(httpResponse.Body, wire.MaxResponseBytes+1))
	if err != nil || len(answer) > wire.MaxResponseBytes {
		return nil, wire.ErrBadResponse
	}

	var decoded struct {
		Data []struct {
			ID string `json:"id"`
			// Some providers (Mistral) say what each model can do. A model that cannot chat or
			// cannot call tools is no use here, because the agent needs both.
			Capabilities map[string]any `json:"capabilities"`
		} `json:"data"`
	}
	if err := json.Unmarshal(answer, &decoded); err != nil {
		return nil, wire.ErrBadResponse
	}

	ids := make([]string, 0, len(decoded.Data))
	for _, entry := range decoded.Data {
		if entry.Capabilities["completion_chat"] == false || entry.Capabilities["function_calling"] == false {
			continue
		}
		ids = append(ids, entry.ID)
	}

	return wire.CleanModelIDs(ids), nil
}
