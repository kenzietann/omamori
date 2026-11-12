package outbound

import (
	"context"
	"errors"
	"time"

	"github.com/kenzietann/omamori/internal/outbound/internal/anthropicclient"
	"github.com/kenzietann/omamori/internal/outbound/internal/openaicompat"
	"github.com/kenzietann/omamori/internal/outbound/internal/wire"
)

type clientKind int

const (
	kindAnthropic clientKind = iota
	kindChatCompletions
)

// descriptor is one provider. The address is fixed here and is never typed by a user,
// so a new place to send data is always a code change that a test and a reviewer see.
type descriptor struct {
	id             string
	name           string
	keyEnv         string
	baseURL        string
	maxTokensField string
	reasoningFallback string
	defaultModel      string
	kind              clientKind
	local             bool
}

var descriptors = []descriptor{
	{id: "anthropic", name: "Anthropic", keyEnv: "ANTHROPIC_API_KEY", baseURL: anthropicclient.DefaultBaseURL, defaultModel: anthropicclient.DefaultModel, kind: kindAnthropic},
	{id: "openai", name: "OpenAI", keyEnv: "OPENAI_API_KEY", baseURL: "https://api.openai.com/v1", maxTokensField: "max_completion_tokens", reasoningFallback: "none", kind: kindChatCompletions},
	{id: "gemini", name: "Google Gemini", keyEnv: "GEMINI_API_KEY", baseURL: "https://generativelanguage.googleapis.com/v1beta/openai", kind: kindChatCompletions},
	{id: "mistral", name: "Mistral", keyEnv: "MISTRAL_API_KEY", baseURL: "https://api.mistral.ai/v1", kind: kindChatCompletions},
	{id: "groq", name: "Groq", keyEnv: "GROQ_API_KEY", baseURL: "https://api.groq.com/openai/v1", kind: kindChatCompletions},
	{id: "together", name: "Together AI", keyEnv: "TOGETHER_API_KEY", baseURL: "https://api.together.xyz/v1", kind: kindChatCompletions},
	{id: "deepseek", name: "DeepSeek", keyEnv: "DEEPSEEK_API_KEY", baseURL: "https://api.deepseek.com", kind: kindChatCompletions},
	{id: "xai", name: "xAI", keyEnv: "XAI_API_KEY", baseURL: "https://api.x.ai/v1", kind: kindChatCompletions},
	{id: "openrouter", name: "OpenRouter", keyEnv: "OPENROUTER_API_KEY", baseURL: "https://openrouter.ai/api/v1", kind: kindChatCompletions},
	{id: "ollama", name: "Ollama (on this computer)", baseURL: "http://127.0.0.1:11434/v1", kind: kindChatCompletions, local: true},
	{id: "lmstudio", name: "LM Studio (on this computer)", baseURL: "http://127.0.0.1:1234/v1", kind: kindChatCompletions, local: true},
}

type Info struct {
	ID    string
	Name  string
	Local bool
	KeyEnv string
	// DefaultModel is empty when the user must choose the model.
	DefaultModel string
}

func Providers() []Info {
	infos := make([]Info, 0, len(descriptors))
	for _, current := range descriptors {
		infos = append(infos, Info{ID: current.id, Name: current.name, Local: current.local, KeyEnv: current.keyEnv, DefaultModel: current.defaultModel})
	}

	return infos
}

// NewProvider builds the provider with this ID. A model is required when the provider has no default,
// and a key is required unless the provider runs on this computer. The clients enforce both.
// A reasoning level must be one that ReasoningOptions names for this model, or empty.
func NewProvider(id, apiKey, model, reasoning string) (Provider, error) {
	return newWith(id, apiKey, model, "", reasoning)
}

const listTimeout = 20 * time.Second

// ListModels asks the provider which models it offers. It sends only the key, never project data,
// so it needs no consent and does not go through the sender.
func ListModels(ctx context.Context, id, apiKey string) ([]string, error) {
	return listAt(ctx, id, apiKey, "")
}

func listAt(ctx context.Context, id, apiKey, baseURL string) ([]string, error) {
	var chosen *descriptor
	for index := range descriptors {
		if descriptors[index].id == id {
			chosen = &descriptors[index]
		}
	}
	if chosen == nil {
		return nil, ErrInvalidSetup
	}
	if baseURL == "" {
		baseURL = chosen.baseURL
	}

	var models []string
	var err error
	if chosen.kind == kindAnthropic {
		models, err = anthropicclient.ListModels(ctx, apiKey, baseURL, listTimeout)
	} else {
		models, err = openaicompat.ListModels(ctx, baseURL, apiKey, listTimeout)
	}
	if err != nil {
		return nil, fromWireError(err)
	}

	return models, nil
}

func NewAnthropic(apiKey, model string) (Provider, error) {
	return NewProvider("anthropic", apiKey, model, "")
}

func newAnthropicAt(apiKey, model, baseURL string) (Provider, error) {
	return newAt("anthropic", apiKey, model, baseURL)
}

func newAt(id, apiKey, model, baseURL string) (Provider, error) {
	return newWith(id, apiKey, model, baseURL, "")
}

func newWith(id, apiKey, model, baseURL, reasoning string) (Provider, error) {
	var chosen *descriptor
	for index := range descriptors {
		if descriptors[index].id == id {
			chosen = &descriptors[index]
		}
	}
	if chosen == nil {
		return nil, ErrInvalidSetup
	}

	if model == "" {
		model = chosen.defaultModel
	}
	if !ValidReasoning(id, model, reasoning) {
		return nil, ErrInvalidSetup
	}
	if baseURL == "" {
		baseURL = chosen.baseURL
	}
	switch chosen.kind {
	case kindAnthropic:
		client, err := anthropicclient.New(apiKey, model, baseURL)
		if err != nil || client.SetEffort(reasoning) != nil {
			return nil, ErrInvalidSetup
		}

		return &wireProvider{name: chosen.name, send: client.Send}, nil
	default:
		client, err := openaicompat.New(openaicompat.Config{BaseURL: baseURL, APIKey: apiKey, Model: model, MaxTokensField: chosen.maxTokensField, ReasoningFallback: chosen.reasoningFallback, Reasoning: reasoning})
		if err != nil {
			return nil, ErrInvalidSetup
		}

		return &wireProvider{name: chosen.name, send: client.Send}, nil
	}
}

type wireProvider struct {
	name string
	send func(ctx context.Context, request wire.Request) (wire.Response, error)
}

func (provider *wireProvider) String() string   { return "provider{" + provider.name + "}" }
func (provider *wireProvider) GoString() string { return provider.String() }

func (provider *wireProvider) Name() string { return provider.name }

func (provider *wireProvider) Send(ctx context.Context, safe SafeRequest) (Response, error) {
	response, err := provider.send(ctx, toWireRequest(safe.Request()))
	if err != nil {
		return Response{}, fromWireError(err)
	}

	converted := Response{Text: response.Text, TokensUsed: response.TokensUsed}
	for _, call := range response.ToolCalls {
		converted.ToolCalls = append(converted.ToolCalls, ToolCall{ID: call.ID, Name: call.Name, Arguments: call.Arguments})
	}

	return converted, nil
}

type ProviderError struct {
	Detail string
}

func (providerError *ProviderError) Error() string {
	return ErrProviderFailed.Error() + " (" + providerError.Detail + ")"
}
func (providerError *ProviderError) Unwrap() error { return ErrProviderFailed }

func DetailOf(err error) string {
	var providerError *ProviderError
	if errors.As(err, &providerError) {
		return providerError.Detail
	}

	return ""
}

func fromWireError(err error) error {
	var rejection *wire.Rejection
	if errors.As(err, &rejection) {
		return &ProviderError{Detail: rejection.Detail()}
	}

	switch {
	case errors.Is(err, wire.ErrRetryable):
		return ErrTemporary
	case errors.Is(err, wire.ErrAuth):
		return ErrAuth
	case errors.Is(err, wire.ErrRefused):
		return ErrRefused
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	}

	return ErrProviderFailed
}

func toWireRequest(request Request) wire.Request {
	converted := wire.Request{System: request.System}

	for _, message := range request.Messages {
		convertedMessage := wire.Message{Role: message.Role, Text: message.Text, ToolCallID: message.ToolCallID}
		for _, call := range message.ToolCalls {
			convertedMessage.ToolCalls = append(convertedMessage.ToolCalls, wire.ToolCall{ID: call.ID, Name: call.Name, Arguments: call.Arguments})
		}
		converted.Messages = append(converted.Messages, convertedMessage)
	}

	for _, spec := range request.Tools {
		tool := wire.Tool{Name: spec.Name, Description: spec.Description}
		for _, parameter := range spec.Parameters {
			tool.Parameters = append(tool.Parameters, wire.Parameter{Name: parameter.Name, Description: parameter.Description, Required: parameter.Required})
		}
		converted.Tools = append(converted.Tools, tool)
	}

	return converted
}
