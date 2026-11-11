package outbound

import (
	"context"
	"errors"

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
	defaultModel   string
	kind           clientKind
	local          bool
}

var descriptors = []descriptor{
	{id: "anthropic", name: "Anthropic", keyEnv: "ANTHROPIC_API_KEY", baseURL: anthropicclient.DefaultBaseURL, defaultModel: anthropicclient.DefaultModel, kind: kindAnthropic},
	{id: "openai", name: "OpenAI", keyEnv: "OPENAI_API_KEY", baseURL: "https://api.openai.com/v1", maxTokensField: "max_completion_tokens", kind: kindChatCompletions},
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

// Info is what a screen needs to let the user choose a provider.
type Info struct {
	ID    string
	Name  string
	Local bool
	// KeyEnv is the environment variable that holds the key. It is empty when no key is needed.
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
func NewProvider(id, apiKey, model string) (Provider, error) {
	return newAt(id, apiKey, model, "")
}

func NewAnthropic(apiKey, model string) (Provider, error) {
	return NewProvider("anthropic", apiKey, model)
}

func newAnthropicAt(apiKey, model, baseURL string) (Provider, error) {
	return newAt("anthropic", apiKey, model, baseURL)
}

// newAt lets a test point a provider at a fake server. Only the tests pass a base URL.
func newAt(id, apiKey, model, baseURL string) (Provider, error) {
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
	if baseURL == "" {
		baseURL = chosen.baseURL
	}
	switch chosen.kind {
	case kindAnthropic:
		client, err := anthropicclient.New(apiKey, model, baseURL)
		if err != nil {
			return nil, ErrInvalidSetup
		}

		return &wireProvider{name: chosen.name, send: client.Send}, nil
	default:
		client, err := openaicompat.New(openaicompat.Config{BaseURL: baseURL, APIKey: apiKey, Model: model, MaxTokensField: chosen.maxTokensField})
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

// String and GoString show the name and nothing else, so no setting can end up in a log line.
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

func fromWireError(err error) error {
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
