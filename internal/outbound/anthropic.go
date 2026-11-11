package outbound

import (
	"context"
	"errors"

	"github.com/kenzietann/omamori/internal/outbound/internal/anthropicclient"
)

type anthropicProvider struct {
	client *anthropicclient.Client
}

// NewAnthropic is the only way to reach the provider. The client lives in a nested internal
// package, so the compiler stops any other package from importing it.
func NewAnthropic(apiKey, model string) (Provider, error) {
	return newAnthropicAt(apiKey, model, "")
}

func newAnthropicAt(apiKey, model, baseURL string) (Provider, error) {
	client, err := anthropicclient.New(apiKey, model, baseURL)
	if err != nil {
		return nil, ErrInvalidSetup
	}

	return &anthropicProvider{client: client}, nil
}

func (provider *anthropicProvider) Name() string { return "Anthropic" }

func (provider *anthropicProvider) Send(ctx context.Context, safe SafeRequest) (Response, error) {
	response, err := provider.client.Send(ctx, toClientRequest(safe.Request()))
	if err != nil {
		return Response{}, fromClientError(err)
	}

	converted := Response{Text: response.Text, TokensUsed: response.TokensUsed}
	for _, call := range response.ToolCalls {
		converted.ToolCalls = append(converted.ToolCalls, ToolCall{ID: call.ID, Name: call.Name, Arguments: call.Arguments})
	}

	return converted, nil
}

func fromClientError(err error) error {
	switch {
	case errors.Is(err, anthropicclient.ErrRetryable):
		return ErrTemporary
	case errors.Is(err, anthropicclient.ErrAuth):
		return ErrAuth
	case errors.Is(err, anthropicclient.ErrRefused):
		return ErrRefused
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	}

	return ErrProviderFailed
}

func toClientRequest(request Request) anthropicclient.Request {
	converted := anthropicclient.Request{System: request.System}

	for _, message := range request.Messages {
		convertedMessage := anthropicclient.Message{Role: message.Role, Text: message.Text, ToolCallID: message.ToolCallID}
		for _, call := range message.ToolCalls {
			convertedMessage.ToolCalls = append(convertedMessage.ToolCalls, anthropicclient.ToolCall{ID: call.ID, Name: call.Name, Arguments: call.Arguments})
		}
		converted.Messages = append(converted.Messages, convertedMessage)
	}

	for _, spec := range request.Tools {
		tool := anthropicclient.Tool{Name: spec.Name, Description: spec.Description}
		for _, parameter := range spec.Parameters {
			tool.Parameters = append(tool.Parameters, anthropicclient.Parameter{Name: parameter.Name, Description: parameter.Description, Required: parameter.Required})
		}
		converted.Tools = append(converted.Tools, tool)
	}

	return converted
}
