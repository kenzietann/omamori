package taskrun

import (
	"context"
	"errors"
	"testing"

	"github.com/kenzietann/omamori/internal/outbound"
)

func TestResolveProviderReusesSelectionWithoutSending(t *testing.T) {
	setup := newSetup(t)
	setup.config.LookupEnv = func(name string) string {
		if name == "OPENAI_API_KEY" {
			return "environment-key"
		}
		return ""
	}
	resolved, err := ResolveProvider(context.Background(), setup.config, Setup{ProviderID: "openai", Model: " fake-model ", Key: "typed-key"})
	if err != nil || resolved.Model != "fake-model" || resolved.ID != "openai" || resolved.Name != "FakeAI" || resolved.Provider != setup.provider {
		t.Fatalf("resolution: %#v, %v", resolved, err)
	}
	if len(*setup.calls) != 1 || (*setup.calls)[0].key != "typed-key" || len(setup.provider.recorded) != 0 {
		t.Fatal("provider resolution changed precedence or made a request")
	}
	_, err = ResolveProvider(context.Background(), setup.config, Setup{ProviderID: "openai", Model: "fake-model"})
	if err != nil || (*setup.calls)[1].key != "environment-key" {
		t.Fatal("environment key was not used")
	}
}

func TestResolveProviderRejectsANilProvider(t *testing.T) {
	setup := newSetup(t)
	setup.config.NewProvider = func(string, string, string, string) (outbound.Provider, error) { return nil, nil }
	if _, err := ResolveProvider(context.Background(), setup.config, Setup{ProviderID: "ollama", Model: "fake"}); !errors.Is(err, ErrSetup) {
		t.Fatalf("nil provider: %v", err)
	}
}
