package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

const adapterKey = "sk-ant-api03-FAKEKEYFAKEKEYFAKEKEY"

type fakeProvider struct {
	requests int
}

func (provider *fakeProvider) Name() string { return "FakeAI" }

func (provider *fakeProvider) Send(ctx context.Context, safe outbound.SafeRequest) (outbound.Response, error) {
	provider.requests++
	if provider.requests == 1 {
		return outbound.Response{ToolCalls: []outbound.ToolCall{{ID: "c1", Name: "run_detectors", Arguments: map[string]string{"path": "."}}}}, nil
	}

	return outbound.Response{Text: "done"}, nil
}

func newTestBackend(t testing.TB) (backend, *fakeProvider, string) {
	t.Helper()

	project, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "exposure", "project"))
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeProvider{}
	output := filepath.Join(t.TempDir(), "out")

	return backend{config: taskrun.Config{
		Target: project, OutputBase: output, Limits: agent.Limits{MaxSteps: 10, MaxTokens: 100000},
		LookupEnv:   func(name string) string { return map[string]string{"OPENAI_API_KEY": "sk-from-environment"}[name] },
		Now:         func() time.Time { return time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC) },
		NewProvider: func(id, key, model string) (outbound.Provider, error) { return provider, nil },
	}}, provider, output
}

func TestTheAdapterListsTheProviders(t *testing.T) {
	adapter, _, _ := newTestBackend(t)

	choices := adapter.Providers()

	if len(choices) != len(outbound.Providers()) {
		t.Fatalf("%d providers, want %d", len(choices), len(outbound.Providers()))
	}
	byID := map[string]tui.Choice{}
	for _, choice := range choices {
		byID[choice.ID] = choice
	}
	if !byID["openai"].KeyFound || byID["anthropic"].KeyFound || !byID["ollama"].Local || byID["anthropic"].DefaultModel != "claude-opus-5-5" || byID["openai"].KeyEnv != "OPENAI_API_KEY" || byID["anthropic"].Name != "Anthropic" {
		t.Errorf("the choices were converted wrongly: %+v", byID)
	}
}

func TestThePlanIsConfirmedAndRunThroughTheAdapter(t *testing.T) {
	adapter, provider, output := newTestBackend(t)

	plan, err := adapter.Prepare(tui.Setup{ProviderID: "anthropic", Key: adapterKey})
	if err != nil {
		t.Fatal(err)
	}

	if plan.ConsentText != "Omamori will send sanitized content to FakeAI during this run." || !strings.Contains(plan.Preview, "System prompt:") || plan.Confirm == nil || plan.Run == nil {
		t.Fatalf("the plan is wrong: %+v", plan)
	}
	if provider.requests != 0 {
		t.Error("preparing sent a request")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Error("preparing created the output folder")
	}

	if _, err := plan.Run(context.Background(), func(string) {}); !errors.Is(err, taskrun.ErrNotConfirmed) {
		t.Errorf("a run without confirmation: err = %v, want ErrNotConfirmed", err)
	}

	plan.Confirm()
	var steps []string
	result, err := plan.Run(context.Background(), func(text string) { steps = append(steps, text) })
	if err != nil {
		t.Fatal(err)
	}

	if !result.Complete || !strings.Contains(result.Report, "[SECRET:aws-access-key:001]") || !strings.HasPrefix(result.SavedTo, output) || len(steps) == 0 || provider.requests != 2 {
		t.Errorf("result = %+v, steps = %d, requests = %d", result, len(steps), provider.requests)
	}
	if _, err := os.Stat(filepath.Join(result.SavedTo, "report.md")); err != nil {
		t.Errorf("the report is not saved: %v", err)
	}
}

func TestTheAdapterPassesSetupErrorsOn(t *testing.T) {
	adapter, _, _ := newTestBackend(t)

	testCases := []struct {
		name    string
		setup   tui.Setup
		wantErr error
	}{
		{"no key", tui.Setup{ProviderID: "anthropic"}, taskrun.ErrNeedsKey},
		{"no model", tui.Setup{ProviderID: "mistral", Key: adapterKey}, taskrun.ErrNeedsModel},
		{"unknown provider", tui.Setup{ProviderID: "nope", Key: adapterKey}, taskrun.ErrUnknownProvider},
	}
	for _, testCase := range testCases {
		_, err := adapter.Prepare(testCase.setup)

		if !errors.Is(err, testCase.wantErr) || strings.Contains(err.Error(), adapterKey) {
			t.Errorf("%s: err = %v, want %v", testCase.name, err, testCase.wantErr)
		}
	}

	if _, err := adapter.Prepare(tui.Setup{ProviderID: "openai", Model: "m"}); err != nil {
		t.Errorf("a key from the environment was not used: %v", err)
	}
}

func TestTheAdapterListsModelsWithTheTypedKeyOrTheEnvironmentKey(t *testing.T) {
	adapter, _, _ := newTestBackend(t)
	var gotKey string
	adapter.config.ListModels = func(ctx context.Context, id, key string) ([]string, error) {
		gotKey = key
		return []string{"model-a"}, nil
	}

	if models, err := adapter.Models(context.Background(), "openai", ""); err != nil || len(models) != 1 || gotKey != "sk-from-environment" {
		t.Errorf("models = %q, err = %v, key = %q", models, err, gotKey)
	}
	if _, err := adapter.Models(context.Background(), "openai", "typed"); err != nil || gotKey != "typed" {
		t.Errorf("err = %v, key = %q", err, gotKey)
	}
	if _, err := adapter.Models(context.Background(), "anthropic", ""); !errors.Is(err, taskrun.ErrNeedsKey) {
		t.Errorf("err = %v, want a missing key", err)
	}
}
