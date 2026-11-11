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
		NewProvider: func(id, key, model, reasoning string) (outbound.Provider, error) { return provider, nil },
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

func TestTheAdapterPassesTheReasoningLevelOn(t *testing.T) {
	adapter, _, _ := newTestBackend(t)
	var gotReasoning []string
	adapter.config.NewProvider = func(id, key, model, reasoning string) (outbound.Provider, error) {
		gotReasoning = append(gotReasoning, reasoning)
		return &fakeProvider{}, nil
	}

	for _, level := range []string{"", "high"} {
		if _, err := adapter.Prepare(tui.Setup{ProviderID: "anthropic", Key: adapterKey, Reasoning: level}); err != nil {
			t.Fatal(err)
		}
	}

	if len(gotReasoning) != 2 || gotReasoning[0] != "" || gotReasoning[1] != "high" {
		t.Errorf("the provider got %q", gotReasoning)
	}
}

func TestTheAdapterListsTheReasoningChoicesOfTheCore(t *testing.T) {
	adapter, _, _ := newTestBackend(t)

	choices := adapter.ReasoningChoices("anthropic", "claude-opus-5-5")

	if len(choices) < 2 || choices[0].Value != "" || choices[len(choices)-1].Value != "max" {
		t.Errorf("choices = %+v", choices)
	}
	if got := adapter.ReasoningChoices("openai", "gpt-5.5"); len(got) != 0 {
		t.Errorf("openai: %+v", got)
	}
}

type memoryKeys struct {
	saved     map[string]string
	available bool
	failSet   bool
}

func (keys *memoryKeys) Available() bool { return keys.available }

func (keys *memoryKeys) Get(ctx context.Context, providerID string) (string, error) {
	if key, found := keys.saved[providerID]; found {
		return key, nil
	}

	return "", errors.New("none")
}

func (keys *memoryKeys) Set(ctx context.Context, providerID, key string) error {
	if keys.failSet {
		return errors.New("boom " + key)
	}
	keys.saved[providerID] = key

	return nil
}

func (keys *memoryKeys) Delete(ctx context.Context, providerID string) error {
	delete(keys.saved, providerID)

	return nil
}

func TestTheAdapterSavesAndForgetsKeysAndSaysIfItCan(t *testing.T) {
	adapter, _, _ := newTestBackend(t)
	if adapter.KeysCanBeSaved() {
		t.Error("an adapter without a store says it can save keys")
	}

	keys := &memoryKeys{saved: map[string]string{}, available: true}
	adapter.config.Keys = keys
	if !adapter.KeysCanBeSaved() {
		t.Fatal("an adapter with a store cannot save keys")
	}
	if err := adapter.SaveKey(context.Background(), "openai", adapterKey); err != nil || keys.saved["openai"] != adapterKey {
		t.Fatalf("err = %v, saved = %v", err, keys.saved)
	}
	var found bool
	for _, choice := range adapter.Providers() {
		if choice.ID == "anthropic" && choice.KeySaved {
			t.Error("a provider without a saved key is marked as saved")
		}
		found = found || (choice.ID == "openai" && choice.KeyFound)
	}
	if !found {
		t.Error("the key in the environment is not seen")
	}

	delete(keys.saved, "openai")
	keys.saved["gemini"] = adapterKey
	for _, choice := range adapter.Providers() {
		if choice.ID == "gemini" && !choice.KeySaved {
			t.Error("a saved key is not shown")
		}
	}
	if err := adapter.ForgetKey("gemini"); err != nil || len(keys.saved) != 0 {
		t.Errorf("err = %v, saved = %v", err, keys.saved)
	}

	keys.failSet = true
	if err := adapter.SaveKey(context.Background(), "openai", adapterKey); err == nil || strings.Contains(err.Error(), adapterKey) {
		t.Errorf("err = %v", err)
	}
}

func TestTheAdapterTurnsARejectedKeyIntoTheScreensError(t *testing.T) {
	adapter, _, _ := newTestBackend(t)
	adapter.config.ListModels = func(context.Context, string, string) ([]string, error) { return nil, outbound.ErrAuth }

	_, err := adapter.Models(context.Background(), "openai", "")

	if !errors.Is(err, tui.ErrKeyRejected) {
		t.Errorf("err = %v", err)
	}
}

func TestTheAdapterSavesSettingsToTheFileAndNeverAKey(t *testing.T) {
	adapter, _, _ := newTestBackend(t)
	if err := adapter.SaveSettings(tui.Defaults{ProviderID: "openai"}); err == nil {
		t.Error("settings were saved without a place for them")
	}

	adapter.settingsPath = filepath.Join(t.TempDir(), "omamori", "settings.json")
	if err := adapter.SaveSettings(tui.Defaults{ProviderID: "openai", Model: "gpt-x", Reasoning: "high"}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(adapter.settingsPath)
	if err != nil || !strings.Contains(string(data), `"model": "gpt-x"`) || strings.Contains(string(data), "sk-") {
		t.Errorf("err = %v, data = %s", err, data)
	}
	if err := adapter.SaveSettings(tui.Defaults{ProviderID: "Open AI"}); err == nil {
		t.Error("bad settings were saved")
	}
}

func TestThePlanHasAShortSummaryAndTheFullPreview(t *testing.T) {
	adapter, _, _ := newTestBackend(t)

	plan, err := adapter.Prepare(tui.Setup{ProviderID: "anthropic", Key: adapterKey})
	if err != nil {
		t.Fatal(err)
	}

	if plan.Summary == "" || !strings.Contains(plan.Summary, "It holds no file content.") || strings.Contains(plan.Summary, "System prompt:") {
		t.Errorf("the summary is wrong:\n%s", plan.Summary)
	}
	if !strings.Contains(plan.Preview, "System prompt:") || len(plan.Summary) >= len(plan.Preview) {
		t.Errorf("the full preview is wrong or not longer than the summary")
	}
}
