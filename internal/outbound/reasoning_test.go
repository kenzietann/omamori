package outbound

import (
	"slices"
	"testing"
)

func optionValues(options []ReasoningOption) []string {
	var values []string
	for _, option := range options {
		values = append(values, option.Value)
	}

	return values
}

func TestReasoningOptionsFollowTheDocumentation(t *testing.T) {
	testCases := []struct {
		name       string
		providerID string
		model      string
		wantValues []string
	}{
		{"opus 5.5 has every level", "anthropic", "claude-opus-5-5", []string{"", "low", "medium", "high", "xhigh", "max"}},
		{"sonnet 4.6 has no xhigh", "anthropic", "claude-sonnet-4-6", []string{"", "low", "medium", "high", "max"}},
		{"opus 4.6 has no xhigh", "anthropic", "claude-opus-4-6", []string{"", "low", "medium", "high", "max"}},
		{"haiku 4.5 has no effort", "anthropic", "claude-haiku-4-5", nil},
		{"sonnet 4.5 has no effort", "anthropic", "claude-sonnet-4-5-20250929", nil},
		{"the case of the name does not matter", "anthropic", "Claude-Opus-5-5", []string{"", "low", "medium", "high", "xhigh", "max"}},
		{"an unknown anthropic model gets no choice", "anthropic", "claude-unknown-9", nil},
		{"gemini 2.5 flash can be turned off", "gemini", "gemini-2.5-flash", []string{"", "none", "low", "medium", "high"}},
		{"gemini 2.5 pro cannot be turned off", "gemini", "gemini-2.5-pro", []string{"", "low", "medium", "high"}},
		{"gemini 3 cannot be turned off", "gemini", "gemini-3.6-flash", []string{"", "low", "medium", "high"}},
		{"gemini 4 cannot be turned off", "gemini", "gemini-4-argon", []string{"", "low", "medium", "high"}},
		{"gemini with a models prefix", "gemini", "models/gemini-2.5-flash", []string{"", "none", "low", "medium", "high"}},
		{"an old gemini model gets no choice", "gemini", "gemini-1.5-flash", nil},
		{"mistral small 4 is on or off", "mistral", "mistral-small-2603", []string{"", "none", "high"}},
		{"mistral large 4", "mistral", "mistral-large-4-0", []string{"", "low", "medium", "high"}},
		{"glm", "mistral", "zai-glm-5-3-flash", []string{"", "low", "high", "max"}},
		{"an older mistral model gets no choice", "mistral", "mistral-small-2506", nil},
		{"openai works with tools only when reasoning is off", "openai", "gpt-5.5", nil},
		{"deepseek is not confirmed", "deepseek", "deepseek-v4-pro", nil},
		{"xai is not confirmed", "xai", "grok-4.7", nil},
		{"groq is not confirmed", "groq", "openai/gpt-oss-120b", nil},
		{"openrouter needs the model list", "openrouter", "anthropic/claude-opus-5-5", nil},
		{"a local provider", "ollama", "llama", nil},
		{"an unknown provider", "nope", "claude-opus-5-5", nil},
		{"no model", "anthropic", "", nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotValues := optionValues(ReasoningOptions(testCase.providerID, testCase.model))

			if !slices.Equal(gotValues, testCase.wantValues) {
				t.Errorf("got %q, want %q", gotValues, testCase.wantValues)
			}
		})
	}
}

func TestTheFirstReasoningOptionIsAlwaysTheDefaultWithALabel(t *testing.T) {
	for providerID := range reasoningRules {
		for _, rule := range reasoningRules[providerID] {
			options := ReasoningOptions(providerID, rule.match)
			if len(options) == 0 {
				continue
			}
			if options[0].Value != "" || options[0].Label == "" {
				t.Errorf("%s %s: the first option is %+v", providerID, rule.match, options[0])
			}
			for _, option := range options {
				if option.Label == "" {
					t.Errorf("%s %s: option %q has no label", providerID, rule.match, option.Value)
				}
			}
		}
	}
	if label := ReasoningOptions("anthropic", "claude-opus-5-5")[0].Label; label != "default (medium)" {
		t.Errorf("the anthropic default is %q: Omamori sends medium when nothing is chosen", label)
	}
}

func TestOnlyDocumentedProvidersHaveRules(t *testing.T) {
	for providerID := range reasoningRules {
		if !slices.Contains([]string{"anthropic", "gemini", "mistral"}, providerID) {
			t.Errorf("%s has reasoning rules that were not confirmed in its documentation", providerID)
		}
	}
}

func TestValidReasoning(t *testing.T) {
	testCases := []struct {
		providerID, model, value string
		want                     bool
	}{
		{"anthropic", "claude-opus-5-5", "", true},
		{"anthropic", "claude-opus-5-5", "max", true},
		{"anthropic", "claude-sonnet-4-6", "xhigh", false},
		{"anthropic", "claude-haiku-4-5", "high", false},
		{"gemini", "gemini-3.6-flash", "none", false},
		{"gemini", "gemini-2.5-flash", "none", true},
		{"gemini", "gemini-2.5-flash", "max", false},
		{"openai", "gpt-5.5", "high", false},
		{"openai", "gpt-5.5", "", true},
		{"mistral", "mistral-large-4-0", "bogus", false},
		{"mistral", "mistral-large-4-0", "HIGH", false},
		{"mistral", "mistral-large-4-0", "high\n", false},
	}

	for _, testCase := range testCases {
		if got := ValidReasoning(testCase.providerID, testCase.model, testCase.value); got != testCase.want {
			t.Errorf("%s %s %q: got %v, want %v", testCase.providerID, testCase.model, testCase.value, got, testCase.want)
		}
	}
}

func TestSetupRefusesAReasoningLevelThatIsNotDocumented(t *testing.T) {
	if _, err := newWith("anthropic", apiTestKey, "claude-sonnet-4-6", "", "xhigh"); err == nil {
		t.Error("xhigh was accepted for sonnet 4.6")
	}
	if _, err := newWith("openai", apiTestKey, "gpt-5.5", "", "high"); err == nil {
		t.Error("a level was accepted for openai")
	}
	for _, valid := range []string{"", "high", "max"} {
		if _, err := newWith("anthropic", apiTestKey, "claude-opus-5-5", "", valid); err != nil {
			t.Errorf("%q was refused: %v", valid, err)
		}
	}
}
