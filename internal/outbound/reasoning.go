package outbound

import "strings"

// ReasoningOption is one level a user may choose. Value is what goes to the provider.
// An empty Value is the provider's own default, and nothing extra is sent for it.
type ReasoningOption struct {
	Value string
	Label string
}

type reasoningRule struct {
	// match is a part of the model name. The first rule that matches wins.
	match   string
	options []ReasoningOption
}

var (
	levelLow    = ReasoningOption{"low", "low"}
	levelMedium = ReasoningOption{"medium", "medium"}
	levelHigh   = ReasoningOption{"high", "high"}
	levelXHigh  = ReasoningOption{"xhigh", "xhigh"}
	levelMax    = ReasoningOption{"max", "max"}
	levelOff    = ReasoningOption{"none", "off (no reasoning)"}
)

// reasoningRules come from the documentation of each provider. Support differs by model, and a
// model that no rule names gets no choice, so Omamori never offers a level that is not documented.
// Providers whose documents could not be confirmed, or that cannot work with tools on this protocol,
// have no rules: OpenAI (tools work only with reasoning off), DeepSeek, xAI, Groq, OpenRouter.
var reasoningRules = map[string][]reasoningRule{
	"anthropic": {
		{"haiku-4-5", nil},
		{"sonnet-4-5", nil},
		{"opus-4-5", nil},
		{"opus-4-6", []ReasoningOption{levelLow, levelMedium, levelHigh, levelMax}},
		{"sonnet-4-6", []ReasoningOption{levelLow, levelMedium, levelHigh, levelMax}},
		{"opus-4-7", []ReasoningOption{levelLow, levelMedium, levelHigh, levelXHigh, levelMax}},
		{"opus-4-8", []ReasoningOption{levelLow, levelMedium, levelHigh, levelXHigh, levelMax}},
		{"opus-5", []ReasoningOption{levelLow, levelMedium, levelHigh, levelXHigh, levelMax}},
		{"sonnet-5", []ReasoningOption{levelLow, levelMedium, levelHigh, levelXHigh, levelMax}},
		{"haiku-5", []ReasoningOption{levelLow, levelMedium, levelHigh, levelXHigh, levelMax}},
		{"fable-", []ReasoningOption{levelLow, levelMedium, levelHigh, levelXHigh, levelMax}},
		{"mythos-", []ReasoningOption{levelLow, levelMedium, levelHigh, levelXHigh, levelMax}},
	},
	"gemini": {
		{"gemini-2.5-pro", []ReasoningOption{levelLow, levelMedium, levelHigh}},
		{"gemini-2.5", []ReasoningOption{levelOff, levelLow, levelMedium, levelHigh}},
		{"gemini-3", []ReasoningOption{levelLow, levelMedium, levelHigh}},
		{"gemini-4", []ReasoningOption{levelLow, levelMedium, levelHigh}},
	},
	"mistral": {
		{"mistral-small-2603", []ReasoningOption{levelOff, levelHigh}},
		{"mistral-medium-3-5", []ReasoningOption{levelOff, levelHigh}},
		{"mistral-large-4", []ReasoningOption{levelLow, levelMedium, levelHigh}},
		{"zai-glm-5-3", []ReasoningOption{levelLow, levelHigh, levelMax}},
	},
}

// defaultReasoningLabel names what happens when the user chooses nothing.
var defaultReasoningLabel = map[string]string{
	"anthropic": "default (medium)",
}

// ReasoningOptions lists the choices for this provider and model. The first one is always the default.
// It returns nothing when the model has no documented choice, and then no step is shown.
func ReasoningOptions(providerID, model string) []ReasoningOption {
	model = strings.ToLower(model)

	for _, rule := range reasoningRules[providerID] {
		if !strings.Contains(model, rule.match) {
			continue
		}
		if len(rule.options) == 0 {
			return nil
		}
		label := defaultReasoningLabel[providerID]
		if label == "" {
			label = "provider default"
		}

		return append([]ReasoningOption{{Value: "", Label: label}}, rule.options...)
	}

	return nil
}

// ValidReasoning says whether a value may be sent for this provider and model.
func ValidReasoning(providerID, model, value string) bool {
	if value == "" {
		return true
	}
	for _, option := range ReasoningOptions(providerID, model) {
		if option.Value == value {
			return true
		}
	}

	return false
}
