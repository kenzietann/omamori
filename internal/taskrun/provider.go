package taskrun

import (
	"context"
	"strings"

	"github.com/kenzietann/omamori/internal/outbound"
)

// ResolvedProvider contains the provider and display metadata, never the API key.
// CLI, terminal and local dashboard services use the same provider selection rules.
type ResolvedProvider struct {
	Provider  outbound.Provider
	ID        string
	Name      string
	Model     string
	Reasoning string
}

// ResolveProvider prepares a live provider without sending a request. A typed key takes
// precedence over the environment and saved key, as it does for the existing tasks.
func ResolveProvider(ctx context.Context, config Config, setup Setup) (ResolvedProvider, error) {
	chosen := config.choice(setup.ProviderID)
	if chosen == nil {
		return ResolvedProvider{}, ErrUnknownProvider
	}
	model := strings.TrimSpace(setup.Model)
	if model == "" {
		model = chosen.DefaultModel
	}
	if model == "" {
		return ResolvedProvider{}, ErrNeedsModel
	}
	key, err := config.resolveKey(ctx, chosen, setup.Key)
	if err != nil {
		return ResolvedProvider{}, err
	}
	if !outbound.ValidReasoning(chosen.ID, model, setup.Reasoning) {
		return ResolvedProvider{}, ErrReasoning
	}
	provider, err := config.factory()(chosen.ID, key, model, setup.Reasoning)
	if err != nil || provider == nil {
		return ResolvedProvider{}, ErrSetup
	}

	return ResolvedProvider{Provider: provider, ID: chosen.ID, Name: provider.Name(), Model: model, Reasoning: setup.Reasoning}, nil
}
