package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

func main() {
	chosen, err := parseSettings(os.Args[1:], os.Getenv, os.UserHomeDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "omamori:", err)
		if err == errUsage {
			os.Exit(2)
		}
		os.Exit(1)
	}

	config := taskrun.Config{
		Target:     chosen.target,
		OutputBase: chosen.output,
		Limits:     agent.Limits{MaxSteps: chosen.maxSteps, MaxTokens: chosen.maxTokens},
	}
	model := tui.New(chosen.target, backend{config: config}, tui.Defaults{ProviderID: chosen.provider, Model: chosen.model})

	if _, err := tea.NewProgram(model, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "omamori: the screen stopped:", err)
		os.Exit(1)
	}
}
