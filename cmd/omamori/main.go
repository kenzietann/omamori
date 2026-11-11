package main

import (
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kenzietann/omamori/internal/tui"
)

func main() {
	os.Exit(run(os.Args[1:], environment{
		stdout:    os.Stdout,
		stderr:    os.Stderr,
		lookupEnv: os.Getenv,
		home:      os.UserHomeDir,
		openScreen: func(model tui.Model) error {
			_, err := tea.NewProgram(model, tea.WithAltScreen()).Run()
			return err
		},
	}))
}
