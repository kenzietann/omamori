package main

import (
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kenzietann/omamori/internal/appconfig"
	"github.com/kenzietann/omamori/internal/keystore"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

func main() {
	// A store that cannot be made leaves the keys unsaved, and everything else works.
	var keys taskrun.KeyStore
	if store, err := keystore.New(keystore.DefaultService); err == nil {
		keys = store
	}

	os.Exit(run(os.Args[1:], environment{
		keys:         keys,
		settingsPath: appconfig.Path,
		stdout:       os.Stdout,
		stderr:       os.Stderr,
		lookupEnv:    os.Getenv,
		home:         os.UserHomeDir,
		// The pages before a run are full-screen. A run leaves the full-screen mode by itself and prints
		// into the normal terminal. The mouse is never captured, so the terminal selects text.
		openScreen: func(model tui.Model) error {
			_, err := tea.NewProgram(model, tea.WithAltScreen()).Run()

			return err
		},
	}))
}
