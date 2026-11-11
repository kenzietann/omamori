package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kenzietann/omamori/internal/tui"
)

var errNotConnected = errors.New("Task A is not connected to an AI provider yet")

func notConnected(ctx context.Context, step func(string)) (tui.Result, error) {
	return tui.Result{}, errNotConnected
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: omamori <project folder>")
		os.Exit(2)
	}

	target, err := filepath.Abs(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "omamori: the folder is not usable")
		os.Exit(1)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		fmt.Fprintln(os.Stderr, "omamori: the target is not a folder")
		os.Exit(1)
	}

	if _, err := tea.NewProgram(tui.New(target, notConnected), tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "omamori: the screen stopped:", err)
		os.Exit(1)
	}
}
