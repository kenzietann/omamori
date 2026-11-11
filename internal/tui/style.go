package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	colorBody   = lipgloss.AdaptiveColor{Light: "#0d1115", Dark: "#e7edf6"}
	colorAccent = lipgloss.AdaptiveColor{Light: "#1d4ed8", Dark: "#6ea8ff"}
	colorDim    = lipgloss.AdaptiveColor{Light: "#4b5563", Dark: "#9aa4b5"}
	colorGood   = lipgloss.AdaptiveColor{Light: "#166534", Dark: "#4ade80"}
	colorWarn   = lipgloss.AdaptiveColor{Light: "#92400e", Dark: "#f5b041"}
	colorBad    = lipgloss.AdaptiveColor{Light: "#b91c1c", Dark: "#ff7b7b"}
)

var (
	styleBody     = lipgloss.NewStyle().Foreground(colorBody)
	styleTitle    = lipgloss.NewStyle().Foreground(colorBody).Bold(true)
	styleAccent   = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleDim      = lipgloss.NewStyle().Foreground(colorDim)
	styleGood     = lipgloss.NewStyle().Foreground(colorGood).Bold(true)
	styleWarn     = lipgloss.NewStyle().Foreground(colorWarn).Bold(true)
	styleBad      = lipgloss.NewStyle().Foreground(colorBad)
	styleSelected = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
)

// styleReportLine only colors a line that the report writer made. The text is already clean,
// and a color never changes what the line says.
func styleReportLine(line string) lipgloss.Style {
	switch {
	case strings.HasPrefix(line, "# "):
		return styleTitle
	case strings.HasPrefix(line, "## "), line == "Timeline":
		return styleAccent
	case strings.HasPrefix(line, "Status: complete"):
		return styleGood
	case strings.HasPrefix(line, "Status: incomplete"):
		return styleWarn
	case strings.Contains(line, "| high |"):
		return styleBad
	case strings.Contains(line, "| medium |"):
		return styleWarn
	}

	return styleBody
}
