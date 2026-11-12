package tui

import (
	"strings"
	"unicode/utf8"
)

const tagline = "a blue team helper with a guard"

const rawWordmark = `
 ██████╗ ███╗   ███╗ █████╗ ███╗   ███╗ ██████╗ ██████╗ ██╗
██╔═══██╗████╗ ████║██╔══██╗████╗ ████║██╔═══██╗██╔══██╗██║
██║   ██║██╔████╔██║███████║██╔████╔██║██║   ██║██████╔╝██║
██║   ██║██║╚██╔╝██║██╔══██║██║╚██╔╝██║██║   ██║██╔══██╗██║
╚██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║██║
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝
`

var wordmarkRows = strings.Split(strings.Trim(rawWordmark, "\n"), "\n")

func wordmarkWidth() int {
	widest := 0
	for _, row := range wordmarkRows {
		widest = max(widest, utf8.RuneCountInString(row))
	}

	return widest
}

const minWordmarkHeight = 18

func (model Model) showWordmark() bool {
	return (model.width == 0 || model.width >= wordmarkWidth()) && (model.height == 0 || model.height >= minWordmarkHeight)
}

func (model Model) oneLineHeader() string {
	title := styleTitle.Render(model.truncate("OMAMORI", 0))
	if model.width == 0 || model.width >= len("OMAMORI  ")+len(tagline) {
		title += styleDim.Render("  " + tagline)
	}

	return title
}

func (model Model) headerLines() []string {
	if !model.showWordmark() {
		return []string{model.oneLineHeader()}
	}

	lines := make([]string, 0, len(wordmarkRows)+1)
	for _, row := range wordmarkRows {
		lines = append(lines, gradientRow(row, wordmarkWidth()))
	}

	return append(lines, styleDim.Render(tagline))
}
