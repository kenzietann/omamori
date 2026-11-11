package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

const (
	pixelDark  = '.'
	pixelLight = 'L'
	pixelBlue  = 'B'

	logoGap       = 3
	tagline       = "a blue team helper with a guard"
	minLogoHeight = 26
)

// Each row is the left half of the icon. mirror() builds the right half, so the icon is
// symmetric by construction. L is the light body, B is the blue diamond, . is empty.
var iconPixels = mirror([]string{
	"......LLLLLLL",
	".....LLLLLLLL",
	".....LLLLLL..",
	"..LLLLLL....B",
	".LLLLLL....BB",
	"LLLLLLL...BBB",
	"LLLLLLLL...BB",
	"LLLLLLLLL...B",
	"LLLL.LLLLL...",
	"LLLL.LLLL.L..",
	"LLLL.LLLL.LL.",
	"LLLL.LLLL.LLL",
	"LLLL.LLLL.LLL",
	"LLLL.LLLL.LLL",
	"LLLL.LLLL.LLL",
	"LLLL.LLLL.LLL",
	"LLLL.LLLL.LLL",
	"LLLL.LLLL.LLL",
	"LLLL.LLLL.LLL",
	"LLLLL....LLLL",
	"LLLLLLL.LLLLL",
	".LLLLLLLLLLLL",
	"...LLLLLLLLLL",
	"....LLLLLLLLL",
	"......LLLLLLL",
	"........LLLLL",
	"..........LLL",
	"............L",
})

var glyphs = map[rune][]string{
	'O': {".####.", "##..##", "##..##", "##..##", "##..##", "##..##", ".####."},
	'M': {"##...##", "###.###", "#######", "##.#.##", "##...##", "##...##", "##...##"},
	'A': {".####.", "##..##", "##..##", "######", "##..##", "##..##", "##..##"},
	'R': {"#####.", "##..##", "##..##", "#####.", "##.##.", "##..##", "##..##"},
	'I': {"######", "..##..", "..##..", "..##..", "..##..", "..##..", "######"},
}

var wordmarkPixels = buildWordmark("OMAMORI")

func mirror(leftHalves []string) []string {
	rows := make([]string, len(leftHalves))
	for index, left := range leftHalves {
		runes := []rune(left)
		for from, to := 0, len(runes)-1; from < to; from, to = from+1, to-1 {
			runes[from], runes[to] = runes[to], runes[from]
		}
		rows[index] = left + string(runes)
	}

	return rows
}

func buildWordmark(word string) []string {
	rows := make([]string, len(glyphs['O']))

	for position, letter := range word {
		for index, row := range glyphs[letter] {
			if position > 0 {
				rows[index] += "."
			}
			rows[index] += strings.ReplaceAll(row, "#", string(pixelLight))
		}
	}

	return rows
}

func pixelAt(rows []string, row, column int) byte {
	if row >= len(rows) || column >= len(rows[row]) {
		return pixelDark
	}

	return rows[row][column]
}

func asciiCell(top, bottom byte) string {
	switch {
	case top == pixelBlue || bottom == pixelBlue:
		return "*"
	case top == pixelLight || bottom == pixelLight:
		return "#"
	}

	return " "
}

func pixelColor(pixel byte) lipgloss.TerminalColor {
	if pixel == pixelBlue {
		return colorLogoBlue
	}

	return colorBody
}

// Two pixel rows fit in one text row with a half block. The upper half is the foreground
// and the lower half is the background, so two different colors can share one cell.
func colorCell(top, bottom byte) string {
	switch {
	case top == pixelDark && bottom == pixelDark:
		return " "
	case top == bottom:
		return lipgloss.NewStyle().Foreground(pixelColor(top)).Render("█")
	case bottom == pixelDark:
		return lipgloss.NewStyle().Foreground(pixelColor(top)).Render("▀")
	case top == pixelDark:
		return lipgloss.NewStyle().Foreground(pixelColor(bottom)).Render("▄")
	}

	return lipgloss.NewStyle().Foreground(pixelColor(top)).Background(pixelColor(bottom)).Render("▀")
}

func usesASCII() bool {
	return lipgloss.ColorProfile() == termenv.Ascii
}

func renderPixels(rows []string) []string {
	useASCII := usesASCII()

	width := 0
	for _, row := range rows {
		width = max(width, len(row))
	}

	rendered := make([]string, 0, (len(rows)+1)/2)
	for row := 0; row < len(rows); row += 2 {
		var line strings.Builder
		for column := 0; column < width; column++ {
			top, bottom := pixelAt(rows, row, column), pixelAt(rows, row+1, column)
			if useASCII {
				line.WriteString(asciiCell(top, bottom))
			} else {
				line.WriteString(colorCell(top, bottom))
			}
		}
		rendered = append(rendered, line.String())
	}

	return rendered
}

// Two pixel rows merged into one character would blur the letters, so without color
// the wordmark keeps one text row for each pixel row.
func renderWordmark() []string {
	if !usesASCII() {
		return renderPixels(wordmarkPixels)
	}

	rows := make([]string, len(wordmarkPixels))
	for index, row := range wordmarkPixels {
		rows[index] = strings.NewReplacer(string(pixelLight), "#", string(pixelDark), " ").Replace(row)
	}

	return rows
}

func logoWidth() int {
	return len(iconPixels[0]) + logoGap + len(wordmarkPixels[0])
}

func (model Model) showFullLogo() bool {
	return (model.width == 0 || model.width >= logoWidth()) && (model.height == 0 || model.height >= minLogoHeight)
}

func (model Model) headerLines() []string {
	if !model.showFullLogo() {
		title := styleTitle.Render("Omamori")
		if model.width == 0 || model.width >= len("Omamori  ")+len(tagline) {
			title += styleDim.Render("  " + tagline)
		}

		return []string{title}
	}

	icon := renderPixels(iconPixels)
	word := renderWordmark()
	gap := strings.Repeat(" ", logoGap)
	wordTop := (len(icon) - len(word)) / 2
	taglineRow := wordTop + len(word) + 1

	lines := make([]string, len(icon))
	for row, iconLine := range icon {
		lines[row] = iconLine + gap

		if index := row - wordTop; index >= 0 && index < len(word) {
			lines[row] += word[index]
		}
		if row == taglineRow {
			lines[row] += styleDim.Render(tagline)
		}
	}

	return lines
}
