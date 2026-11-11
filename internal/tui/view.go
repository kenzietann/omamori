package tui

import (
	"strings"
	"unicode"

	"github.com/mattn/go-runewidth"
)

const chromeLines = 4

type hint struct {
	key         string
	description string
}

func safeText(text string) string {
	text = strings.ToValidUTF8(text, "?")

	return strings.Map(func(character rune) rune {
		switch {
		case character == '\n':
			return character
		case character == '\t':
			return ' '
		case unicode.IsControl(character), unicode.Is(unicode.Cf, character):
			return '?'
		}

		return character
	}, text)
}

// truncate cuts by display width, because a Japanese character takes two columns.
// The cut happens before any color is added, so a color code is never cut in half.
func (model Model) truncate(text string, reserved int) string {
	if model.width <= 0 {
		return text
	}

	return runewidth.Truncate(text, max(model.width-reserved, 1), "…")
}

func (model Model) footer(hints ...hint) string {
	plain := make([]string, len(hints))
	for index, current := range hints {
		plain[index] = current.key + ": " + current.description
	}
	joined := strings.Join(plain, "   ")

	if model.width > 0 && runewidth.StringWidth(joined) > model.width {
		return styleDim.Render(model.truncate(joined, 0))
	}

	styled := make([]string, len(hints))
	for index, current := range hints {
		styled[index] = styleAccent.Render(current.key) + styleDim.Render(": "+current.description)
	}

	return strings.Join(styled, "   ")
}

func (model Model) View() string {
	switch model.screen {
	case runScreen:
		return strings.Join(model.runLines(), "\n")
	case resultsScreen:
		return strings.Join(model.resultsLines(), "\n")
	}

	return strings.Join(model.homeLines(), "\n")
}

func (model Model) homeLines() []string {
	menu := []string{"Task A: Exposure check", "Task B: Log triage (not built yet)", "Quit"}

	lines := model.headerLines()
	label := "Target folder: "
	lines = append(lines, "",
		styleDim.Render(label)+styleBody.Render(model.truncate(safeText(model.target), len(label))), "")

	for index, item := range menu {
		marker := "  "
		style := styleBody
		switch {
		case index == model.cursor:
			marker, style = "> ", styleSelected
		case index == menuTaskB:
			style = styleDim
		}
		lines = append(lines, style.Render(model.truncate(marker+item, 0)))
	}
	if model.notice != "" {
		lines = append(lines, "", styleWarn.Render(model.truncate(safeText(model.notice), 0)))
	}

	return append(lines, "", model.footer(hint{"up/down", "move"}, hint{"enter", "choose"}, hint{"q", "quit"}))
}

func (model Model) runLines() []string {
	title, style := "Running: Task A, exposure check", styleAccent
	if model.cancelling {
		title, style = "Cancelling... waiting for the current step to stop", styleWarn
	}

	lines := []string{style.Render(model.truncate(title, 0)), ""}
	steps := model.steps
	if room := model.height - chromeLines; model.height > 0 && len(steps) > room && room > 0 {
		steps = steps[len(steps)-room:]
	}
	for _, step := range steps {
		lines = append(lines, styleBody.Render(model.truncate(safeText(step), 0)))
	}
	if len(model.steps) == 0 {
		lines = append(lines, styleDim.Render("Starting..."))
	}

	return append(lines, "", model.footer(hint{"esc", "cancel"}, hint{"q", "quit"}))
}

func (model Model) bodyLines() []string {
	body := strings.Split(safeText(model.report), "\n")
	body = append(body, "", "Timeline")
	if len(model.steps) == 0 {
		body = append(body, "(no steps)")
	}
	for _, step := range model.steps {
		body = append(body, "- "+safeText(step))
	}

	return body
}

func (model Model) viewHeight() int {
	if model.height <= 0 {
		return len(model.bodyLines())
	}

	return max(model.height-chromeLines, 1)
}

func (model Model) maxScroll() int {
	return max(len(model.bodyLines())-model.viewHeight(), 0)
}

func (model Model) resultsLines() []string {
	title, style := "Results: Task A, complete", styleGood
	if model.stopped {
		title, style = "Results: Task A, incomplete", styleWarn
	}

	body := model.bodyLines()
	start := min(model.scroll, model.maxScroll())
	end := min(start+model.viewHeight(), len(body))

	lines := []string{style.Render(model.truncate(title, 0)), ""}
	for _, line := range body[start:end] {
		lines = append(lines, styleReportLine(line).Render(model.truncate(line, 0)))
	}

	return append(lines, "", model.footer(
		hint{"up/down, pgup/pgdn", "scroll"}, hint{"b", "back to home"}, hint{"q", "quit"}))
}
