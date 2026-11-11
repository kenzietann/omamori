package tui

import (
	"strings"
	"unicode"
)

const chromeLines = 4

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

func (model Model) fit(line string) string {
	if model.width <= 0 {
		return line
	}

	runes := []rune(line)
	if len(runes) <= model.width {
		return line
	}

	return string(runes[:max(model.width-1, 1)]) + "…"
}

func (model Model) View() string {
	var lines []string

	switch model.screen {
	case homeScreen:
		lines = model.homeLines()
	case runScreen:
		lines = model.runLines()
	case resultsScreen:
		lines = model.resultsLines()
	}

	fitted := make([]string, len(lines))
	for index, line := range lines {
		fitted[index] = model.fit(line)
	}

	return strings.Join(fitted, "\n")
}

func (model Model) homeLines() []string {
	menu := []string{"Task A: Exposure check", "Task B: Log triage (not built yet)", "Quit"}

	lines := []string{"Omamori: a blue team helper with a guard", "", "Target folder: " + safeText(model.target), ""}
	for index, item := range menu {
		marker := "  "
		if index == model.cursor {
			marker = "> "
		}
		lines = append(lines, marker+item)
	}
	if model.notice != "" {
		lines = append(lines, "", safeText(model.notice))
	}

	return append(lines, "", "up/down: move   enter: choose   q: quit")
}

func (model Model) runLines() []string {
	title := "Running: Task A, exposure check"
	if model.cancelling {
		title = "Cancelling... waiting for the current step to stop"
	}

	lines := []string{title, ""}
	steps := model.steps
	if room := model.height - chromeLines; model.height > 0 && len(steps) > room && room > 0 {
		steps = steps[len(steps)-room:]
	}
	for _, step := range steps {
		lines = append(lines, safeText(step))
	}
	if len(model.steps) == 0 {
		lines = append(lines, "Starting...")
	}

	return append(lines, "", "esc: cancel   q: quit")
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
	status := "complete"
	if model.stopped {
		status = "incomplete"
	}

	body := model.bodyLines()
	start := min(model.scroll, model.maxScroll())
	end := min(start+model.viewHeight(), len(body))

	lines := []string{"Results: Task A, " + status, ""}
	lines = append(lines, body[start:end]...)

	return append(lines, "", "up/down, pgup/pgdn: scroll   b: back to home   q: quit")
}
