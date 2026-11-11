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
	switch model.step {
	case stepProvider:
		return model.providerLines()
	case stepKey:
		return model.entryLines()
	case stepModel:
		if model.modelTyping {
			return model.entryLines()
		}

		return model.modelLines()
	case stepConsent:
		return model.consentLines()
	}

	return model.menuLines()
}

func providerStatus(choice Choice) string {
	switch {
	case choice.Local:
		return "no key needed"
	case choice.KeyFound:
		return "key found in " + choice.KeyEnv
	}

	return "needs a key (" + choice.KeyEnv + ")"
}

func (model Model) providerLines() []string {
	lines := []string{model.oneLineHeader(), "", styleAccent.Render("Choose the AI provider"), ""}

	for index, choice := range model.choices {
		marker, style := "  ", styleBody
		if index == model.providerCursor {
			marker, style = "> ", styleSelected
		}
		lines = append(lines, style.Render(model.truncate(marker+safeText(choice.Name)+"   "+safeText(providerStatus(choice)), 0)))
	}

	lines = append(lines, "", styleDim.Render(model.truncate("Your files are cleaned before anything is sent. You will see the first request before you confirm.", 0)))

	return append(lines, "", model.footer(hint{"up/down", "move"}, hint{"enter", "choose"}, hint{"esc", "back"}, hint{"q", "quit"}))
}

func (model Model) entryLines() []string {
	chosen := model.choices[model.providerCursor]
	lines := []string{model.oneLineHeader(), "", styleAccent.Render(model.truncate("Provider: "+safeText(chosen.Name), 0)), ""}

	if model.step == stepModel {
		lines = append(lines, styleBody.Render("Model name:"), styleSelected.Render(model.truncate("> "+safeText(string(model.modelInput))+"_", 0)), "")
		if model.modelsNotice != "" {
			lines = append(lines, styleDim.Render(model.truncate(model.modelsNotice, 0)))
		} else {
			lines = append(lines, styleDim.Render(model.truncate("Type the exact model name from the documentation of the provider.", 0)))
		}
	} else {
		// The key is shown as dots and never as text.
		lines = append(lines, styleBody.Render("API key (hidden):"), styleSelected.Render("> "+strings.Repeat("•", min(len(model.keyInput), 40))+"_"), "",
			styleDim.Render(model.truncate("The key stays in memory. It is never shown, saved, or logged.", 0)))
		if chosen.KeyEnv != "" {
			lines = append(lines, styleDim.Render(model.truncate("To skip this step next time, set "+safeText(chosen.KeyEnv)+" before you start.", 0)))
		}
	}

	if model.setupError != "" {
		lines = append(lines, "", styleWarn.Render(model.truncate(safeText(model.setupError), 0)))
	}

	return append(lines, "", model.footer(hint{"enter", "next"}, hint{"esc", "back"}, hint{"ctrl+c", "quit"}))
}

// listRoom is how many lines of the model list fit in the window.
func (model Model) listRoom() int {
	if model.height <= 0 {
		return len(model.models) + 1
	}

	return max(model.height-listChrome, 3)
}

func (model Model) modelLines() []string {
	chosen := model.choices[model.providerCursor]
	lines := []string{model.oneLineHeader(), "", styleAccent.Render(model.truncate("Provider: "+safeText(chosen.Name), 0)), ""}

	if model.modelsLoading {
		lines = append(lines, styleDim.Render(model.truncate("Getting the list of models from "+safeText(chosen.Name)+"...", 0)))

		return append(lines, "", model.footer(hint{"esc", "back"}, hint{"ctrl+c", "quit"}))
	}

	lines = append(lines, styleBody.Render("Choose the model:"))

	entries := make([]string, 0, len(model.models)+1)
	for _, name := range model.models {
		entries = append(entries, safeText(name))
	}
	entries = append(entries, "Type a model name myself")

	room := min(model.listRoom(), len(entries))
	start := min(max(model.modelCursor-room/2, 0), len(entries)-room)
	for index := start; index < start+room; index++ {
		marker, style := "  ", styleBody
		if index == model.modelCursor {
			marker, style = "> ", styleSelected
		}
		lines = append(lines, style.Render(model.truncate(marker+entries[index], 0)))
	}

	if model.setupError != "" {
		lines = append(lines, "", styleWarn.Render(model.truncate(safeText(model.setupError), 0)))
	}

	return append(lines, "", model.footer(hint{"up/down", "move"}, hint{"enter", "choose"}, hint{"esc", "back"}, hint{"q", "quit"}))
}

func (model Model) consentBody() []string {
	if model.plan == nil {
		return nil
	}

	return strings.Split(safeText(model.plan.Preview), "\n")
}

func (model Model) consentViewHeight() int {
	if model.height <= 0 {
		return max(len(model.consentBody()), 1)
	}

	return max(model.height-consentChrome, 1)
}

func (model Model) maxConsentScroll() int {
	return max(len(model.consentBody())-model.consentViewHeight(), 0)
}

func (model Model) consentLines() []string {
	consent := ""
	if model.plan != nil {
		consent = safeText(model.plan.ConsentText)
	}

	lines := []string{model.oneLineHeader(), "", styleAccent.Render("Please confirm before anything is sent"), "",
		styleWarn.Render(model.truncate(consent, 0)), "", styleDim.Render("Nothing has been sent yet. This is the dry run:"), ""}

	body := model.consentBody()
	start := min(model.consentScroll, model.maxConsentScroll())
	end := min(start+model.consentViewHeight(), len(body))
	for _, line := range body[start:end] {
		lines = append(lines, styleBody.Render(model.truncate(line, 0)))
	}

	return append(lines, "", model.footer(hint{"enter", "send and start"}, hint{"up/down", "scroll"}, hint{"esc", "cancel"}, hint{"q", "quit"}))
}

func (model Model) menuLines() []string {
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

	chrome := chromeLines
	if model.saved != "" {
		chrome++
	}

	return max(model.height-chrome, 1)
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

	lines := []string{style.Render(model.truncate(title, 0))}
	if model.saved != "" {
		lines = append(lines, styleDim.Render(model.truncate("Saved to: "+safeText(model.saved), 0)))
	}
	lines = append(lines, "")
	for _, line := range body[start:end] {
		lines = append(lines, styleReportLine(line).Render(model.truncate(line, 0)))
	}

	return append(lines, "", model.footer(
		hint{"up/down, pgup/pgdn", "scroll"}, hint{"b", "back to home"}, hint{"q", "quit"}))
}
