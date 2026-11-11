package tui

import (
	"strings"
	"unicode"

	"github.com/mattn/go-runewidth"
)

// The pages before a run (the menu, the choices, the settings, and the dry run) are full-screen pages.
// A run leaves the full-screen mode: its steps and its report are printed into the normal terminal,
// so that the scrollback, the wheel, the selection and select-all of the terminal work on them.
// Only one status line stays at the bottom while it runs.

const (
	selectMarker = "❯ "
	idleMarker   = "  "
)

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

func (model Model) bodyLine(text string) string { return styleBody.Render(model.truncate(text, 0)) }
func (model Model) dimLine(text string) string {
	return styleDim.Render(model.truncate(safeText(text), 0))
}
func (model Model) warnLine(text string) string {
	return styleWarn.Render(model.truncate(safeText(text), 0))
}
func (model Model) accentLine(text string) string {
	return styleAccent.Render(model.truncate(safeText(text), 0))
}

// visibleRange picks the lines of a long list that fit, with the cursor in the middle when it can.
func visibleRange(cursor, total, room int) (first, last int) {
	room = min(max(room, 1), total)
	first = min(max(cursor-room/2, 0), total-room)

	return first, first + room
}

// room is how many lines a list may have, when the page has this many other lines.
func (model Model) room(otherLines int) int {
	if model.height <= 0 {
		return 1 << 20
	}

	return max(model.height-otherLines, 3)
}

// choiceList draws a list with a marker at the cursor. Only the lines that fit are drawn.
// A line whose number is in dim is drawn in the dim color.
func (model Model) choiceList(labels []string, cursor, room int, dim ...int) []string {
	first, last := visibleRange(cursor, len(labels), room)

	body := make([]string, 0, last-first)
	for index := first; index < last; index++ {
		marker, style := idleMarker, styleBody
		switch {
		case index == cursor:
			marker, style = selectMarker, styleSelected
		case containsIndex(dim, index):
			style = styleDim
		}
		body = append(body, style.Render(model.truncate(marker+safeText(labels[index]), 0)))
	}

	return body
}

func containsIndex(indexes []int, index int) bool {
	for _, candidate := range indexes {
		if candidate == index {
			return true
		}
	}

	return false
}

// page puts a page together: the lines before the list, the list (as many lines as fit), the lines
// after it, a blank line, and the keys.
func (model Model) page(lead []string, labels []string, cursor int, trail []string, keys string, dim ...int) string {
	room := model.room(len(lead) + len(trail) + 2)

	lines := append([]string{}, lead...)
	lines = append(lines, model.choiceList(labels, cursor, room, dim...)...)
	lines = append(lines, trail...)
	lines = append(lines, "", keys)

	return strings.Join(lines, "\n")
}

// plainPage is a page without a list.
func (model Model) plainPage(lines []string, keys string) string {
	return strings.Join(append(append([]string{}, lines...), "", keys), "\n")
}

func (model Model) View() string {
	if model.quitting {
		return ""
	}
	if model.screen == runScreen {
		return model.runView()
	}

	switch model.step {
	case stepProvider:
		return model.providerView()
	case stepModel:
		if model.modelTyping {
			return model.entryView()
		}

		return model.modelView()
	case stepKey:
		return model.entryView()
	case stepReasoning:
		return model.reasoningView()
	case stepConsent:
		return model.consentView()
	case stepSettings:
		return model.settingsView()
	}

	return model.menuView()
}

func providerStatus(choice Choice) string {
	switch {
	case choice.Local:
		return "no key needed"
	case choice.KeyFound:
		return "key found in " + choice.KeyEnv
	case choice.KeySaved:
		return "key saved in your Keychain"
	}

	return "needs a key (" + choice.KeyEnv + ")"
}

// targetLine is the label and the folder. In a window that is narrower than the label, the label is cut too.
func (model Model) targetLine(label string) string {
	line := model.truncate(label+safeText(model.target), 0)
	if rest, isLonger := strings.CutPrefix(line, label); isLonger {
		return styleDim.Render(label) + styleBody.Render(rest)
	}

	return styleDim.Render(line)
}

func (model Model) menuView() string {
	menu := []string{"Task A: Exposure check", "Task B: Log triage (not built yet)", "Settings", "Quit"}

	lead := append(model.headerLines(), "", model.targetLine("Target folder: "), "")
	var trail []string
	if model.notice != "" {
		trail = []string{"", model.warnLine(model.notice)}
	}

	return model.page(lead, menu, model.cursor, trail,
		model.footer(hint{"up/down", "move"}, hint{"enter", "choose"}, hint{"q", "quit"}), menuTaskB)
}

func (model Model) providerView() string {
	lead := []string{model.oneLineHeader(), "", model.accentLine("Choose the AI provider"), ""}
	trail := []string{"", model.dimLine("Your files are cleaned before anything is sent. You will see the first request before you confirm.")}

	labels := make([]string, len(model.choices))
	for index, choice := range model.choices {
		labels[index] = choice.Name + "   " + providerStatus(choice)
	}

	return model.page(lead, labels, model.providerCursor, trail,
		model.footer(hint{"up/down", "move"}, hint{"enter", "choose"}, hint{"esc", "back"}, hint{"q", "quit"}))
}

func (model Model) entryView() string {
	chosen := model.choices[model.providerCursor]
	lines := []string{model.oneLineHeader(), "", model.accentLine("Provider: " + chosen.Name), ""}

	if model.step == stepModel {
		lines = append(lines, model.bodyLine("Model name:"),
			styleSelected.Render(model.truncate(selectMarker+safeText(string(model.modelInput))+"_", 0)), "")
		if model.modelsNotice != "" {
			lines = append(lines, model.dimLine(model.modelsNotice))
		} else {
			lines = append(lines, model.dimLine("Type the exact model name from the documentation of the provider."))
		}
	} else {
		keyText := "This system cannot save keys. The key stays in memory only. It is never shown or logged."
		if model.backend != nil && model.backend.KeysCanBeSaved() {
			keyText = "After it works, the key is saved in your Keychain, so you type it once. It is never shown or logged."
		}
		// The key is shown as dots and never as text.
		lines = append(lines, model.bodyLine("API key (hidden):"),
			styleSelected.Render(model.truncate(selectMarker+strings.Repeat("•", min(len(model.keyInput), 40))+"_", 0)), "",
			model.dimLine(keyText))
		if chosen.KeyEnv != "" {
			lines = append(lines, model.dimLine("To skip this step next time, set "+chosen.KeyEnv+" before you start."))
		}
	}
	if model.setupError != "" {
		lines = append(lines, "", model.warnLine(model.setupError))
	}

	return model.plainPage(lines, model.footer(hint{"enter", "next"}, hint{"esc", "back"}, hint{"ctrl+c", "quit"}))
}

func (model Model) modelView() string {
	chosen := model.choices[model.providerCursor]
	lead := []string{model.oneLineHeader(), "", model.accentLine("Provider: " + chosen.Name), ""}

	if model.modelsLoading {
		return model.plainPage(append(lead, model.dimLine("Getting the list of models from "+chosen.Name+"...")),
			model.footer(hint{"esc", "back"}, hint{"ctrl+c", "quit"}))
	}

	lead = append(lead, model.bodyLine("Choose the model:"))
	if model.keyNotice != "" {
		lead = append(lead, model.dimLine(model.keyNotice))
	}
	var trail []string
	if model.setupError != "" {
		trail = []string{"", model.warnLine(model.setupError)}
	}

	labels := append(append([]string{}, model.models...), "Type a model name myself")

	return model.page(lead, labels, model.modelCursor, trail,
		model.footer(hint{"up/down", "move"}, hint{"enter", "choose"}, hint{"esc", "back"}, hint{"q", "quit"}))
}

func (model Model) reasoningView() string {
	chosen := model.choices[model.providerCursor]
	lead := []string{model.oneLineHeader(), "", model.accentLine("Provider: " + chosen.Name), model.accentLine("Model: " + string(model.modelInput)), "",
		model.bodyLine("Choose how much the AI reasons:")}
	trail := []string{"", model.dimLine("Not every model supports every level. The default is the safest choice.")}
	if model.setupError != "" {
		trail = append(trail, "", model.warnLine(model.setupError))
	}

	labels := make([]string, len(model.reasonChoices))
	for index, choice := range model.reasonChoices {
		labels[index] = choice.Label
	}

	return model.page(lead, labels, model.reasonCursor, trail,
		model.footer(hint{"up/down", "move"}, hint{"enter", "choose"}, hint{"esc", "back"}, hint{"q", "quit"}))
}

func (model Model) settingsView() string {
	provider, key := "(not chosen)", ""
	for _, choice := range model.choices {
		if choice.ID == model.defaults.ProviderID {
			provider, key = choice.Name, providerStatus(choice)
		}
	}
	modelName, level := "(not chosen)", "provider default"
	if model.defaults.Model != "" {
		modelName = model.defaults.Model
	}
	if model.defaults.Reasoning != "" {
		level = model.defaults.Reasoning
	}

	lead := []string{model.oneLineHeader(), "", model.accentLine("Settings"), "",
		model.bodyLine("Provider:   " + safeText(provider)),
		model.bodyLine("Model:      " + safeText(modelName)),
		model.bodyLine("Reasoning:  " + safeText(level))}
	if key != "" {
		lead = append(lead, model.bodyLine("API key:    "+safeText(key)))
	}
	lead = append(lead, "")

	var trail []string
	if model.notice != "" {
		trail = []string{"", model.accentLine(model.notice)}
	}

	items := model.settingsItems()
	labels := make([]string, len(items))
	for index, item := range items {
		labels[index] = item.label
	}

	return model.page(lead, labels, model.settingsCursor, trail,
		model.footer(hint{"up/down", "move"}, hint{"enter", "choose"}, hint{"esc", "back"}, hint{"q", "quit"}))
}

// shownLine is a piece of the dry run on the screen. A long line is wrapped into several pieces.
type shownLine struct {
	text string
}

// wrapLine cuts a line into pieces that fit the width. It cuts at a space when it can, and by width
// when a word is longer than the line, because a Japanese character takes two columns.
func wrapLine(text string, width int) []string {
	if width <= 0 || runewidth.StringWidth(text) <= width {
		return []string{text}
	}

	var pieces []string
	runes := []rune(text)
	for len(runes) > 0 {
		used, cut, lastSpace := 0, 0, -1
		for cut < len(runes) {
			next := runewidth.RuneWidth(runes[cut])
			if used+next > width && cut > 0 {
				break
			}
			used += next
			if runes[cut] == ' ' {
				lastSpace = cut
			}
			cut++
		}
		if cut < len(runes) && lastSpace > 0 {
			pieces = append(pieces, string(runes[:lastSpace]))
			runes = runes[lastSpace+1:]
			continue
		}
		pieces = append(pieces, string(runes[:cut]))
		runes = runes[cut:]
	}

	return pieces
}

// consentLead is the lines above the dry run on the dry run page.
func (model Model) consentLead() []string {
	consent := ""
	if model.plan != nil {
		consent = model.plan.ConsentText
	}

	return []string{model.oneLineHeader(), "", model.accentLine("Please confirm before anything is sent"), "",
		model.warnLine(consent), "", model.dimLine(model.dryRunTitle()), ""}
}

func (model Model) consentBody() []shownLine {
	if model.plan == nil {
		return nil
	}
	text := model.plan.Preview
	if model.plan.Summary != "" && !model.consentFull {
		text = model.plan.Summary
	}

	var shown []shownLine
	for _, line := range strings.Split(safeText(text), "\n") {
		for _, piece := range wrapLine(line, model.width) {
			shown = append(shown, shownLine{text: piece})
		}
	}

	return shown
}

func (model Model) consentViewHeight() int {
	if model.height <= 0 {
		return max(len(model.consentBody()), 1)
	}

	return max(model.height-len(model.consentLead())-2, 1)
}

func (model Model) maxConsentScroll() int {
	return max(len(model.consentBody())-model.consentViewHeight(), 0)
}

func (model Model) dryRunTitle() string {
	if model.plan != nil && model.plan.Summary != "" && !model.consentFull {
		return "Nothing has been sent yet. This is a summary of the first request:"
	}

	return "Nothing has been sent yet. This is the dry run:"
}

func (model Model) consentView() string {
	lines := model.consentLead()

	body := model.consentBody()
	start := min(model.consentScroll, model.maxConsentScroll())
	end := min(start+model.consentViewHeight(), len(body))
	for _, line := range body[start:end] {
		lines = append(lines, styleBody.Render(model.truncate(line.text, 0)))
	}

	hints := []hint{{"enter", "send and start"}, {"up/down", "scroll"}}
	if model.plan != nil && model.plan.Summary != "" {
		if model.consentFull {
			hints = append(hints, hint{"d", "summary"})
		} else {
			hints = append(hints, hint{"d", "full request"})
		}
	}

	return model.plainPage(lines, model.footer(append(hints, hint{"esc", "cancel"}, hint{"q", "quit"})...))
}

var spinnerFrames = []string{"✻", "✽", "✶", "✳"}

// runView is the only line that stays at the bottom of the normal terminal. It has no frame,
// because the output above it is what matters, and it is not a chat.
func (model Model) runView() string {
	if !model.running {
		return model.footer(hint{"enter", "back to the menu"}, hint{"q", "quit"})
	}

	title, style := "Running: Task A, exposure check", styleAccent
	if model.cancelling {
		title, style = "Cancelling... waiting for the current step to stop", styleWarn
	}
	mark := spinnerFrames[model.frame%len(spinnerFrames)]

	// The line is cut once, as a whole, so that it never goes over the width.
	const keys = "  (esc: cancel, q: quit)"
	line := model.truncate(mark+" "+title+keys, 0)
	if first, found := strings.CutSuffix(line, keys); found {
		return style.Render(first) + styleDim.Render(keys)
	}

	return style.Render(line)
}
