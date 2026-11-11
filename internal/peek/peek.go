// Package peek shows the user what a report matched, on the user's own screen.
//
// A report holds places and placeholders only. A user who wants to tell a false alarm from a real leak needs to
// see the text around the match. This package finds the match again in the file and returns a masked excerpt.
// The result is for the terminal only: nothing here writes a file, and nothing is sent anywhere. The AI never gets it.
package peek

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

const (
	maxFileBytes = 8 << 20
	contextBytes = 45
)

var (
	ErrNoReport  = errors.New("no report was found there")
	ErrNoMatches = errors.New("the report lists no matches")

	// "- path:line [LABEL:001]" or "- path:line [LABEL:001]–[LABEL:005] (5 phone matches)".
	bulletPattern      = regexp.MustCompile(`^- (.+):(\d+) \[((?:SECRET:[a-z0-9-]+)|MYNUMBER|PHONE):(\d{3,})\](?:–\[[A-Za-z:0-9-]+:(\d{3,})\])?`)
	placeholderPattern = regexp.MustCompile(`^\[(.+):(\d{3,})\]$`)
)

// Item is one match that the report lists.
type Item struct {
	Placeholder string
	File        string
	Line        int
	label       string
	number      int
}

// Shown is a match with its excerpt. Value and Context are masked unless the user asked to reveal them.
type Shown struct {
	Item
	Value   string
	Context string
	// Problem is set when the match could not be shown, with a fixed reason.
	Problem string
}

// ReadReport finds the matches in the text of a Markdown report. The same match can be listed in
// more than one section; it is returned once.
func ReadReport(report string) ([]Item, error) {
	var items []Item
	seen := map[string]bool{}
	for _, line := range strings.Split(report, "\n") {
		parts := bulletPattern.FindStringSubmatch(line)
		if parts == nil {
			continue
		}
		lineNumber, _ := strconv.Atoi(parts[2])
		first, _ := strconv.Atoi(parts[4])
		last := first
		if parts[5] != "" {
			last, _ = strconv.Atoi(parts[5])
		}
		if lineNumber < 1 || last < first || last-first > 10000 {
			continue
		}

		for number := first; number <= last; number++ {
			placeholder := fmt.Sprintf("[%s:%03d]", parts[3], number)
			if seen[placeholder] {
				continue
			}
			seen[placeholder] = true
			items = append(items, Item{Placeholder: placeholder, File: parts[1], Line: lineNumber, label: parts[3], number: number})
		}
	}
	if len(items) == 0 {
		return nil, ErrNoMatches
	}

	return items, nil
}

type location struct {
	start, end int
	line       int
	label      string
}

// Show finds each match again in its file. With reveal, the matched value is shown as it is. Without it,
// the middle of the value is hidden. Text near the match is always masked, and a private key block is never
// shown, only its first line.
func Show(root *pathguard.Root, items []Item, reveal bool) []Shown {
	cache := map[string]*fileView{}
	groups := map[string][]int{}
	for index, item := range items {
		key := fmt.Sprintf("%s\x00%d\x00%s", item.File, item.Line, item.label)
		groups[key] = append(groups[key], index)
	}

	shown := make([]Shown, len(items))
	for _, indexes := range groups {
		slices.SortFunc(indexes, func(first, second int) int { return items[first].number - items[second].number })

		item := items[indexes[0]]
		view := viewOf(root, item.File, cache)
		if view.problem != "" {
			for _, index := range indexes {
				shown[index] = Shown{Item: items[index], Problem: view.problem}
			}
			continue
		}

		var found []location
		for _, current := range view.locations {
			if current.line == item.Line && current.label == item.label {
				found = append(found, current)
			}
		}
		for position, index := range indexes {
			if position >= len(found) {
				shown[index] = Shown{Item: items[index], Problem: "not found at this line: the file may have changed since the scan"}
				continue
			}
			shown[index] = describe(items[index], view, found[position], reveal)
		}
	}

	return shown
}

type fileView struct {
	text      string
	locations []location
	problem   string
}

func viewOf(root *pathguard.Root, file string, cache map[string]*fileView) *fileView {
	if cached, found := cache[file]; found {
		return cached
	}
	view := &fileView{}
	cache[file] = view

	if strings.Contains(file, "[SECRET:") || strings.Contains(file, "[MYNUMBER:") || strings.Contains(file, "[PHONE:") {
		view.problem = "the file name holds a hidden value, so the file cannot be found again"
		return view
	}
	resolved, err := root.Resolve(file)
	if err != nil {
		view.problem = "the file is not there, or it is outside the project folder"
		return view
	}
	handle, err := os.Open(resolved)
	if err != nil {
		view.problem = "the file could not be opened"
		return view
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, maxFileBytes+1))
	if err != nil || len(data) > maxFileBytes {
		view.problem = "the file could not be read or is too large"
		return view
	}

	view.text = string(data)
	var finder sanitizer.Sanitizer
	_, findings := finder.Sanitize(view.text)
	line, position := 1, 0
	for _, finding := range findings {
		line += strings.Count(view.text[position:finding.Start], "\n")
		position = finding.Start
		parts := placeholderPattern.FindStringSubmatch(finding.Placeholder)
		if parts == nil {
			continue
		}
		view.locations = append(view.locations, location{start: finding.Start, end: finding.End, line: line, label: parts[1]})
	}
	sort.SliceStable(view.locations, func(first, second int) bool { return view.locations[first].start < view.locations[second].start })

	return view
}

func describe(item Item, view *fileView, current location, reveal bool) Shown {
	value := view.text[current.start:current.end]
	if strings.HasSuffix(current.label, "private-key") {
		first, _, _ := strings.Cut(value, "\n")

		return Shown{Item: item, Value: clean(first) + fmt.Sprintf(" (a private key block of %d lines, never shown)", strings.Count(value, "\n")+1), Context: ""}
	}

	shownValue := Mask(value)
	if reveal {
		shownValue = clean(value)
	}

	return Shown{Item: item, Value: shownValue, Context: contextAround(view, current, reveal)}
}

// contextAround is the text near the match on its line. Every match in it is masked, except the match itself with reveal.
func contextAround(view *fileView, target location, reveal bool) string {
	from := max(target.start-contextBytes, 0)
	to := min(target.end+contextBytes, len(view.text))
	for from > 0 && !isRuneStart(view.text[from]) {
		from--
	}
	for to < len(view.text) && !isRuneStart(view.text[to]) {
		to++
	}
	cutLeft, cutRight := from > 0, to < len(view.text)
	if newline := strings.LastIndex(view.text[from:target.start], "\n"); newline >= 0 {
		from += newline + 1
		cutLeft = false
	} else if from == 0 {
		cutLeft = false
	}
	if newline := strings.Index(view.text[target.end:to], "\n"); newline >= 0 {
		to = target.end + newline
		cutRight = false
	} else if to == len(view.text) {
		cutRight = false
	}

	var out strings.Builder
	cursor := from
	for _, current := range view.locations {
		if current.end <= from || current.start >= to {
			continue
		}
		if current.start < cursor {
			continue
		}
		out.WriteString(clean(view.text[cursor:current.start]))
		piece := view.text[current.start:min(current.end, to)]
		if reveal && current.start == target.start {
			out.WriteString(clean(piece))
		} else {
			out.WriteString(Mask(clean(piece)))
		}
		cursor = min(current.end, to)
	}
	if cursor < to {
		out.WriteString(clean(view.text[cursor:to]))
	}

	text := strings.TrimSpace(out.String())
	if cutLeft {
		text = "…" + text
	}
	if cutRight {
		text += "…"
	}

	return text
}

func isRuneStart(character byte) bool { return character&0xC0 != 0x80 }

// clean makes text safe to print: no control characters that could move the cursor or hide text.
func clean(text string) string {
	return strings.Map(func(character rune) rune {
		switch {
		case character == '\t' || character == '\n' || character == '\r':
			return ' '
		case unicode.IsControl(character) || character == ' ' || character == ' ':
			return '?'
		}

		return character
	}, text)
}

// Mask hides the middle of a value and keeps its shape. "090-1234-5678" becomes "090-****-**78".
func Mask(value string) string {
	runes := []rune(value)
	front, back := 0, 0
	switch {
	case len(runes) >= 10:
		front, back = 3, 2
	case len(runes) >= 6:
		front, back = 1, 1
	}

	for index := front; index < len(runes)-back; index++ {
		if unicode.IsLetter(runes[index]) || unicode.IsDigit(runes[index]) || runes[index] == '_' {
			runes[index] = '*'
		}
	}

	return string(runes)
}
