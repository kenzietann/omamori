package sanitizer

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/kenzietann/omamori/internal/edge"
	"github.com/kenzietann/omamori/internal/mynumber"
	"github.com/kenzietann/omamori/internal/phone"
	"github.com/kenzietann/omamori/internal/secrets"
)

// NumberLike is the label of digits that look like a phone number or a My Number but sit inside a longer
// number or a name.
const NumberLike = "NUMBERLIKE"

type Finding struct {
	Placeholder string
	Start       int
	End         int
}

type Sanitizer struct {
	counters map[string]int
}

type span struct {
	start    int
	end      int
	label    string
	priority int
}

func findSpans(text string) []span {
	var spans []span

	for _, match := range secrets.FindSecrets(text) {
		label := "SECRET:" + match.Kind
		// A password like user:pass in an address is an example from a document or a test. It is hidden as well.
		if match.Kind == "url-credentials" && edge.PlaceholderCredentials(text[match.Start:match.End]) {
			label = "EXAMPLE:" + match.Kind
		}
		spans = append(spans, span{start: match.Start, end: match.End, label: label, priority: 0})
	}
	// A number inside a decimal (0.0643290124), a UUID, a row of digit groups, or next to letters (abc0312345678)
	// is hidden like any other, because a missed value costs more than a needless placeholder. It gets its own
	// label, so that the report can tell the user that it is most likely a coordinate, an id or a test value.
	for _, match := range mynumber.FindMyNumbers(text) {
		label := "MYNUMBER"
		if edge.Embedded(text, match.Start, match.End) || edge.InUUID(text, match.Start, match.End) || edge.InChain(text, match.Start, match.End) || edge.Trivial(text[match.Start:match.End]) {
			label = NumberLike
		}
		spans = append(spans, span{start: match.Start, end: match.End, label: label, priority: 1})
	}
	for _, match := range phone.FindPhoneNumbers(text) {
		label := "PHONE"
		if edge.Embedded(text, match.Start, match.End) || edge.InUUID(text, match.Start, match.End) || edge.Trivial(text[match.Start:match.End]) {
			label = NumberLike
		}
		spans = append(spans, span{start: match.Start, end: match.End, label: label, priority: 2})
	}

	return spans
}

func mergeSpans(spans []span) []span {
	slices.SortFunc(spans, func(first, second span) int {
		return cmp.Or(cmp.Compare(first.start, second.start), cmp.Compare(first.priority, second.priority))
	})

	var merged []span

	for _, current := range spans {
		last := len(merged) - 1

		if last >= 0 && current.start < merged[last].end {
			merged[last].end = max(merged[last].end, current.end)
			if current.priority < merged[last].priority {
				merged[last].label = current.label
				merged[last].priority = current.priority
			}
			continue
		}

		merged = append(merged, current)
	}

	return merged
}

func (sanitizer *Sanitizer) Sanitize(text string) (string, []Finding) {
	if sanitizer.counters == nil {
		sanitizer.counters = make(map[string]int)
	}

	var builder strings.Builder
	var findings []Finding
	cursor := 0

	for _, current := range mergeSpans(findSpans(text)) {
		sanitizer.counters[current.label]++
		placeholder := fmt.Sprintf("[%s:%03d]", current.label, sanitizer.counters[current.label])

		builder.WriteString(text[cursor:current.start])
		builder.WriteString(placeholder)
		findings = append(findings, Finding{Placeholder: placeholder, Start: current.start, End: current.end})
		cursor = current.end
	}
	builder.WriteString(text[cursor:])

	return builder.String(), findings
}
