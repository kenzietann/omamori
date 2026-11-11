package exposure

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

const maxNotesRunes = 4000

var ErrUnsafeReport = errors.New("the report could not be made safe")

func plainText(text string) string {
	return strings.Map(func(character rune) rune {
		switch {
		case unicode.IsControl(character):
			return '?'
		case strings.ContainsRune("|`<>&", character):
			return '_'
		}

		return character
	}, text)
}

func cleanNotes(text string) string {
	withoutControls := strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' {
			return character
		}
		if unicode.IsControl(character) {
			return -1
		}

		return character
	}, text)

	runes := []rune(withoutControls)
	if len(runes) > maxNotesRunes {
		runes = runes[:maxNotesRunes]
	}

	cleaned, _ := (&sanitizer.Sanitizer{}).Sanitize(string(runes))

	return cleaned
}

func Render(findings []Finding, stats Stats, outcome agent.Outcome) (string, error) {
	var report strings.Builder

	report.WriteString("# Omamori report: exposure check\n\n")
	if outcome.Status == agent.Complete {
		report.WriteString("Status: complete\n")
	} else {
		fmt.Fprintf(&report, "Status: incomplete (%s)\n", plainText(outcome.Reason))
	}
	fmt.Fprintf(&report, "Scans completed: %d\n\n", stats.Scans)

	report.WriteString("## Findings\n\n")
	switch {
	case stats.Scans == 0:
		report.WriteString("No scan ran, so nothing was checked. This report has no findings because nothing was looked at.\n\n")
	case len(findings) == 0:
		report.WriteString("The scans that ran reported no findings. This does not prove that the project is clean. See Limits.\n\n")
	default:
		report.WriteString("| ID | Severity | Type | File | Line |\n|---|---|---|---|---|\n")
		for _, finding := range findings {
			fmt.Fprintf(&report, "| %s | %s | %s | %s | %d |\n", plainText(finding.Placeholder), finding.Severity, plainText(finding.Type), plainText(finding.File), finding.Line)
		}
		report.WriteString("\n")
	}

	if len(findings) > 0 {
		report.WriteString("## Evidence locations\n\n")
		for _, finding := range findings {
			fmt.Fprintf(&report, "- %s:%d %s\n", plainText(finding.File), finding.Line, plainText(finding.Placeholder))
		}
		report.WriteString("\n## Fixes\n\n")
		report.WriteString(renderFixes(findings))
		report.WriteString("\n")
	}

	if len(outcome.Texts) > 0 {
		report.WriteString("## AI notes (not checked by Omamori)\n\n")
		for _, line := range strings.Split(cleanNotes(strings.Join(outcome.Texts, "\n\n")), "\n") {
			report.WriteString("    " + line + "\n")
		}
		report.WriteString("\n")
	}

	report.WriteString(renderLimits(stats))

	text := report.String()
	if _, found := (&sanitizer.Sanitizer{}).Sanitize(text); len(found) > 0 {
		return "", ErrUnsafeReport
	}

	return text, nil
}

func renderFixes(findings []Finding) string {
	counts := make(map[string]int)
	adviceFor := make(map[string]string)
	for _, finding := range findings {
		counts[finding.Type]++
		adviceFor[finding.Type] = finding.Advice
	}

	types := make([]string, 0, len(counts))
	for findingType := range counts {
		types = append(types, findingType)
	}
	slices.Sort(types)

	var fixes strings.Builder
	for _, findingType := range types {
		fmt.Fprintf(&fixes, "- %s (%d): %s\n", plainText(findingType), counts[findingType], adviceFor[findingType])
	}

	return fixes.String()
}

func renderLimits(stats Stats) string {
	var limits strings.Builder

	limits.WriteString("## Limits\n\n")
	limits.WriteString("- Omamori looks for four things: AWS access key IDs (AKIA, ASIA), GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_), My Number, and Japanese phone numbers.\n")
	limits.WriteString("- It does not find or hide other secret formats, passwords, email addresses, IP addresses, names, or street addresses.\n")
	limits.WriteString("- A My Number with a valid check digit is a possible identifier, not proof.\n")
	limits.WriteString("- Findings come only from the files that the scans in this run covered. Anything else is not covered.\n")
	limits.WriteString("- The .git folder (the history of the project) is not scanned. A secret that was committed earlier and later removed is not found.\n")
	limits.WriteString("- A placeholder in a file name stands for a secret found in the name. The real name is not shown. Placeholder numbers come from the scan and can change from run to run.\n")
	limits.WriteString("- The AI notes are written by the AI. Omamori did not check them.\n")
	if stats.Skipped > 0 {
		fmt.Fprintf(&limits, "- %d files were skipped because they were too large or could not be read.\n", stats.Skipped)
	}
	if stats.Truncated {
		limits.WriteString("- At least one scan stopped at a limit, so some findings may be missing.\n")
	}
	if stats.Unparsed > 0 {
		fmt.Fprintf(&limits, "- %d lines of scan output could not be read and are not in the findings.\n", stats.Unparsed)
	}

	return limits.String()
}
