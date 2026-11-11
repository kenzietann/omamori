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

	var exposed, keptOut, notYours, doubtful []Finding
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityKeptOut:
			keptOut = append(keptOut, finding)
		case SeverityNotYours:
			notYours = append(notYours, finding)
		case SeverityDoubtful:
			doubtful = append(doubtful, finding)
		default:
			exposed = append(exposed, finding)
		}
	}
	notCounted := len(keptOut) + len(notYours) + len(doubtful)

	report.WriteString("## Findings\n\n")
	switch {
	case stats.Scans == 0:
		report.WriteString("No scan ran, so nothing was checked. This report has no findings because nothing was looked at.\n\n")
	case len(exposed) == 0 && notCounted > 0:
		report.WriteString("The scans that ran reported no exposed data. Matches that are not counted (a key that .gitignore keeps out of git, text in a library or a generated file, or digits inside a decimal number or a name) are listed below. This does not prove that the project is clean. See Limits.\n\n")
	case len(exposed) == 0:
		report.WriteString("The scans that ran reported no findings. This does not prove that the project is clean. See Limits.\n\n")
	default:
		report.WriteString("| ID | Severity | Type | File | Line |\n|---|---|---|---|---|\n")
		for _, finding := range exposed {
			fmt.Fprintf(&report, "| %s | %s | %s | %s | %d |\n", plainText(finding.Placeholder), finding.Severity, plainText(finding.Type), plainText(finding.File), finding.Line)
		}
		report.WriteString("\n")
	}

	if len(exposed) > 0 {
		report.WriteString("## Evidence locations\n\n")
		for _, finding := range exposed {
			fmt.Fprintf(&report, "- %s:%d %s\n", plainText(finding.File), finding.Line, plainText(finding.Placeholder))
		}
		report.WriteString("\n## Fixes\n\n")
		report.WriteString(renderFixes(exposed))
		report.WriteString("\n")
	}

	if len(keptOut) > 0 {
		report.WriteString("## Kept out of git (not counted as findings)\n\n")
		report.WriteString("These are keys in env files that a .gitignore file keeps out of git. This is the normal setup for a key. The AI did not see the .gitignore files, so if a note below calls one of these keys exposed, this section is the checked answer.\n\n")
		for _, finding := range keptOut {
			fmt.Fprintf(&report, "- %s:%d %s (%s)\n", plainText(finding.File), finding.Line, plainText(finding.Placeholder), plainText(finding.Type))
		}
		report.WriteString("\n")
	}

	if len(notYours) > 0 {
		report.WriteString("## Library and generated files (not counted as findings)\n\n")
		report.WriteString("These matches are in code of other projects, in caches, or in files that a tool made. They are not your code, so they are not counted. Most are sample text. A real number in a library is not your responsibility.\n\n")
		report.WriteString(renderNotYours(notYours))
		report.WriteString("\n")
	}

	if len(doubtful) > 0 {
		report.WriteString("## Probably not real (not counted as findings)\n\n")
		report.WriteString("These look like a phone number, a My Number or a password in an address, but most likely they are not: digits inside a long decimal, a UUID, a table of numbers or a name (coordinates, ids, hashes), test values (digits that count up or repeat), and example passwords like user:pass. Omamori hides them from the AI like any other match, and does not count them. Look at them with omamori peek if you want to be sure.\n\n")
		report.WriteString(renderNotYours(doubtful))
		report.WriteString("\n")
	}

	if len(findings) > 0 {
		report.WriteString("To see what was matched, masked and on your screen only, run: omamori peek <this report folder> <project folder>\n\n")
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

// renderNotYours folds the matches of one type on one line into one bullet.
func renderNotYours(findings []Finding) string {
	var out strings.Builder
	for index := 0; index < len(findings); {
		first := findings[index]
		end := index + 1
		for end < len(findings) && findings[end].File == first.File && findings[end].Line == first.Line && findings[end].Type == first.Type {
			end++
		}

		where := fmt.Sprintf("%s:%d %s", plainText(first.File), first.Line, plainText(first.Placeholder))
		if end-index > 1 {
			where += "–" + plainText(findings[end-1].Placeholder) + fmt.Sprintf(" (%d %s matches)", end-index, plainText(first.Type))
		} else {
			where += fmt.Sprintf(" (%s)", plainText(first.Type))
		}
		fmt.Fprintf(&out, "- %s\n", where)
		index = end
	}

	return out.String()
}

func renderFixes(findings []Finding) string {
	counts := make(map[string]int)
	adviceFor := make(map[string]string)
	for _, finding := range findings {
		key := finding.Type
		if finding.Severity == "low" {
			key += " in generated files"
		}
		counts[key]++
		adviceFor[key] = finding.Advice
	}

	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	var fixes strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&fixes, "- %s (%d): %s\n", plainText(key), counts[key], adviceFor[key])
	}

	return fixes.String()
}

func renderLimits(stats Stats) string {
	var limits strings.Builder

	limits.WriteString("## Limits\n\n")
	limits.WriteString("- Omamori looks for: AWS access key IDs (AKIA, ASIA), GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_), AI provider keys (sk-), Google API keys (AIza), Slack tokens (xox), Stripe live keys, JWTs, private key blocks, passwords written inside web addresses, My Number, and Japanese phone numbers.\n")
	limits.WriteString("- It does not find or hide other secret formats, passwords, email addresses, IP addresses, names, or street addresses.\n")
	limits.WriteString("- A My Number with a valid check digit is a possible identifier, not proof.\n")
	limits.WriteString("- For a key in an env file (.env), the .gitignore files inside the scanned folder are read. Omamori does not check git itself: a file that was committed before it was ignored is still in the git history.\n")
	limits.WriteString("- Findings come only from the files that the scans in this run covered. Anything else is not covered.\n")
	limits.WriteString("- These are not scanned: the .git folder (the history of the project), dependency folders (node_modules, vendor, venv, .venv, __pycache__), and lock files. A secret that was committed earlier and later removed is not found.\n")
	limits.WriteString("- A placeholder in a file name stands for a secret found in the name. The real name is not shown. Placeholder numbers come from the scan and can change from run to run.\n")
	limits.WriteString("- The AI notes are written by the AI. Omamori did not check them.\n")
	if stats.Skipped > 0 {
		fmt.Fprintf(&limits, "- %d files were skipped because they were too large, binary, or could not be read.\n", stats.Skipped)
	}
	if stats.Truncated {
		limits.WriteString("- At least one scan stopped at a limit, so some findings may be missing.\n")
	}
	if stats.Unparsed > 0 {
		fmt.Fprintf(&limits, "- %d lines of scan output could not be read and are not in the findings.\n", stats.Unparsed)
	}

	return limits.String()
}
