// Package livetest runs a small fixed set of real-provider runs on the fake fixtures and scores them
// on correct findings and correct evidence locations, not on wording (FR-19).
package livetest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Verdict is the score of one run.
type Verdict struct {
	Passed bool
	// Detail is a short fixed-form reason. It holds counts, placeholders and locations, never a value.
	Detail string
}

type expectedExposure struct {
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Placeholder string `json:"placeholder"`
}

// LoadExposure reads the expected findings of the exposure fixture as comparable rows.
func LoadExposure(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the expected findings could not be read")
	}
	var expected []expectedExposure
	if err := json.Unmarshal(data, &expected); err != nil {
		return nil, fmt.Errorf("the expected findings are not valid")
	}
	rows := make([]string, 0, len(expected))
	for _, finding := range expected {
		rows = append(rows, row(finding.Placeholder, finding.Severity, finding.Type, finding.File, fmt.Sprint(finding.Line)))
	}
	slices.Sort(rows)

	return rows, nil
}

// LoadTriage reads how many findings each triage log should give, and the year of its lines.
func LoadTriage(path string) (counts map[string]int, year int, err error) {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, 0, fmt.Errorf("the expected findings could not be read")
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return nil, 0, fmt.Errorf("the expected findings are not valid")
	}
	counts = map[string]int{}
	for name, value := range raw {
		if !strings.HasSuffix(name, ".log") {
			continue
		}
		var findings []json.RawMessage
		if json.Unmarshal(value, &findings) != nil {
			return nil, 0, fmt.Errorf("the expected findings are not valid")
		}
		counts[name] = len(findings)
	}
	if json.Unmarshal(raw["year"], &year) != nil || year == 0 {
		return nil, 0, fmt.Errorf("the expected findings have no year")
	}

	return counts, year, nil
}

func row(cells ...string) string { return strings.Join(cells, " | ") }

// ScoreExposure compares the Findings table of a Task A report with the expected rows.
// The report must hold exactly the expected rows, no more and no less.
func ScoreExposure(report string, expected []string) Verdict {
	found := findingRows(report)
	slices.Sort(found)
	if slices.Equal(found, expected) {
		return Verdict{Passed: true, Detail: fmt.Sprintf("%d of %d expected findings, nothing extra", len(found), len(expected))}
	}

	var missing, extra []string
	for _, want := range expected {
		if !slices.Contains(found, want) {
			missing = append(missing, want)
		}
	}
	for _, got := range found {
		if !slices.Contains(expected, got) {
			extra = append(extra, got)
		}
	}

	return Verdict{Detail: fmt.Sprintf("%d missing, %d extra", len(missing), len(extra))}
}

func findingRows(report string) []string {
	var rows []string
	inFindings := false
	for _, line := range strings.Split(report, "\n") {
		switch {
		case strings.HasPrefix(line, "## "):
			inFindings = line == "## Findings"
		case inFindings && strings.HasPrefix(line, "| ["):
			cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
			for index := range cells {
				cells[index] = strings.TrimSpace(cells[index])
			}
			rows = append(rows, row(cells...))
		}
	}

	return rows
}

// ScoreTriage reads the counts of a Task B report. The run passes when the AI's claims prove exactly
// the expected findings: none missed by the AI, none rejected, and none extra.
func ScoreTriage(report string, expected int) Verdict {
	var verified, missed, rejected int
	section := ""
	for _, line := range strings.Split(report, "\n") {
		switch {
		case strings.HasPrefix(line, "## "):
			section = line
		case strings.HasPrefix(line, "| T-") && strings.HasPrefix(section, "## Verified"):
			verified++
		case strings.HasPrefix(line, "| M-") && strings.HasPrefix(section, "## Found by Omamori"):
			missed++
		case strings.HasPrefix(line, "- Claim ") && strings.HasPrefix(section, "## Claims"):
			rejected++
		}
	}

	detail := fmt.Sprintf("%d of %d expected findings proved, %d missed by the AI, %d claims rejected", verified, expected, missed, rejected)
	if verified == expected && missed == 0 && rejected == 0 {
		return Verdict{Passed: true, Detail: detail}
	}

	return Verdict{Detail: detail}
}

// Path joins the folder of the fixtures with a name.
func Path(fixtures string, parts ...string) string {
	return filepath.Join(append([]string{fixtures}, parts...)...)
}
