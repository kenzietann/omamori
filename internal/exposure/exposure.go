package exposure

import (
	"cmp"
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/gateway"
)

const Instruction = `Check this project for exposed secrets and personal data. ` +
	`Run run_detectors on the path "." first. Then explain each finding by its placeholder and suggest a fix. Do not guess any value.`

var detectorLine = regexp.MustCompile(`^(.*):(\d+): (\[(SECRET:[a-z0-9-]+|MYNUMBER|PHONE):\d{3,}\])$`)

type Finding struct {
	Severity    string
	Type        string
	File        string
	Line        int
	Placeholder string
	Advice      string
}

type Stats struct {
	Scans     int
	Truncated bool
	Skipped   int
	Unparsed  int
}

type Collector struct {
	inner    agent.Tools
	findings map[string]Finding
	stats    Stats
}

func NewCollector(inner agent.Tools) *Collector {
	return &Collector{inner: inner, findings: make(map[string]Finding)}
}

func (collector *Collector) Call(ctx context.Context, toolName string, arguments map[string]any) (gateway.Result, error) {
	result, err := collector.inner.Call(ctx, toolName, arguments)
	if err != nil || toolName != "run_detectors" {
		return result, err
	}

	collector.stats.Scans++
	collector.stats.Skipped += result.Skipped
	if result.Truncated {
		collector.stats.Truncated = true
	}
	collector.absorb(result.Text)

	return result, nil
}

func (collector *Collector) Stats() Stats {
	return collector.stats
}

// A file that is scanned twice gives the same lines twice. The key makes the second copy
// count as the first one. A second finding of the same type on the same line has its own
// occurrence number, so it is not lost.
func (collector *Collector) absorb(text string) {
	occurrences := make(map[string]int)

	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}

		finding, ok := parseDetectorLine(line)
		if !ok {
			collector.stats.Unparsed++
			continue
		}

		where := fmt.Sprintf("%s\x00%d\x00%s", finding.File, finding.Line, finding.Type)
		key := fmt.Sprintf("%s\x00%d", where, occurrences[where])
		occurrences[where]++

		if _, seen := collector.findings[key]; !seen {
			collector.findings[key] = finding
		}
	}
}

func parseDetectorLine(line string) (Finding, bool) {
	parts := detectorLine.FindStringSubmatch(line)
	if parts == nil {
		return Finding{}, false
	}

	lineNumber, err := strconv.Atoi(parts[2])
	if err != nil || lineNumber < 1 {
		return Finding{}, false
	}

	findingType, severity, advice := describe(parts[4])

	return Finding{
		Severity:    severity,
		Type:        findingType,
		File:        parts[1],
		Line:        lineNumber,
		Placeholder: parts[3],
		Advice:      advice,
	}, true
}

func describe(label string) (findingType, severity, advice string) {
	switch {
	case label == "SECRET:aws-access-key":
		return "aws-access-key", "high", "Rotate this AWS access key in IAM, then check CloudTrail for use. Remove it from the code and from the git history. Use a secrets manager or an environment variable."
	case label == "SECRET:github-token":
		return "github-token", "high", "Revoke this token in the GitHub settings, then create a new one with the smallest scope. Remove it from the code and from the git history."
	case label == "SECRET:private-key":
		return "private-key", "high", "Treat this private key as leaked: create a new key pair and replace the old one everywhere it was used. Remove the file from the code and from the git history."
	case label == "SECRET:ai-api-key":
		return "ai-api-key", "high", "Revoke this AI provider key in the provider console, then create a new one. Check the usage page for calls you did not make. Remove it from the code and from the git history."
	case label == "SECRET:url-credentials":
		return "url-credentials", "high", "Change the password of this account. Take the password out of the address and read it from an environment variable or a secrets manager."
	case label == "SECRET:jwt":
		return "jwt", "high", "A token that is still valid can be used by anyone who has it. Revoke or let it expire, check that its signing key is not exposed, and remove it from the code."
	case strings.HasPrefix(label, "SECRET:"):
		return strings.TrimPrefix(label, "SECRET:"), "high", "Rotate this secret. Remove it from the code and from the git history."
	case label == "MYNUMBER":
		return "mynumber", "high", "This is a possible My Number (the check digit is valid). Remove it from the file. Check if the file is shared or kept in version control."
	}

	return "phone", "medium", "This looks like a Japanese phone number. Remove it if it belongs to a person."
}

func severityRank(severity string) int {
	if severity == "high" {
		return 0
	}

	return 1
}

func (collector *Collector) Findings() []Finding {
	found := make([]Finding, 0, len(collector.findings))
	for _, finding := range collector.findings {
		found = append(found, finding)
	}

	slices.SortFunc(found, func(first, second Finding) int {
		return cmp.Or(
			cmp.Compare(severityRank(first.Severity), severityRank(second.Severity)),
			cmp.Compare(first.File, second.File),
			cmp.Compare(first.Line, second.Line),
			cmp.Compare(first.Placeholder, second.Placeholder),
		)
	})

	return found
}

type Runner interface {
	Run(ctx context.Context, instruction string) agent.Outcome
}

func Run(ctx context.Context, runner Runner, collector *Collector) (string, agent.Outcome, error) {
	outcome := runner.Run(ctx, Instruction)
	report, err := Render(collector.Findings(), collector.Stats(), outcome)

	return report, outcome, err
}
