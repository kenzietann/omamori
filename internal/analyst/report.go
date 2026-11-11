package analyst

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Markdown renders only fixed text and facts the checker reconstructed. Dynamic evidence is placed in
// code paragraphs; the static HTML renderer also escapes every character. Provider state is added by
// the session layer, because claim verification and a completed provider call are different things.
func Markdown(result Result) string {
	var out strings.Builder
	out.WriteString("## AI analyst\n\n")
	fmt.Fprintf(&out, "- Claim check: %s\n- Verified claims: %d\n- Rejected claims: %d\n- Included alerts not reviewed: %d\n\n", result.Status,
		len(result.Verified), len(result.Rejected), len(result.Unreviewed))
	out.WriteString("Only claims checked against the detected alerts and their evidence appear below. No unverified AI narrative is shown.\n\n")
	if len(result.Verified) == 0 {
		out.WriteString("No checked AI claims are available. The deterministic detection results remain the source of alerts.\n\n")
	}
	for number, finding := range result.Verified {
		fmt.Fprintf(&out, "Checked claim %d:\n\n    %s\n\n", number+1, oneLine(finding.Summary))
		fmt.Fprintf(&out, "    Alerts: %s\n    From: %s\n    To: %s\n\n", strings.Join(finding.Alerts, ", "), finding.First, finding.Last)
		out.WriteString("Cited evidence:\n\n")
		for _, evidence := range finding.Evidence {
			fmt.Fprintf(&out, "    %s — %s at %s\n", evidence.ID, oneLine(evidence.Ref), evidence.Time)
		}
		out.WriteString("\n")
		if len(finding.Actions) > 0 {
			out.WriteString("Suggested review steps (not executed):\n\n")
			for _, action := range finding.Actions {
				fmt.Fprintf(&out, "- %s\n", action.Text)
			}
			out.WriteString("\n")
		}
	}
	if len(result.Rejected) > 0 {
		out.WriteString("Rejected claims:\n\n")
		for _, rejected := range result.Rejected {
			if rejected.Claim == 0 {
				fmt.Fprintf(&out, "- %s\n", rejected.Reason)
			} else {
				fmt.Fprintf(&out, "- Claim %d: %s\n", rejected.Claim, rejected.Reason)
			}
		}
		out.WriteString("\n")
	}
	if len(result.Unreviewed) > 0 {
		fmt.Fprintf(&out, "Included alerts without a checked AI claim: %s. They remain in the detection report.\n\n", strings.Join(result.Unreviewed, ", "))
	}
	out.WriteString("Analysis coverage:\n\n")
	fmt.Fprintf(&out, "- %d of %d alerts were included; %d alerts were omitted by the analysis limit.\n", result.Coverage.IncludedAlerts, result.Coverage.TotalAlerts, result.Coverage.OmittedAlerts)
	fmt.Fprintf(&out, "- At least %d events or hits from the included alerts were not shown as evidence. Nested correlation totals may be larger.\n", result.Coverage.OmittedEvidence)
	fmt.Fprintf(&out, "- Intake reported %d malformed lines and %d skipped files; %d rules reached a match limit.\n", result.Coverage.MalformedLines, result.Coverage.SkippedFiles, result.Coverage.RulesCut)
	out.WriteString("- These checks establish agreement with the available logs and rules. They do not establish intent, a successful attack, attribution, or the absence of activity outside this evidence.\n")
	return out.String()
}

func oneLine(text string) string { return strings.Join(strings.Fields(text), " ") }

// JSON is a versioned result for local consumers, including the future dashboard. It does not contain
// raw model output. Transport status and recording metadata belong to the session result.
func JSON(result Result) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}
