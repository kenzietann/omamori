package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/eventlog"
	"github.com/kenzietann/omamori/internal/gateway"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

const fixtureDirectory = "../../testdata/fixtures/exposure"

var plantedValues = []string{
	"AKIAIOSFODNN7EXAMPLE",
	"ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1",
	"123123123128",
	"090-1234-5678",
	"080-9876-5432",
}

type expectedFinding struct {
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Placeholder string `json:"placeholder"`
}

type scriptedProvider struct {
	script   func(index int) outbound.Response
	recorded []outbound.Request
}

func (provider *scriptedProvider) Name() string { return "FakeAI" }

func (provider *scriptedProvider) Send(ctx context.Context, safe outbound.SafeRequest) (outbound.Response, error) {
	index := len(provider.recorded)
	provider.recorded = append(provider.recorded, safe.Request())

	return provider.script(index), nil
}

func scan(path string) outbound.Response {
	return outbound.Response{ToolCalls: []outbound.ToolCall{{Name: "run_detectors", Arguments: map[string]string{"path": path}}}}
}

func inOrder(responses ...outbound.Response) func(int) outbound.Response {
	return func(index int) outbound.Response {
		if index >= len(responses) {
			return outbound.Response{Text: "done"}
		}

		return responses[index]
	}
}

type runResult struct {
	project     string
	report      string
	outcome     agent.Outcome
	collector   *Collector
	provider    *scriptedProvider
	outputFiles map[string]string
}

func runFixture(t testing.TB, script func(int) outbound.Response, limits agent.Limits) runResult {
	t.Helper()

	project, err := filepath.Abs(filepath.Join(fixtureDirectory, "project"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := pathguard.NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}

	provider := &scriptedProvider{script: script}
	sender, err := outbound.New(provider, project)
	if err != nil {
		t.Fatal(err)
	}
	sender.Authorize()

	outputDirectory := filepath.Join(t.TempDir(), "out")
	writer, err := reportwriter.New(project, outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	appender, err := writer.Open("events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	log := eventlog.New(appender, time.Now)

	toolGateway := gateway.New(root, gateway.DefaultLimits)
	toolGateway.Observe(log.RecordGatewayEvent)
	collector := NewCollector(toolGateway)

	runner, err := agent.New(sender, collector, log, limits, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, outcome, err := Run(context.Background(), runner, collector)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Write("report.md", report); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	outputFiles := make(map[string]string)
	entries, err := os.ReadDir(outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(outputDirectory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		outputFiles[entry.Name()] = string(content)
	}

	return runResult{project: project, report: report, outcome: outcome, collector: collector, provider: provider, outputFiles: outputFiles}
}

var generousLimits = agent.Limits{MaxSteps: 20, MaxTokens: 100000}

func loadExpected(t testing.TB) []expectedFinding {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(fixtureDirectory, "expected_findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected []expectedFinding
	if err := json.Unmarshal(content, &expected); err != nil {
		t.Fatal(err)
	}

	return expected
}

func asExpected(findings []Finding) []expectedFinding {
	var converted []expectedFinding
	for _, finding := range findings {
		converted = append(converted, expectedFinding{finding.Severity, finding.Type, finding.File, finding.Line, finding.Placeholder})
	}

	return converted
}

var placeholderNumber = regexp.MustCompile(`:\d{3}\]`)

func withoutNumbers(findings []expectedFinding) []expectedFinding {
	var converted []expectedFinding
	for _, finding := range findings {
		finding.File = placeholderNumber.ReplaceAllString(finding.File, "]")
		finding.Placeholder = placeholderNumber.ReplaceAllString(finding.Placeholder, "]")
		converted = append(converted, finding)
	}

	return converted
}

func TestFixtureFindingsMatchExactly(t *testing.T) {
	result := runFixture(t, inOrder(scan("."), outbound.Response{Text: "Found problems."}), generousLimits)

	gotFindings := asExpected(result.collector.Findings())
	wantFindings := loadExpected(t)

	if !slices.Equal(gotFindings, wantFindings) {
		t.Errorf("findings:\n got  %+v\n want %+v", gotFindings, wantFindings)
	}
	for _, finding := range result.collector.Findings() {
		if finding.Advice == "" {
			t.Errorf("finding %s has no fix advice", finding.Placeholder)
		}
	}
	if result.outcome.Status != agent.Complete {
		t.Errorf("outcome = %+v, want complete", result.outcome)
	}
}

func TestReportHasAllFourPartsAndTheExpectedPlaceholders(t *testing.T) {
	result := runFixture(t, inOrder(scan("."), outbound.Response{Text: "Found problems."}), generousLimits)

	for _, part := range []string{"## Findings", "## Evidence locations", "## Fixes", "## Limits", "Status: complete"} {
		if !strings.Contains(result.report, part) {
			t.Errorf("the report has no %q", part)
		}
	}
	for _, expected := range loadExpected(t) {
		wantLocation := fmt.Sprintf("%s:%d %s", expected.File, expected.Line, expected.Placeholder)
		if !strings.Contains(result.report, wantLocation) {
			t.Errorf("the report has no evidence location %q", wantLocation)
		}
	}
	if strings.Contains(result.report, "123456789012") {
		t.Error("a number with a wrong check digit was reported")
	}
}

func TestNoPlantedValueInTheReportTheFilesOrTheRequests(t *testing.T) {
	result := runFixture(t, inOrder(scan("."), outbound.Response{Text: "Found problems."}), generousLimits)

	var searchTexts []string
	for name, content := range result.outputFiles {
		searchTexts = append(searchTexts, name+": "+content)
	}
	for _, recorded := range result.provider.recorded {
		encoded, err := json.Marshal(recorded)
		if err != nil {
			t.Fatal(err)
		}
		searchTexts = append(searchTexts, string(encoded), fmt.Sprintf("%+v", recorded))
	}
	if len(result.provider.recorded) != 2 || len(result.outputFiles) != 2 {
		t.Fatalf("requests = %d, output files = %d, want 2 and 2", len(result.provider.recorded), len(result.outputFiles))
	}

	for _, searchText := range searchTexts {
		for _, planted := range append(plantedValues, result.project) {
			if strings.Contains(searchText, planted) {
				t.Errorf("a generated file or request contains %q", planted)
			}
		}
	}
}

func TestSecretInAFileNameIsShownAsAPlaceholder(t *testing.T) {
	result := runFixture(t, inOrder(scan("."), outbound.Response{Text: "done"}), generousLimits)

	if !strings.Contains(result.report, "notes/[SECRET:aws-access-key:002].txt") {
		t.Error("the report does not show the safe file reference")
	}
	if strings.Contains(result.report, "AKIAIOSFODNN7EXAMPLE.txt") {
		t.Error("the report shows the real file name")
	}
}

func TestAnotherScanOrderGivesTheSameFindings(t *testing.T) {
	inForwardOrder := runFixture(t, inOrder(scan("."), outbound.Response{Text: "done"}), generousLimits)
	byFolder := runFixture(t, inOrder(scan("notes"), scan("docs"), scan("data"), scan("app"), outbound.Response{Text: "done"}), generousLimits)
	withRepeats := runFixture(t, inOrder(scan("app"), scan("app"), scan("data"), scan("data"), scan("docs"), scan("notes"), outbound.Response{Text: "done"}), generousLimits)

	want := withoutNumbers(asExpected(inForwardOrder.collector.Findings()))
	for name, result := range map[string]runResult{"by folder": byFolder, "with repeats": withRepeats} {
		got := withoutNumbers(asExpected(result.collector.Findings()))
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got  %+v\n want %+v", name, got, want)
		}
	}
}

func TestAnIncompleteRunKeepsItsFindingsAndSaysSo(t *testing.T) {
	result := runFixture(t, func(int) outbound.Response { return scan("app") }, agent.Limits{MaxSteps: 2, MaxTokens: 100000})

	if result.outcome.Status != agent.Incomplete || !strings.Contains(result.report, "Status: incomplete (step limit reached)") {
		t.Errorf("outcome = %+v, report:\n%s", result.outcome, result.report)
	}
	if len(result.collector.Findings()) != 2 {
		t.Errorf("%d findings were kept, want the 2 from the app folder", len(result.collector.Findings()))
	}
}

func TestNoScanMeansNoCleanClaim(t *testing.T) {
	result := runFixture(t, inOrder(outbound.Response{Text: "Looks fine to me."}), generousLimits)

	if result.collector.Stats().Scans != 0 || !strings.Contains(result.report, "No scan ran, so nothing was checked") {
		t.Errorf("report:\n%s", result.report)
	}
	if strings.Contains(result.report, "no findings") && !strings.Contains(result.report, "nothing was looked at") {
		t.Error("the report sounds like the project is clean")
	}
}

func TestTheModelsNotesAreSanitizedAndLabelled(t *testing.T) {
	notes := "Call 090-9999-8888 and use key AKIAIOSFODNN7EXAMPLE.\x1b[31m red"
	result := runFixture(t, inOrder(scan("."), outbound.Response{Text: notes}), generousLimits)

	if !strings.Contains(result.report, "## AI notes (not checked by Omamori)") {
		t.Error("the notes are not labelled")
	}
	if strings.Contains(result.report, "090-9999-8888") || strings.Contains(result.report, "\x1b") {
		t.Errorf("the notes were not cleaned:\n%s", result.report)
	}
}

func TestParseDetectorLine(t *testing.T) {
	testCases := []struct {
		name      string
		inputLine string
		wantFile  string
		wantLine  int
		wantOK    bool
	}{
		{"plain", "app/config.py:3: [SECRET:aws-access-key:001]", "app/config.py", 3, true},
		{"a colon in the file name", "a:b/c.txt:12: [PHONE:002]", "a:b/c.txt", 12, true},
		{"brackets in the file name", "a[1].txt:4: [MYNUMBER:001]", "a[1].txt", 4, true},
		{"a placeholder in the file name", "notes/[SECRET:aws-access-key:002].txt:2: [PHONE:002]", "notes/[SECRET:aws-access-key:002].txt", 2, true},
		{"large placeholder number", "a:1: [PHONE:1000]", "a", 1, true},
		{"empty", "", "", 0, false},
		{"no placeholder", "app/config.py:3: hello", "", 0, false},
		{"line zero", "a:0: [PHONE:001]", "", 0, false},
		{"line too large", "a:99999999999999999999: [PHONE:001]", "", 0, false},
		{"short placeholder number", "a:1: [PHONE:1]", "", 0, false},
		{"unknown label", "a:1: [PASSWORD:001]", "", 0, false},
		{"text after the placeholder", "a:1: [PHONE:001] extra", "", 0, false},
		{"no line number", "a: [PHONE:001]", "", 0, false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotFinding, gotOK := parseDetectorLine(testCase.inputLine)

			if gotOK != testCase.wantOK || gotFinding.File != testCase.wantFile || gotFinding.Line != testCase.wantLine {
				t.Errorf("parseDetectorLine(%q) = %q, %d, %v; want %q, %d, %v",
					testCase.inputLine, gotFinding.File, gotFinding.Line, gotOK, testCase.wantFile, testCase.wantLine, testCase.wantOK)
			}
		})
	}
}

type fakeTools struct {
	result gateway.Result
	err    error
	calls  int
}

func (tools *fakeTools) Call(ctx context.Context, toolName string, arguments map[string]any) (gateway.Result, error) {
	tools.calls++

	return tools.result, tools.err
}

func TestCollectorOnlyTrustsSuccessfulRunDetectors(t *testing.T) {
	line := "a.txt:1: [PHONE:001]"

	testCases := []struct {
		name      string
		toolName  string
		tools     *fakeTools
		wantScans int
		wantCount int
	}{
		{"run_detectors works", "run_detectors", &fakeTools{result: gateway.Result{Text: line}}, 1, 1},
		{"run_detectors fails", "run_detectors", &fakeTools{result: gateway.Result{Text: line}, err: gateway.ErrToolFailed}, 0, 0},
		{"read_file with detector-like text", "read_file", &fakeTools{result: gateway.Result{Text: line}}, 0, 0},
		{"search_text with detector-like text", "search_text", &fakeTools{result: gateway.Result{Text: line}}, 0, 0},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			collector := NewCollector(testCase.tools)

			_, err := collector.Call(context.Background(), testCase.toolName, nil)

			if !errors.Is(err, testCase.tools.err) {
				t.Errorf("err = %v, want the tool's own error %v", err, testCase.tools.err)
			}
			if collector.Stats().Scans != testCase.wantScans || len(collector.Findings()) != testCase.wantCount {
				t.Errorf("scans = %d, findings = %d, want %d and %d", collector.Stats().Scans, len(collector.Findings()), testCase.wantScans, testCase.wantCount)
			}
		})
	}
}

func TestTwoFindingsOfTheSameTypeOnOneLineAreBothKept(t *testing.T) {
	tools := &fakeTools{result: gateway.Result{Text: "a.txt:1: [PHONE:001]\na.txt:1: [PHONE:002]"}}
	collector := NewCollector(tools)

	collector.Call(context.Background(), "run_detectors", nil)
	collector.Call(context.Background(), "run_detectors", nil)

	if len(collector.Findings()) != 2 {
		t.Errorf("%d findings, want 2 (the second scan is a repeat)", len(collector.Findings()))
	}
}

func TestStatsReachTheLimitsSection(t *testing.T) {
	tools := &fakeTools{result: gateway.Result{Text: "a.txt:1: [PHONE:001]\nthis line is garbage", Truncated: true, Skipped: 3}}
	collector := NewCollector(tools)
	collector.Call(context.Background(), "run_detectors", nil)

	report, err := Render(collector.Findings(), collector.Stats(), agent.Outcome{Status: agent.Complete})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"3 files were skipped", "stopped at a limit", "1 lines of scan output could not be read"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report has no %q", want)
		}
	}
}

func TestRenderCleansUntrustedText(t *testing.T) {
	hostile := "a|b`c<script>alert(1)</script>\nd\x1b[31m.txt"
	findings := []Finding{{Severity: "high", Type: "phone", File: hostile, Line: 4, Placeholder: "[PHONE:001]", Advice: "x"}}

	report, err := Render(findings, Stats{Scans: 1}, agent.Outcome{Status: agent.Complete})
	if err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{"<script>", "`c", "\x1b", "a|b"} {
		if strings.Contains(report, bad) {
			t.Errorf("the report contains %q", bad)
		}
	}
	for _, line := range strings.Split(report, "\n") {
		if strings.HasPrefix(line, "| [PHONE:001]") && strings.Count(line, "|") != 6 {
			t.Errorf("the table row is broken: %q", line)
		}
	}
}

func TestAReportWithARawValueIsRefused(t *testing.T) {
	testCases := []struct {
		name    string
		finding Finding
	}{
		{"a phone number in the file name", Finding{Severity: "high", Type: "phone", File: "090-1234-5678.txt", Line: 1, Placeholder: "[PHONE:001]"}},
		{"a key in the type", Finding{Severity: "high", Type: "AKIAIOSFODNN7EXAMPLE", File: "a.txt", Line: 1, Placeholder: "[PHONE:001]"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			report, err := Render([]Finding{testCase.finding}, Stats{Scans: 1}, agent.Outcome{Status: agent.Complete})

			if !errors.Is(err, ErrUnsafeReport) || report != "" {
				t.Errorf("err = %v, report = %q, want ErrUnsafeReport and no report", err, report)
			}
		})
	}
}

func TestControlCharactersCannotHideANumberInTheNotes(t *testing.T) {
	outcome := agent.Outcome{Status: agent.Complete, Texts: []string{"call 090\x00-1234-5678 now"}}

	report, err := Render(nil, Stats{Scans: 1}, outcome)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(report, "090-1234-5678") {
		t.Errorf("the number came out of the notes:\n%s", report)
	}
}

func TestLongNotesAreCut(t *testing.T) {
	outcome := agent.Outcome{Status: agent.Complete, Texts: []string{strings.Repeat("a", 10000)}}

	report, err := Render(nil, Stats{Scans: 1}, outcome)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Count(report, "a") > maxNotesRunes+200 {
		t.Errorf("the notes were not cut")
	}
}

func FuzzParseDetectorLine(f *testing.F) {
	f.Add("app/config.py:3: [SECRET:aws-access-key:001]")
	f.Add("a:1: [PHONE:001]")
	f.Add("")
	f.Add(":::")

	f.Fuzz(func(t *testing.T, line string) {
		finding, ok := parseDetectorLine(line)
		if ok && (finding.Line < 1 || finding.Placeholder == "" || finding.Advice == "") {
			t.Fatalf("a parsed finding is incomplete: %+v", finding)
		}
	})
}

func FuzzRender(f *testing.F) {
	f.Add("a.txt", "phone", "notes")
	f.Add("a|b\n`<script>", "x\x1b", "090\x00-1234-5678")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, fileName, findingType, notes string) {
		findings := []Finding{{Severity: "high", Type: findingType, File: fileName, Line: 1, Placeholder: "[PHONE:001]", Advice: "x"}}
		outcome := agent.Outcome{Status: agent.Incomplete, Reason: "cancelled", Texts: []string{notes}}

		report, err := Render(findings, Stats{Scans: 1}, outcome)
		if err != nil {
			if !errors.Is(err, ErrUnsafeReport) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}

		for _, character := range report {
			if character < ' ' && character != '\n' && character != '\t' {
				t.Fatalf("the report holds the control character %q", character)
			}
		}
		if _, found := (&sanitizer.Sanitizer{}).Sanitize(report); len(found) > 0 {
			t.Fatal("the report still has a finding")
		}
	})
}
