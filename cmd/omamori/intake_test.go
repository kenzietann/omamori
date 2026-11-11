package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/analysisrun"
	"github.com/kenzietann/omamori/internal/analyst"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/rules"
)

func TestSourceFixtureDetectionAndAIReview(t *testing.T) {
	fixture, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "intake"))
	if err != nil {
		t.Fatal(err)
	}
	logs, custom := filepath.Join(fixture, "logs"), filepath.Join(fixture, "rules")
	before := snapshot(t, logs)
	output := filepath.Join(t.TempDir(), "detection")
	got := runAt(t, detectNow, "detect", logs, "--rules", custom, "--year", "2026", "--timezone", "UTC", "--output", output)
	if got.code != exitOK || !strings.Contains(got.stdout, "8 events. 8 rules. 6 alerts") {
		t.Fatalf("detect: %d %s %s", got.code, got.stdout, got.stderr)
	}
	files := analysisFiles(t, output)
	page, _ := os.ReadFile(files["report.md"])
	if !strings.Contains(string(page), "json (json, suricata, wazuh, windows, zeek)") || !strings.Contains(string(page), "signature=Synthetic sensor observation") {
		t.Fatalf("report lost source or sensor evidence: %s", page)
	}
	data, _ := os.ReadFile(files["alerts.json"])
	var alerts struct {
		Alerts []struct {
			Events []struct{ Source string } `json:"events"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(data, &alerts); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, alert := range alerts.Alerts {
		for _, event := range alert.Events {
			seen[event.Source] = true
		}
	}
	for _, source := range []string{"suricata", "zeek", "wazuh", "windows"} {
		if !seen[source] {
			t.Errorf("no %s source in the alert JSON", source)
		}
	}
	set, err := rules.Load(custom)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := detect.Run([]string{logs}, set, "from a folder", intake.Options{Year: 2026, Location: time.UTC}, detectNow)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := analyst.BuildSnapshot(outcome)
	if err != nil {
		t.Fatal(err)
	}
	provider := &analystProvider{answer: analystAnswers(t, packet)}
	analysisOutput := filepath.Join(t.TempDir(), "analysis")
	review := analyzeCommand(t, func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil },
		"analyze", logs, "--rules", custom, "--year", "2026", "--timezone", "UTC", "--output", analysisOutput,
		"--yes", "--provider", "openai", "--model", "test")
	if review.code != exitOK || len(provider.sent) != 1 {
		t.Fatalf("review: %d %s %s", review.code, review.stdout, review.stderr)
	}
	resultData, _ := os.ReadFile(analysisFiles(t, analysisOutput)["analysis.json"])
	var result analysisrun.Result
	if err := json.Unmarshal(resultData, &result); err != nil || !result.Complete || len(result.Analysis.Verified) != 6 {
		t.Fatalf("analysis result: %v %s", err, resultData)
	}
	request, _ := json.Marshal(provider.sent[0])
	for _, key := range []string{"event_id", "collector", "dst_port", "signature", "process"} {
		if !strings.Contains(string(request), key) {
			t.Errorf("analyst evidence lacks %s", key)
		}
	}
	after := snapshot(t, logs)
	for file, original := range before {
		if after[file] != original {
			t.Fatal("the source fixture changed")
		}
	}
}

func TestExplicitSourceFormatRefusesOtherSources(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "intake")
	output := filepath.Join(t.TempDir(), "reports")
	got := runAt(t, detectNow, "detect", filepath.Join(fixture, "logs"), "--format", "windows", "--rules", filepath.Join(fixture, "rules"),
		"--year", "2026", "--timezone", "UTC", "--output", output)
	if got.code != exitOK || !strings.Contains(got.stdout, "3 events. 8 rules. 2 alerts") {
		t.Fatalf("explicit source: %d %s %s", got.code, got.stdout, got.stderr)
	}
	report, _ := os.ReadFile(analysisFiles(t, output)["report.md"])
	if !strings.Contains(string(report), "5 lines that could not be read") {
		t.Fatal("the report hid source-mismatched input lines")
	}
}
