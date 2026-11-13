package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/analyst"
	"github.com/kenzietann/omamori/internal/assets"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/indicators"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/rules"
)

func TestReplayOfAnAnalystRunTakesItsLists(t *testing.T) {
	logs, assetsFile, indicatorsFile := campaignWithLists(t)
	machines, err := assets.Load(assetsFile)
	if err != nil {
		t.Fatal(err)
	}
	known, err := indicators.Load(indicatorsFile)
	if err != nil {
		t.Fatal(err)
	}
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := detect.Run([]string{logs}, set, "built-in", intake.Options{Year: 2026, Location: time.UTC, Assets: machines, Indicators: known}, detectNow)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := analyst.BuildSnapshot(outcome)
	if err != nil {
		t.Fatal(err)
	}
	provider := &analystProvider{answer: analystAnswers(t, snapshot)}
	factory := func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }
	live := filepath.Join(t.TempDir(), "live")
	lists := []string{"--assets", assetsFile, "--indicators", indicatorsFile}
	got := analyzeCommand(t, factory, append([]string{"analyze", "--yes", "--provider", "openai", "--model", "test", "--year", "2026", "--timezone", "UTC", "--output", live}, append(lists, logs)...)...)
	if got.code != exitOK {
		t.Fatalf("live: %d %s %s", got.code, got.stdout, got.stderr)
	}
	recording := analysisFiles(t, live)["recording.json"]

	noProvider := func(_, _, _, _ string) (outbound.Provider, error) {
		t.Fatal("a replay asked for a provider")
		return nil, nil
	}
	without := analyzeCommand(t, noProvider, "replay", "--year", "2026", "--timezone", "UTC", "--output", filepath.Join(t.TempDir(), "a"), recording, logs)
	if without.code == exitOK || !strings.Contains(without.stderr, "did not match") {
		t.Fatalf("a replay without the lists: %d %s %s", without.code, without.stdout, without.stderr)
	}
	with := analyzeCommand(t, noProvider, append([]string{"replay", "--year", "2026", "--timezone", "UTC", "--output", filepath.Join(t.TempDir(), "b")}, append(lists, recording, logs)...)...)
	if with.code != exitOK || !strings.Contains(with.stdout, "REPLAY") || !strings.Contains(with.stdout, "0 rejected claims") {
		t.Fatalf("a replay with the lists: %d %s %s", with.code, with.stdout, with.stderr)
	}
}

func TestReplayRefusesFlagsAndRecordingsThatDoNotFit(t *testing.T) {
	logs := campaignFolder(t)
	provider := &analystProvider{answer: cronRuleAnswer}
	factory := func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }
	draft := filepath.Join(t.TempDir(), "draft")
	if got := analyzeCommand(t, factory, ruleArgs(draft, logs, "--yes", "--provider", "openai", "--model", "test")...); got.code != exitOK {
		t.Fatalf("draft: %d %s", got.code, got.stderr)
	}
	recording := analysisFiles(t, draft)["recording.json"]
	got := analyzeCommand(t, factory, "replay", recording, logs)
	if got.code != exitUsage || !strings.Contains(got.stderr, "omamori rule draft --replay") {
		t.Fatalf("a rule draft recording: %d %s", got.code, got.stderr)
	}

	exposure := filepath.Join(t.TempDir(), "exposure.json")
	if err := os.WriteFile(exposure, []byte(`{"version":1,"source":"scripted","task":"exposure","steps":[{"answer":{"text":"done"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got = analyzeCommand(t, factory, "replay", "--assets", "a.yml", exposure, logs)
	if got.code != exitUsage || !strings.Contains(got.stderr, "only fit the recording of an analyst run") {
		t.Fatalf("lists on an exposure recording: %d %s", got.code, got.stderr)
	}
}
