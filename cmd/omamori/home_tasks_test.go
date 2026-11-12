package main

import (
	"context"
	"github.com/kenzietann/omamori/internal/outbound"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/tui"
)

func TestHomeLocalTasksUseRealServices(t *testing.T) {
	logs, _ := analystFixture(t, true)
	b := backend{config: taskrun.Config{Target: logs, OutputBase: filepath.Join(t.TempDir(), "reports"), Now: func() time.Time { return detectNow }}}
	for _, task := range []string{tui.TaskDetect, tui.TaskForensics, tui.TaskDemo} {
		plan, err := b.Prepare(tui.Setup{Task: task})
		if err != nil {
			t.Fatalf("%s: %v", task, err)
		}
		if !plan.Local || plan.Confirm == nil || plan.Run == nil {
			t.Fatalf("invalid local plan %s", task)
		}
		if _, err := plan.Run(context.Background(), nil); err == nil {
			t.Fatal("unconfirmed plan ran")
		}
		plan.Confirm()
		result, err := plan.Run(context.Background(), nil)
		if err != nil || !result.Complete || result.SavedTo == "" {
			t.Fatalf("%s: %+v %v", task, result, err)
		}
		if task == tui.TaskDemo {
			if _, err := os.Stat(filepath.Join(result.SavedTo, "host", "root", "etc", "crontab")); err != nil {
				t.Fatal(err)
			}
		} else {
			text, err := os.ReadFile(filepath.Join(result.SavedTo, "report.html"))
			if err != nil || !strings.Contains(string(text), "<!doctype html>") {
				t.Fatal("missing real report")
			}
		}
	}
}

func TestHomeStoredRunsDoesNotCreateMissingDatabase(t *testing.T) {
	home := t.TempDir()
	b := backend{env: environment{home: homeAt(home)}}
	if _, err := b.Prepare(tui.Setup{Task: tui.TaskStored}); err == nil {
		t.Fatal("missing store was accepted")
	}
	if _, err := os.Stat(filepath.Join(home, "omamori-data")); !os.IsNotExist(err) {
		t.Fatal("preparation created a store")
	}
}

func TestHomeAnalysisPreviewsWithoutSending(t *testing.T) {
	logs, packet := analystFixture(t, true)
	provider := &analystProvider{answer: analystAnswers(t, packet)}
	b := backend{config: taskrun.Config{Target: logs, OutputBase: filepath.Join(t.TempDir(), "reports"), Now: func() time.Time { return detectNow }, NewProvider: func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }}}
	plan, err := b.Prepare(tui.Setup{Task: tui.TaskAnalyze, ProviderID: "openai", Model: "test", Key: "fake-key"})
	if err != nil {
		t.Fatal(err)
	}
	if len(provider.sent) != 0 || plan.Local || !strings.Contains(plan.Preview, "claims") {
		t.Fatal("AI preparation did not preview safely")
	}
	plan.Confirm()
	result, err := plan.Run(context.Background(), nil)
	if err != nil || !result.Complete || len(provider.sent) != 1 {
		t.Fatalf("analysis: %+v %v calls %d", result, err, len(provider.sent))
	}
}
