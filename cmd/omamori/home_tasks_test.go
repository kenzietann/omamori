package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/scenario"
	"github.com/kenzietann/omamori/internal/taskrun"
	"github.com/kenzietann/omamori/internal/triage"
	"github.com/kenzietann/omamori/internal/tui"
)

func TestHomeLocalTasksUseRealServices(t *testing.T) {
	logs, _ := analystFixture(t, true)
	system := hostFolder(t)
	for _, task := range []string{tui.TaskDetect, tui.TaskForensics, tui.TaskDemo} {
		target := logs
		if task == tui.TaskForensics {
			target = system
		}
		b := backend{config: taskrun.Config{Target: target, OutputBase: filepath.Join(t.TempDir(), "reports"), Now: func() time.Time { return detectNow }}}
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
	// The fixture is written in Tokyo time. The home screen reads syslog in the time of the computer unless it is
	// told, so the test tells it: on a computer in another zone the hours, and so the counts, would differ.
	tokyo := &triage.Config{Year: 2026, Location: time.FixedZone("JST", 9*3600)}
	b := backend{config: taskrun.Config{Target: logs, OutputBase: filepath.Join(t.TempDir(), "reports"), Now: func() time.Time { return detectNow }, Triage: tokyo, NewProvider: func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }}}
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

// The Dashboard line of the home screen starts the same server as the dashboard command: on this computer
// only, with a private link, until the run is cancelled.
func TestHomeDashboardServesUntilCancelled(t *testing.T) {
	logs, _ := analystFixture(t, false)
	home := t.TempDir()
	b := backend{
		config: taskrun.Config{Target: logs, OutputBase: filepath.Join(t.TempDir(), "reports"), Now: func() time.Time { return detectNow }},
		env:    environment{home: homeAt(home), lookupEnv: func(string) string { return "" }},
	}
	plan, err := b.Prepare(tui.Setup{Task: tui.TaskDashboard})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Local || !strings.Contains(plan.Summary, "127.0.0.1") || !strings.Contains(plan.Summary, filepath.Join(home, "omamori-data", "omamori.db")) {
		t.Fatalf("the plan does not say what will be started: %q", plan.Summary)
	}
	if _, err := os.Stat(filepath.Join(home, "omamori-data")); !os.IsNotExist(err) {
		t.Fatal("preparing the dashboard made the database folder")
	}
	unconfirmed, stop := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = plan.Run(unconfirmed, func(string) { t.Error("the dashboard started without a confirmation") })
	stop()
	if !errors.Is(err, taskrun.ErrNotConfirmed) {
		t.Fatalf("an unconfirmed dashboard gave %v", err)
	}

	plan.Confirm()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	links := make(chan string, 1)
	type outcome struct {
		result tui.Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := plan.Run(ctx, func(text string) {
			if _, link, found := strings.Cut(text, "private link: "); found {
				links <- link
			}
		})
		done <- outcome{result, err}
	}()

	var link string
	select {
	case link = <-links:
	case ended := <-done:
		t.Fatalf("the dashboard ended at once: %+v %v", ended.result, ended.err)
	case <-time.After(20 * time.Second):
		t.Fatal("the dashboard gave no link")
	}
	if !strings.HasPrefix(link, "http://127.0.0.1:") {
		t.Fatalf("the link is not on this computer: %s", link)
	}
	response, err := http.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the link answered %d", response.StatusCode)
	}

	cancel()
	select {
	case ended := <-done:
		if ended.err != nil || !ended.result.Complete || !strings.Contains(ended.result.Report, "stopped") {
			t.Fatalf("after the cancel: %+v %v", ended.result, ended.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the dashboard did not stop")
	}
	if _, err := http.Get(link); err == nil {
		t.Fatal("the link still answers after the stop")
	}
}

// hostFolder writes the synthetic Linux system of the demo and gives the top of it.
func hostFolder(t *testing.T) string {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "host")
	if err := scenario.WriteHost(folder, scenario.GenerateHost(3, time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC), true)); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(folder, "root")
}
