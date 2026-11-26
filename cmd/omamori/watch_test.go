package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// Without a webhook or email, watch must print the alerts themselves, not only how many there were.
func TestWatchOncePrintsAlertsWithoutASink(t *testing.T) {
	base := t.TempDir()
	logs, state := filepath.Join(base, "logs"), filepath.Join(base, "state.json")
	if made := runAt(t, detectNow, "scenario", "--seed", "3", "--date", "2026-11-10", "--timezone", "Asia/Tokyo", logs); made.code != exitOK {
		t.Fatalf("scenario: %d %s", made.code, made.stderr)
	}

	first := runAt(t, detectNow, "watch", "--once", "--year", "2026", "--timezone", "Asia/Tokyo", "--state", state, logs)
	if first.code != exitOK {
		t.Fatalf("watch: %d %s", first.code, first.stderr)
	}
	for _, want := range []string{
		"one check", "ALERT [critical] SSH login succeeded after password guessing (ssh_brute_force_success)",
		"ALERT [high] Injection attempts at the web server (web_injection_attempt)",
		// detect gives 15 alerts. Three are one cron line that ran at 02:30, 03:00 and 03:30: the same event apart
		// from its time is the same alert, so watch sends it once and 13 in all.
		"13 new alert(s)",
	} {
		if !strings.Contains(first.stdout, want) {
			t.Errorf("the output has no %q:\n%s", want, first.stdout)
		}
	}
	if strings.Contains(first.stdout, "Ctrl-C") {
		t.Error("a single check must not say Ctrl-C to stop")
	}

	again := runAt(t, detectNow, "watch", "--once", "--year", "2026", "--timezone", "Asia/Tokyo", "--state", state, logs)
	if again.code != exitOK || strings.Contains(again.stdout, "ALERT ") || !strings.Contains(again.stdout, "nothing new") {
		t.Errorf("a second check sent the same alerts again:\n%s", again.stdout)
	}
}
