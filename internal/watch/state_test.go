package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/rules"
)

var baseTime = time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)

func rule(t *testing.T, name string) *rules.Rule {
	t.Helper()
	parsed, err := rules.Parse([]byte("title: T\nname: "+name+"\nlogsource: {}\ndetection:\n  s: {action: x}\n  condition: s"), "t.yml")
	if err != nil {
		t.Fatal(err)
	}

	return parsed[0]
}

func sampleAlert(t *testing.T, ruleName, srcIP string, last time.Time) *rules.Alert {
	t.Helper()
	return &rules.Alert{
		Rule: rule(t, ruleName),
		Last: last,
		Events: []event.Event{{
			Source: "logs", Ref: "auth.log:1",
			Fields: map[string]string{"action": "x", "src_ip": srcIP},
		}},
		Count: 1,
	}
}

func TestNewReportsAnAlertOnlyOnce(t *testing.T) {
	state := newState()
	alert := sampleAlert(t, "guess", "203.0.113.5", baseTime)

	first := state.New([]*rules.Alert{alert}, nil, baseTime)
	if len(first) != 1 {
		t.Fatalf("first tick: got %d fresh alerts, want 1", len(first))
	}

	// The same alert (same rule, same event) seen again on a later tick must not be reported again.
	again := sampleAlert(t, "guess", "203.0.113.5", baseTime.Add(time.Minute))
	second := state.New([]*rules.Alert{again}, nil, baseTime.Add(time.Minute))
	if len(second) != 0 {
		t.Fatalf("second tick: got %d fresh alerts, want 0 (already seen)", len(second))
	}
}

func TestNewReportsADifferentAlertAsFresh(t *testing.T) {
	state := newState()
	first := sampleAlert(t, "guess", "203.0.113.5", baseTime)
	state.New([]*rules.Alert{first}, nil, baseTime)

	other := sampleAlert(t, "guess", "203.0.113.9", baseTime.Add(time.Minute))
	fresh := state.New([]*rules.Alert{other}, nil, baseTime.Add(time.Minute))
	if len(fresh) != 1 {
		t.Fatalf("a different source address must be a fresh alert, got %d", len(fresh))
	}
}

// burst is a correlation alert over more events than it keeps (Count > len(Events)), so knowngood.Items cannot
// pin it: like app_login_bruteforce after many failures from one address.
func burst(t *testing.T, srcIP string, first time.Time, count int) *rules.Alert {
	t.Helper()
	alert := sampleAlert(t, "many", srcIP, first.Add(time.Minute))
	alert.First, alert.Count = first, count
	alert.Group = []rules.Pair{{Field: "src_ip", Value: srcIP}}

	return alert
}

func TestNewSendsAGrowingBurstOnce(t *testing.T) {
	// Found by attacking a real app: such a burst was sent again on every check, 22 times for one attack.
	state := newState()
	if got := state.New([]*rules.Alert{burst(t, "203.0.113.5", baseTime, 12)}, nil, baseTime); len(got) != 1 {
		t.Fatalf("first check: %d fresh, want 1", len(got))
	}
	for i, count := range []int{12, 15, 30} {
		later := baseTime.Add(time.Duration(i+1) * 5 * time.Second)
		if got := state.New([]*rules.Alert{burst(t, "203.0.113.5", baseTime, count)}, nil, later); len(got) != 0 {
			t.Fatalf("check %d: the same burst was sent again (%d events)", i+2, count)
		}
	}
}

func TestNewSendsANewBurstAndAnotherAddress(t *testing.T) {
	state := newState()
	state.New([]*rules.Alert{burst(t, "203.0.113.5", baseTime, 12)}, nil, baseTime)

	if got := state.New([]*rules.Alert{burst(t, "203.0.113.9", baseTime, 12)}, nil, baseTime); len(got) != 1 {
		t.Errorf("a burst from another address must be sent, got %d", len(got))
	}
	later := baseTime.Add(2 * time.Hour)
	if got := state.New([]*rules.Alert{burst(t, "203.0.113.5", later, 12)}, nil, later); len(got) != 1 {
		t.Errorf("a new burst later from the same address must be sent, got %d", len(got))
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")

	state := newState()
	alert := sampleAlert(t, "guess", "203.0.113.5", baseTime)
	state.New([]*rules.Alert{alert}, nil, baseTime)

	if err := state.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	// The same alert must be recognized as already seen after a reload, so a restart of `watch` does
	// not resend everything it had already delivered.
	fresh := loaded.New([]*rules.Alert{alert}, nil, baseTime.Add(time.Minute))
	if len(fresh) != 0 {
		t.Fatalf("after reload, an already-seen alert must not be fresh, got %d", len(fresh))
	}
}

func TestLoadStateMissingFileStartsEmpty(t *testing.T) {
	state, err := LoadState(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("a missing state file must not be an error, got %v", err)
	}
	if len(state.Seen) != 0 {
		t.Fatalf("a fresh state must start empty, has %d entries", len(state.Seen))
	}
}

func TestLoadStateRejectsWrongVersion(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	if err := writeRaw(path, `{"version":99,"seen":{}}`); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadState(path); err == nil {
		t.Fatal("a state file of an unknown version must be refused")
	}
}

func TestLoadStateRejectsInvalidJSON(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	if err := writeRaw(path, `not json`); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadState(path); err == nil {
		t.Fatal("an unreadable state file must be refused, not silently treated as empty")
	}
}

func TestPruneDropsEntriesPastTTL(t *testing.T) {
	state := newState()
	alert := sampleAlert(t, "guess", "203.0.113.5", baseTime)
	state.New([]*rules.Alert{alert}, nil, baseTime)

	// Long after SeenTTL, the entry must be forgotten: the alert is treated as fresh again, rather
	// than the state file growing forever for an address that stopped appearing.
	later := baseTime.Add(SeenTTL + time.Hour)
	fresh := state.New([]*rules.Alert{alert}, nil, later)
	if len(fresh) != 1 {
		t.Fatalf("an entry past its TTL must be forgotten, alert should be fresh again, got %d fresh", len(fresh))
	}
}

func TestPruneBoundsTotalEntries(t *testing.T) {
	state := newState()
	// Each alert has a distinct source address, so each gets its own fingerprint.
	for i := 0; i < MaxSeen+50; i++ {
		alert := sampleAlert(t, "guess", addressFor(i), baseTime)
		state.New([]*rules.Alert{alert}, nil, baseTime)
	}

	if len(state.Seen) > MaxSeen {
		t.Fatalf("state has %d entries, must never exceed MaxSeen=%d", len(state.Seen), MaxSeen)
	}
}

func addressFor(i int) string {
	return "10.0." + itoa(i/256) + "." + itoa(i%256)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func writeRaw(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
