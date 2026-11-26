// Package watch runs detection on a tick and delivers alerts that have not been sent before. It wraps
// detect.RunContext unchanged: the same rules, the same intake, the same sanitizer. This package adds
// only the loop, a bounded memory of what was already sent, and delivery to one or more sinks.
//
// This first version re-reads the whole watched paths on every tick (see docs/watch.md) and relies on
// the dedup state below, not on a byte offset, to avoid sending the same alert twice.
package watch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/knowngood"
	"github.com/kenzietann/omamori/internal/rules"
)

const stateVersion = 1

// MaxSeen bounds how many fingerprints the state keeps. Past it, the oldest (by SeenAt) are dropped.
// An alert that was already sent and ages out of this set could in principle be sent again; that is
// the same tradeoff a bounded cache always makes, and is far better than growing the file forever.
const MaxSeen = 10_000

// SeenTTL is how long a fingerprint is kept before it is eligible to be dropped, even under MaxSeen.
// An alert whose events stop happening is forgotten after this long, which keeps the state file from
// silently growing across months of otherwise-idle watching.
const SeenTTL = 30 * 24 * time.Hour

var ErrState = errors.New("the watch state file cannot be used")

type seenEntry struct {
	SeenAt time.Time `json:"seen_at"`
}

// burstRange is one burst that was sent: the time of its first and last event, and when it was last seen.
type burstRange struct {
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
	SeenAt time.Time `json:"seen_at"`
}

// State is the dedup memory, persisted to disk so a restart of `watch` does not resend every alert
// that was already delivered. It holds no evidence: only the SHA-256 fingerprints that knowngood
// already computes from an alert's events, the SHA-256 of a burst's rule and group, times, and when they
// were last seen.
type State struct {
	Version int                     `json:"version"`
	Seen    map[string]seenEntry    `json:"seen"`
	Bursts  map[string][]burstRange `json:"bursts,omitempty"`
}

func newState() *State {
	return &State{Version: stateVersion, Seen: map[string]seenEntry{}, Bursts: map[string][]burstRange{}}
}

// LoadState reads a state file. A missing file starts empty: the first tick after `watch` is set up
// for the first time has nothing to compare against, which is expected, not an error.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: it cannot be read", ErrState)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("%w: it is not valid", ErrState)
	}
	if state.Version != stateVersion {
		return nil, fmt.Errorf("%w: version %d is not known; this Omamori writes version %d", ErrState, state.Version, stateVersion)
	}
	if state.Seen == nil {
		state.Seen = map[string]seenEntry{}
	}
	if state.Bursts == nil {
		state.Bursts = map[string][]burstRange{}
	}

	return &state, nil
}

// Save writes the state file atomically: to a temporary file in the same folder, then renamed over
// the target. A crash mid-write leaves the previous state in place, never a half-written file.
func (state *State) Save(path string) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("%w: it cannot be written", ErrState)
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".omamori-watch-state-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: a temporary file cannot be made next to it", ErrState)
	}
	defer os.Remove(temporary.Name())

	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("%w: it cannot be written", ErrState)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: it cannot be written", ErrState)
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return fmt.Errorf("%w: it cannot be saved", ErrState)
	}

	return nil
}

// eventKeys gives the fingerprints of an alert's events, in a fixed order, and whether the alert is keyed by them.
//
// A single-event rule is its events: it is new when one of them is new. A correlation (a count over a time window)
// is a burst instead (see burstNew): each new request of a running attack joins it, so keying it by its events made
// it new again with every request, and an injection burst of fifteen payloads was sent 13 times in a test attack.
// An alert whose events cannot all be fingerprinted (knowngood.Items reports incomplete) is a burst too.
func eventKeys(alert *rules.Alert, hashes map[string]string) ([]string, bool) {
	items, complete := knowngood.Items(alert, hashes)
	if !complete || alert.Rule.IsCorrelation() {
		return nil, false
	}
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Fingerprint)
	}
	sort.Strings(keys)

	return keys, true
}

// burstKey names a burst by its rule and what it is grouped by (an address, an account), not by its times.
func burstKey(alert *rules.Alert) string {
	group := make([]string, 0, len(alert.Group))
	for _, pair := range alert.Group {
		group = append(group, fmt.Sprintf("%q=%q", pair.Field, pair.Value))
	}
	sort.Strings(group)
	sum := sha256.Sum256([]byte(fmt.Sprintf("omamori watch burst v2\nrule=%q\ngroup=%s\n", alert.Rule.Name, strings.Join(group, ","))))

	return hex.EncodeToString(sum[:])
}

// burstNew says whether a burst is new, and records it. A burst is the one already sent when their times overlap
// for the same rule and group: as an attack goes on, the burst grows, and its first event can also move earlier
// when lines of another log arrive late. Its recorded range grows with it. A burst whose times do not touch any sent
// one (the same address again an hour later) is new.
func (state *State) burstNew(alert *rules.Alert, now time.Time) bool {
	key := burstKey(alert)
	ranges := state.Bursts[key]
	for index := range ranges {
		known := &ranges[index]
		if !alert.First.After(known.Last) && !alert.Last.Before(known.First) {
			if alert.First.Before(known.First) {
				known.First = alert.First
			}
			if alert.Last.After(known.Last) {
				known.Last = alert.Last
			}
			known.SeenAt = now
			return false
		}
	}
	state.Bursts[key] = append(ranges, burstRange{First: alert.First, Last: alert.Last, SeenAt: now})

	return true
}

// New reports which of the given alerts are new, records them, and prunes entries older than SeenTTL or past
// MaxSeen. An alert keyed by its events is new when one of them was not seen before; a burst is new when it
// overlaps no burst already sent (burstNew).
func (state *State) New(alerts []*rules.Alert, hashes map[string]string, now time.Time) []*rules.Alert {
	// Drop anything past its TTL before checking what is new, so an entry that aged out is treated
	// as unseen rather than silently refreshed by this same call.
	state.prune(now)

	var fresh []*rules.Alert

	for _, alert := range alerts {
		keys, byEvents := eventKeys(alert, hashes)
		if !byEvents {
			if state.burstNew(alert, now) {
				fresh = append(fresh, alert)
			}
			continue
		}

		isNew := false
		for _, key := range keys {
			if _, ok := state.Seen[key]; !ok {
				isNew = true
			}
		}
		for _, key := range keys {
			state.Seen[key] = seenEntry{SeenAt: now}
		}
		if isNew {
			fresh = append(fresh, alert)
		}
	}

	// Enforce the size bound again now that new entries were added. TTL pruning already ran above
	// this call, so this pass only trims by count, it never undoes the "is this fresh" check we just made.
	state.prune(now)

	return fresh
}

func (state *State) prune(now time.Time) {
	for key, entry := range state.Seen {
		if now.Sub(entry.SeenAt) > SeenTTL {
			delete(state.Seen, key)
		}
	}
	state.pruneBursts(now)
	if len(state.Seen) <= MaxSeen {
		return
	}

	type keyed struct {
		key string
		at  time.Time
	}
	ordered := make([]keyed, 0, len(state.Seen))
	for key, entry := range state.Seen {
		ordered = append(ordered, keyed{key: key, at: entry.SeenAt})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].at.Before(ordered[j].at) })

	for _, item := range ordered[:len(ordered)-MaxSeen] {
		delete(state.Seen, item.key)
	}
}

// pruneBursts drops bursts not seen for SeenTTL, and keeps at most MaxSeen of them, the most recently seen.
func (state *State) pruneBursts(now time.Time) {
	type keyed struct {
		key   string
		burst burstRange
	}
	var kept []keyed
	for key, ranges := range state.Bursts {
		for _, burst := range ranges {
			if now.Sub(burst.SeenAt) <= SeenTTL {
				kept = append(kept, keyed{key: key, burst: burst})
			}
		}
	}
	if len(kept) > MaxSeen {
		sort.Slice(kept, func(i, j int) bool { return kept[i].burst.SeenAt.After(kept[j].burst.SeenAt) })
		kept = kept[:MaxSeen]
	}
	state.Bursts = map[string][]burstRange{}
	for _, item := range kept {
		state.Bursts[item.key] = append(state.Bursts[item.key], item.burst)
	}
}
