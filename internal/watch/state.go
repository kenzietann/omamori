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

// State is the dedup memory, persisted to disk so a restart of `watch` does not resend every alert
// that was already delivered. It holds no evidence: only the SHA-256 fingerprints that knowngood
// already computes from an alert's events, and the time they were last seen.
type State struct {
	Version int                  `json:"version"`
	Seen    map[string]seenEntry `json:"seen"`
}

func newState() *State {
	return &State{Version: stateVersion, Seen: map[string]seenEntry{}}
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

// fingerprintsOf gives every fingerprint of an alert's events, in a fixed order, so the same alert
// always produces the same key set regardless of map iteration order elsewhere.
// keysOf gives the keys that stand for an alert. An alert whose events can all be fingerprinted (knowngood.Items)
// is its events: it is new when one of them is new. A correlation over more events than it keeps cannot be
// pinned that way, and its kept events change as it grows; it is one burst instead: the rule, what it is grouped
// by (an address, an account) and when the burst began. A burst that grows is then sent once, and a new burst
// later (another start) is sent again. Sending it on every check, as before, flooded the sink.
func keysOf(alert *rules.Alert, hashes map[string]string) []string {
	if items, complete := knowngood.Items(alert, hashes); complete {
		keys := make([]string, 0, len(items))
		for _, item := range items {
			keys = append(keys, item.Fingerprint)
		}
		sort.Strings(keys)

		return keys
	}

	group := make([]string, 0, len(alert.Group))
	for _, pair := range alert.Group {
		group = append(group, fmt.Sprintf("%q=%q", pair.Field, pair.Value))
	}
	sort.Strings(group)
	text := fmt.Sprintf("omamori watch burst v1\nrule=%q\ngroup=%s\nfirst=%s\n",
		alert.Rule.Name, strings.Join(group, ","), alert.First.UTC().Format(time.RFC3339Nano))
	sum := sha256.Sum256([]byte(text))

	return []string{hex.EncodeToString(sum[:])}
}

// New reports which of the given alerts are new: an alert whose keys (keysOf) include one not seen before. It
// marks all of their keys as seen now, and prunes entries older than SeenTTL or past MaxSeen.
func (state *State) New(alerts []*rules.Alert, hashes map[string]string, now time.Time) []*rules.Alert {
	// Drop anything past its TTL before checking what is new, so an entry that aged out is treated
	// as unseen rather than silently refreshed by this same call.
	state.prune(now)

	var fresh []*rules.Alert

	for _, alert := range alerts {
		keys := keysOf(alert, hashes)

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
