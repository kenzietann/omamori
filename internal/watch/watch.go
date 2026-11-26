package watch

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/kenzietann/omamori/internal/alertsink"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
)

var levelRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

type Config struct {
	Paths     []string
	Rules     rules.Set
	RulesFrom string
	Options   intake.Options
	StatePath string
	Sinks     []alertsink.Sink
	MinLevel  string
	Interval  time.Duration
	// Once runs a single tick and returns, instead of looping. Used by tests and by a caller that
	// wants to drive the schedule itself (for example from cron).
	Once bool
	// Now lets a test fix the clock. Left nil, time.Now is used.
	Now func() time.Time
	// OnTick is called after every tick with a short, human-readable line, if set. Used by the
	// command to print progress; tests can use it to observe behavior without parsing stdout.
	OnTick func(string)
}

func (config Config) now() time.Time {
	if config.Now != nil {
		return config.Now()
	}

	return time.Now()
}

func (config Config) interval() time.Duration {
	if config.Interval <= 0 {
		return 15 * time.Second
	}

	return config.Interval
}

func (config Config) minRank() int {
	if rank, ok := levelRank[config.MinLevel]; ok {
		return rank
	}

	return levelRank["low"]
}

func (config Config) report(line string) {
	if config.OnTick != nil {
		config.OnTick(line)
	}
}

// Run starts the watch loop. It returns when ctx is cancelled, when Config.Once is set and one tick
// has completed, or when the state file cannot be loaded or saved (a dedup memory that cannot be
// trusted must stop the loop rather than risk silently resending or silently dropping alerts).
func Run(ctx context.Context, config Config) error {
	state, err := LoadState(config.StatePath)
	if err != nil {
		return err
	}
	seen := &memory{warned: map[string]bool{}, firstApp: map[string]int{}}

	for {
		if err := tick(ctx, config, state, seen); err != nil {
			return err
		}
		if config.Once {
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(config.interval()):
		}
	}
}

// memory is what one run of watch remembers between ticks: the warnings already shown, so a blind log is named
// once and not every tick, and how many application events each file had when watch first saw it.
type memory struct {
	warned   map[string]bool
	firstApp map[string]int
}

// warnings gives the warnings of this tick. The one for an application log with no request at all waits until
// the file has new application lines since watch first saw it: a freshly started app has had no request yet, and
// warning then is a false alarm. A single check (Once) has no "later", so it warns as detect does.
func (seen *memory) warnings(read intake.Result, once bool) []string {
	var out []string
	for _, file := range read.Files {
		first, known := seen.firstApp[file.File]
		if !known {
			seen.firstApp[file.File] = file.AppEvents
			first = file.AppEvents
		}
		for _, warning := range file.Warnings() {
			if warning == intake.WarningNoRequests && !once && file.AppEvents <= first {
				continue
			}
			out = append(out, filepath.Base(file.File)+": "+warning)
		}
	}

	return out
}

// tick runs one check.
func tick(ctx context.Context, config Config, state *State, seen *memory) error {
	now := config.now()

	outcome, err := detect.RunContext(ctx, config.Paths, config.Rules, config.RulesFrom, config.Options, now)
	if err != nil {
		config.report(fmt.Sprintf("tick failed: %v", err))
		return nil
	}
	clean := alertsink.Sanitizer()
	for _, warning := range seen.warnings(outcome.Intake, config.Once) {
		if !seen.warned[warning] {
			seen.warned[warning] = true
			config.report("warning: " + clean(warning))
		}
	}

	var toSend []*rules.Alert
	for _, alert := range outcome.Active() {
		if levelRank[alert.Rule.Level] >= config.minRank() {
			toSend = append(toSend, alert)
		}
	}

	fresh := state.New(toSend, outcome.Hashes, now)
	if err := state.Save(config.StatePath); err != nil {
		return err
	}

	if len(fresh) == 0 {
		config.report(fmt.Sprintf("%d alert(s), nothing new", len(toSend)))
		return nil
	}

	payload := alertsink.FromAlerts(fresh, clean)

	sent := 0
	for _, sink := range config.Sinks {
		if err := sink.Send(ctx, payload); err != nil {
			config.report(fmt.Sprintf("a sink failed to deliver %d alert(s): %v", len(payload), err))
			continue
		}
		sent++
	}

	config.report(fmt.Sprintf("%d new alert(s) sent to %d of %d sink(s)", len(fresh), sent, len(config.Sinks)))

	return nil
}
