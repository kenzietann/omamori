package triage

import (
	"slices"
	"sort"
	"time"

	"github.com/kenzietann/omamori/internal/authlog"
)

const (
	GuessingThenSuccess = "guessing_then_success"
	PasswordSpraying    = "password_spraying"
)

// Finding is a pattern that the log proves. Omamori finds it by itself, or checks it from a claim of the AI.
// Everything in it comes from the parsed lines, never from the claim.
type Finding struct {
	Scenario string
	IP       string
	Users []string
	// FailureLines are the failed password lines that count, in time order.
	FailureLines []int
	// SuccessLine is the accepted password line of the guessing. It is 0 for spraying.
	SuccessLine int
	Count       int
	First, Last time.Time
	FirstStamp  string
	LastStamp   string
}

func Detect(parsed authlog.Parsed, config Config) []Finding {
	findings := append(detectGuessing(parsed.Events, config), detectSpraying(parsed.Events, config)...)

	sort.SliceStable(findings, func(first, second int) bool {
		a, b := findings[first], findings[second]
		if !a.First.Equal(b.First) {
			return a.First.Before(b.First)
		}
		if a.Scenario != b.Scenario {
			return a.Scenario < b.Scenario
		}

		return a.IP < b.IP
	})

	return findings
}

type pair struct{ ip, user string }

// detectGuessing: at least the threshold of failed passwords from one address for one user name within the
// window, then an accepted password from the same address for the same user name, at or after the last
// counted failure and no more than the window after it.
func detectGuessing(events []authlog.Event, config Config) []Finding {
	groups := make(map[pair][]authlog.Event)
	var order []pair
	for _, event := range events {
		key := pair{event.IP, event.User}
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], event)
	}

	var findings []Finding
	for _, key := range order {
		var failures []authlog.Event
		for _, event := range groups[key] {
			if event.Kind == authlog.Failed {
				failures = append(failures, event)
				continue
			}

			if cluster := countedFailures(failures, event, config); cluster != nil {
				findings = append(findings, guessingFinding(key, cluster, event))
				failures = nil
			}
		}
	}

	return findings
}

func countedFailures(failures []authlog.Event, success authlog.Event, config Config) []authlog.Event {
	for last := len(failures) - 1; last >= 0; last-- {
		end := failures[last]
		if success.Time.Before(end.Time) || success.Time.Sub(end.Time) > config.Window {
			continue
		}

		start := last
		for start > 0 && end.Time.Sub(failures[start-1].Time) <= config.Window {
			start--
		}
		if last-start+1 >= config.FailureThreshold {
			return slices.Clone(failures[start : last+1])
		}
	}

	return nil
}

func guessingFinding(key pair, cluster []authlog.Event, success authlog.Event) Finding {
	finding := Finding{Scenario: GuessingThenSuccess, IP: key.ip, Users: []string{key.user}, SuccessLine: success.Line, Count: len(cluster),
		First: cluster[0].Time, Last: cluster[len(cluster)-1].Time, FirstStamp: cluster[0].Stamp, LastStamp: cluster[len(cluster)-1].Stamp}
	for _, event := range cluster {
		finding.FailureLines = append(finding.FailureLines, event.Line)
	}

	return finding
}

// detectSpraying: failed passwords from one address for at least the threshold of different user names within the window.
func detectSpraying(events []authlog.Event, config Config) []Finding {
	failuresByIP := make(map[string][]authlog.Event)
	var order []string
	for _, event := range events {
		if event.Kind != authlog.Failed {
			continue
		}
		if _, seen := failuresByIP[event.IP]; !seen {
			order = append(order, event.IP)
		}
		failuresByIP[event.IP] = append(failuresByIP[event.IP], event)
	}

	var findings []Finding
	for _, ip := range order {
		failures := failuresByIP[ip]
		for start := 0; start < len(failures); {
			end := start
			users := map[string]bool{}
			for end < len(failures) && failures[end].Time.Sub(failures[start].Time) <= config.Window {
				users[failures[end].User] = true
				end++
			}

			if len(users) < config.SprayThreshold {
				start++
				continue
			}

			findings = append(findings, sprayingFinding(ip, failures[start:end], users))
			start = end
		}
	}

	return findings
}

func sprayingFinding(ip string, cluster []authlog.Event, users map[string]bool) Finding {
	finding := Finding{Scenario: PasswordSpraying, IP: ip, Count: len(cluster), First: cluster[0].Time, Last: cluster[len(cluster)-1].Time,
		FirstStamp: cluster[0].Stamp, LastStamp: cluster[len(cluster)-1].Stamp}
	for user := range users {
		finding.Users = append(finding.Users, user)
	}
	slices.Sort(finding.Users)
	for _, event := range cluster {
		finding.FailureLines = append(finding.FailureLines, event.Line)
	}

	return finding
}
