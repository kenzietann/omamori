package rules

import (
	"sort"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

const (
	// MaxEvidence is how many events one alert keeps. Count says how many there were.
	MaxEvidence = 50
	maxValuesIn = 200
	// maxHits is how many hits one rule may have in one evaluation. More than that is cut and reported.
	maxHits = 500_000
)

// Pair is one group-by field and its value.
type Pair struct {
	Field string
	Value string
}

// Alert is what a rule gives. For a detection rule it is one event. For a correlation rule it is a burst:
// Time is the moment the limit was reached, First and Last are the first and the last event of the burst.
type Alert struct {
	Rule  *Rule
	Time  time.Time
	First time.Time
	Last  time.Time
	Group []Pair
	// Count is the number of events (or hits) in the alert. Events holds the first MaxEvidence of them.
	Count  int
	Events []event.Event
	// Values are the different values that a value_count rule saw, at most 200.
	Values []string
	// Parts are the steps of a temporal alert, in the order in which they happened.
	Parts []*Alert

	// order is the place, among the sorted events, of the event that made the alert fire.
	order int
}

// Result is the outcome of one evaluation.
type Result struct {
	// Alerts are in the order of time.
	Alerts []*Alert
	// Cut names the rules that had more hits than the limit. Their counts are too low.
	Cut []string
}

func (alert *Alert) field(name string) (string, bool) {
	if alert.Rule.correlation == nil {
		return alert.Events[0].Get(name)
	}
	canonical := event.Canonical(name)
	for _, pair := range alert.Group {
		if event.Canonical(pair.Field) == canonical {
			return pair.Value, true
		}
	}

	return "", false
}

func (alert *Alert) addEvents(events []event.Event) {
	room := MaxEvidence - len(alert.Events)
	if room <= 0 {
		return
	}
	if len(events) > room {
		events = events[:room]
	}
	alert.Events = append(alert.Events, events...)
}

// Evaluate runs every rule over the events. The events need not be sorted, and they are not changed.
func (set Set) Evaluate(events []event.Event) Result {
	hits, cut := set.evaluate(events)

	var result Result
	result.Cut = cut
	for _, rule := range set.rules {
		if set.quiet[rule] {
			continue
		}
		result.Alerts = append(result.Alerts, hits[rule]...)
	}
	sort.SliceStable(result.Alerts, func(first, second int) bool { return result.Alerts[first].order < result.Alerts[second].order })

	return result
}

func (set Set) evaluate(events []event.Event) (map[*Rule][]*Alert, []string) {
	sorted := make([]event.Event, len(events))
	copy(sorted, events)
	event.Sort(sorted)

	hits := make(map[*Rule][]*Alert, len(set.rules))
	var cut []string
	// set.ordered has every rule after the rules that it refers to.
	for _, rule := range set.ordered {
		var found []*Alert
		if rule.detection != nil {
			found = rule.detect(sorted)
		} else {
			found = rule.correlate(set.merge(rule, hits))
		}
		if len(found) > maxHits {
			found = found[:maxHits]
			cut = append(cut, rule.Title)
		}
		hits[rule] = found
	}

	return hits, cut
}

func (rule *Rule) detect(sorted []event.Event) []*Alert {
	var found []*Alert
	for index, candidate := range sorted {
		if !rule.fitsSource(candidate) || !rule.detection.match(candidate) {
			continue
		}
		found = append(found, &Alert{
			Rule: rule, Time: candidate.Time, First: candidate.Time, Last: candidate.Time,
			Count: 1, Events: sorted[index : index+1 : index+1], order: index,
		})
		if len(found) > maxHits {
			break
		}
	}

	return found
}

// fitsSource compares the logsource of the rule with the event. A key that the rule does not set fits everything.
func (rule *Rule) fitsSource(candidate event.Event) bool {
	for key, wanted := range rule.LogSource {
		if value, found := candidate.Fields[key]; !found || !strings.EqualFold(value, wanted) {
			return false
		}
	}

	return true
}

// step is one hit of a rule that a correlation refers to. index is the place of that rule in the list.
type step struct {
	hit   *Alert
	index int
}

// merge gives the hits of the rules that a correlation refers to, in the order of time.
func (set Set) merge(rule *Rule, hits map[*Rule][]*Alert) []step {
	var steps []step
	for index, reference := range rule.correlation.references {
		for _, hit := range hits[set.byName[reference]] {
			steps = append(steps, step{hit: hit, index: index})
		}
	}
	sort.SliceStable(steps, func(first, second int) bool {
		if steps[first].hit.order == steps[second].hit.order && rule.correlation.kind == temporalOrdered {
			// Finish earlier chains before this same event can replace their first steps.
			// The order check in inOrder still prevents one event from filling two steps.
			return steps[first].index > steps[second].index
		}

		return steps[first].hit.order < steps[second].hit.order
	})

	return steps
}

// groupOf gives the group of a hit. A hit that lacks one of the group-by fields belongs to no group and is not counted.
func (rule *Rule) groupOf(hit *Alert) (key string, group []Pair, complete bool) {
	var builder strings.Builder
	for _, field := range rule.correlation.groupBy {
		value, found := hit.field(field)
		if !found || value == "" {
			return "", nil, false
		}
		builder.WriteString(value)
		builder.WriteByte(0)
		group = append(group, Pair{Field: field, Value: value})
	}

	return builder.String(), group, true
}

func (rule *Rule) correlate(steps []step) []*Alert {
	groups := map[string]*groupState{}
	var found []*Alert
	for _, current := range steps {
		key, group, complete := rule.groupOf(current.hit)
		if !complete {
			continue
		}
		state := groups[key]
		if state == nil {
			state = &groupState{group: group, latest: make([]*Alert, len(rule.correlation.references))}
			groups[key] = state
		}

		var fired *Alert
		switch rule.correlation.kind {
		case eventCount, valueCount:
			fired = rule.count(state, current.hit)
		case temporal:
			fired = rule.together(state, current)
		default:
			fired = rule.inOrder(state, current)
		}
		if fired != nil {
			found = append(found, fired)
		}
	}

	return found
}

// groupState is what a correlation remembers for one group.
type groupState struct {
	group []Pair
	// window holds the hits of the last timespan, and burst is the alert that is open (count rules).
	window []*Alert
	burst  *Alert
	values map[string]bool
	// latest holds, for each rule of the list, its last hit (temporal), or the chain that ends with it (temporal_ordered).
	latest []*Alert
	chains [][]*Alert
}

// count handles event_count and value_count. It gives an alert at the moment the limit is reached.
// Hits that follow inside the timespan go into the same alert, so that one burst is one alert.
func (rule *Rule) count(state *groupState, hit *Alert) *Alert {
	settings := rule.correlation
	value := ""
	if settings.kind == valueCount {
		var found bool
		if value, found = hit.field(settings.field); !found || value == "" {
			return nil
		}
	}

	if state.burst != nil {
		if hit.Time.Sub(state.burst.Last) <= settings.timespan {
			state.burst.Count++
			state.burst.Last = hit.Last
			state.burst.addEvents(hit.Events)
			if settings.kind == valueCount && !state.values[value] && len(state.burst.Values) < maxValuesIn {
				state.values[value] = true
				state.burst.Values = append(state.burst.Values, value)
			}

			return nil
		}
		state.burst, state.window, state.values = nil, nil, nil
	}

	state.window = append(state.window, hit)
	for hit.Time.Sub(state.window[0].Time) > settings.timespan {
		state.window = state.window[1:]
	}

	reached := len(state.window)
	var values []string
	if settings.kind == valueCount {
		seen := map[string]bool{}
		for _, earlier := range state.window {
			text, _ := earlier.field(settings.field)
			if !seen[text] {
				seen[text] = true
				values = append(values, text)
			}
		}
		reached = len(values)
		state.values = seen
	}
	if reached < settings.threshold {
		return nil
	}
	if len(values) > maxValuesIn {
		values = values[:maxValuesIn]
	}

	alert := &Alert{
		Rule: rule, Time: hit.Time, First: state.window[0].First, Last: hit.Last,
		Group: state.group, Count: len(state.window), Values: values, order: hit.order,
	}
	for _, earlier := range state.window {
		alert.addEvents(earlier.Events)
	}
	state.burst = alert

	return alert
}

// together handles temporal: every rule of the list has a hit, and none ended longer ago than the timespan.
func (rule *Rule) together(state *groupState, current step) *Alert {
	state.latest[current.index] = current.hit
	for _, earlier := range state.latest {
		if earlier == nil || current.hit.Time.Sub(earlier.Last) > rule.correlation.timespan {
			return nil
		}
	}

	parts := make([]*Alert, len(state.latest))
	copy(parts, state.latest)
	sort.SliceStable(parts, func(first, second int) bool { return parts[first].order < parts[second].order })
	state.latest = make([]*Alert, len(parts))

	return rule.joined(state.group, parts)
}

// inOrder handles temporal_ordered. chains[i] is the newest chain of hits for the first i+1 rules of the list.
func (rule *Rule) inOrder(state *groupState, current step) *Alert {
	last := len(rule.correlation.references) - 1
	if state.chains == nil {
		state.chains = make([][]*Alert, last+1)
	}

	if current.index == 0 {
		state.chains[0] = []*Alert{current.hit}

		return nil
	}

	before := state.chains[current.index-1]
	if before == nil {
		return nil
	}
	previous := before[len(before)-1]
	if current.hit.order <= previous.order || current.hit.Time.Sub(previous.Last) > rule.correlation.timespan {
		return nil
	}

	chain := append(append([]*Alert{}, before...), current.hit)
	if current.index < last {
		state.chains[current.index] = chain

		return nil
	}
	state.chains = nil

	return rule.joined(state.group, chain)
}

func (rule *Rule) joined(group []Pair, parts []*Alert) *Alert {
	final := parts[len(parts)-1]
	alert := &Alert{Rule: rule, Time: final.Time, First: parts[0].First, Last: final.Last, Group: group, Parts: parts, order: final.order}
	share := MaxEvidence / len(parts)
	for _, part := range parts {
		alert.Count += part.Count
		if part.First.Before(alert.First) {
			alert.First = part.First
		}
		if part.Last.After(alert.Last) {
			alert.Last = part.Last
		}
		events := part.Events
		if len(events) > share {
			events = events[:share]
		}
		alert.addEvents(events)
	}

	return alert
}
