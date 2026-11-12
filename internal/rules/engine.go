package rules

import (
	"sort"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

const (
	MaxEvidence = 50
	maxValuesIn = 200
	maxHits     = 500_000
)

type Pair struct {
	Field string
	Value string
}

type Alert struct {
	Rule   *Rule
	Time   time.Time
	First  time.Time
	Last   time.Time
	Group  []Pair
	Count  int
	Events []event.Event
	Values []string
	Parts  []*Alert

	order int
}

type Result struct {
	Alerts []*Alert
	Cut    []string
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

	// A hit of a correlation also has a field when every event that it kept has it with one value:
	// ten failed logins on one host are a hit "on that host", whatever the hit was grouped by.
	shared := ""
	for _, kept := range alert.Events {
		value, found := kept.Get(name)
		if !found || value == "" || shared != "" && value != shared {
			return "", false
		}
		shared = value
	}

	return shared, shared != ""
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

func (rule *Rule) fitsSource(candidate event.Event) bool {
	for key, wanted := range rule.LogSource {
		if value, found := candidate.Fields[key]; !found || !strings.EqualFold(value, wanted) {
			return false
		}
	}

	return true
}

type step struct {
	hit   *Alert
	index int
}

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

func (rule *Rule) groupOf(current step) (key string, group []Pair, complete bool) {
	var builder strings.Builder
	for _, field := range rule.correlation.groupBy {
		source := field
		if fields, aliased := rule.correlation.aliases[field]; aliased {
			source = fields[current.index]
		}
		value, found := current.hit.field(source)
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
		key, group, complete := rule.groupOf(current)
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

type groupState struct {
	group  []Pair
	window []*Alert
	burst  *Alert
	values map[string]bool
	latest []*Alert
	chains [][]*Alert
}

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
