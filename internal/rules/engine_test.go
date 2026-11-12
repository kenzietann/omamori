package rules

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

var start = time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)

func at(seconds int, fields ...string) event.Event {
	made := event.Event{Time: start.Add(time.Duration(seconds) * time.Second), Ref: fmt.Sprintf("t:%d", seconds), Fields: map[string]string{}}
	for index := 0; index+1 < len(fields); index += 2 {
		made.Fields[fields[index]] = fields[index+1]
	}

	return made
}

func mustSet(t *testing.T, text string) Set {
	t.Helper()
	parsed, err := Parse([]byte(text), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewSet(parsed)
	if err != nil {
		t.Fatal(err)
	}

	return set
}

func detectionRule(detection string) string {
	return "title: T\nname: t\ndetection:\n" + detection
}

func TestDetectionMatching(t *testing.T) {
	cases := []struct {
		name      string
		detection string
		fields    []string
		want      bool
	}{
		{"equal without regard to case", "  s: {user: Root}\n  condition: s", []string{"user", "rOOT"}, true},
		{"equal is not contains", "  s: {user: roo}\n  condition: s", []string{"user", "root"}, false},
		{"missing field does not match", "  s: {user: root}\n  condition: s", []string{"src_ip", "1.2.3.4"}, false},
		{"empty text needs a present field", "  s: {user: ''}\n  condition: s", []string{"src_ip", "1.2.3.4"}, false},
		{"empty text matches a present empty field", "  s: {user: ''}\n  condition: s", []string{"user", ""}, true},
		{"wildcard needs a present field", "  s: {user: '*'}\n  condition: s", []string{"src_ip", "1.2.3.4"}, false},
		{"empty regex needs a present field", "  s: {user|re: '^$'}\n  condition: s", []string{"src_ip", "1.2.3.4"}, false},
		{"list is any", "  s: {user: [admin, root]}\n  condition: s", []string{"user", "root"}, true},
		{"two fields are all", "  s: {user: root, outcome: failure}\n  condition: s", []string{"user", "root", "outcome", "success"}, false},
		{"number is compared as text", "  s: {status: 404}\n  condition: s", []string{"status", "404"}, true},
		{"contains", "  s: {url|contains: '/.env'}\n  condition: s", []string{"url", "/app/.ENV.bak"}, true},
		{"contains all needs every value", "  s: {command|contains|all: [curl, '| sh']}\n  condition: s", []string{"command", "curl http://x"}, false},
		{"contains all with every value", "  s: {command|contains|all: [curl, '| sh']}\n  condition: s", []string{"command", "curl http://x | sh"}, true},
		{"startswith", "  s: {url|startswith: /admin}\n  condition: s", []string{"url", "/administrator"}, true},
		{"startswith is not contains", "  s: {url|startswith: /admin}\n  condition: s", []string{"url", "/x/admin"}, false},
		{"endswith", "  s: {url|endswith: .php}\n  condition: s", []string{"url", "/a.PHP"}, true},
		{"wildcard star", "  s: {url: '/a/*/c'}\n  condition: s", []string{"url", "/a/bbb/c"}, true},
		{"wildcard is anchored", "  s: {url: '/a/*/c'}\n  condition: s", []string{"url", "/a/bbb/cd"}, false},
		{"wildcard question mark is one character", "  s: {user: 'adm?n'}\n  condition: s", []string{"user", "admn"}, false},
		{"escaped star is a star", "  s: {url: 'a\\*b'}\n  condition: s", []string{"url", "axxb"}, false},
		{"escaped star matches a star", "  s: {url: 'a\\*b'}\n  condition: s", []string{"url", "a*b"}, true},
		{"regex metacharacters in plain text are plain", "  s: {url|contains: 'a.c('}\n  condition: s", []string{"url", "abc("}, false},
		{"cased", "  s: {user|cased: Root}\n  condition: s", []string{"user", "root"}, false},
		{"regex", "  s: {url|re: '^/v[0-9]+/'}\n  condition: s", []string{"url", "/v12/items"}, true},
		{"regex is cased", "  s: {url|re: 'select'}\n  condition: s", []string{"url", "SELECT"}, false},
		{"regex with i", "  s: {url|re|i: 'select'}\n  condition: s", []string{"url", "SELECT"}, true},
		{"cidr inside", "  s: {src_ip|cidr: 10.0.0.0/8}\n  condition: s", []string{"src_ip", "10.200.3.4"}, true},
		{"cidr outside", "  s: {src_ip|cidr: 10.0.0.0/8}\n  condition: s", []string{"src_ip", "11.0.0.1"}, false},
		{"cidr with text that is no address", "  s: {src_ip|cidr: 10.0.0.0/8}\n  condition: s", []string{"src_ip", "10.0.0.1; rm"}, false},
		{"gte", "  s: {status|gte: 500}\n  condition: s", []string{"status", "503"}, true},
		{"gte with text", "  s: {status|gte: 500}\n  condition: s", []string{"status", "abc"}, false},
		{"lt", "  s: {status|lt: 400}\n  condition: s", []string{"status", "400"}, false},
		{"exists true", "  s: {user|exists: true}\n  condition: s", []string{"user", ""}, true},
		{"exists false", "  s: {user|exists: false}\n  condition: s", []string{"user", "x"}, false},
		{"null matches a missing field", "  s: {user: null}\n  condition: s", []string{"url", "/"}, true},
		{"null does not match a value", "  s: {user: null}\n  condition: s", []string{"user", "x"}, false},
		{"sigma field names are mapped", "  s: {c-ip: 203.0.113.9, sc-status: 200}\n  condition: s", []string{"src_ip", "203.0.113.9", "status", "200"}, true},
		{"and not", "  s: {action: login}\n  f: {user: backup}\n  condition: s and not f", []string{"action", "login", "user", "backup"}, false},
		{"or", "  a: {user: x}\n  b: {user: y}\n  condition: a or b", []string{"user", "y"}, true},
		{"and binds tighter than or", "  a: {user: x}\n  b: {user: y}\n  c: {status: 1}\n  condition: a or b and c", []string{"user", "x", "status", "2"}, true},
		{"brackets", "  a: {user: x}\n  b: {user: y}\n  c: {status: 1}\n  condition: (a or b) and c", []string{"user", "x", "status", "2"}, false},
		{"1 of pattern", "  sel_a: {user: x}\n  sel_b: {user: y}\n  other: {user: z}\n  condition: 1 of sel_*", []string{"user", "z"}, false},
		{"all of them", "  a: {user: x}\n  b: {status: 1}\n  condition: all of them", []string{"user", "x", "status", "1"}, true},
		{"all of them with one missing", "  a: {user: x}\n  b: {status: 1}\n  condition: all of them", []string{"user", "x"}, false},
		{"list of maps is any map", "  s:\n    - {user: x, status: 1}\n    - {user: y}\n  condition: s", []string{"user", "y"}, true},
		{"keywords look in every field", "  s: ['segfault', 'Out of memory']\n  condition: s", []string{"message", "kernel: OUT OF MEMORY: killed"}, true},
		{"keywords that are absent", "  s: ['segfault']\n  condition: s", []string{"message", "all fine"}, false},
		{"list of conditions is any", "  a: {user: x}\n  b: {user: y}\n  condition: [a, b]", []string{"user", "y"}, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			set := mustSet(t, detectionRule(testCase.detection))
			got := len(set.Evaluate([]event.Event{at(0, testCase.fields...)}).Alerts) == 1
			if got != testCase.want {
				t.Fatalf("match is %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestLogSourceLimitsARule(t *testing.T) {
	set := mustSet(t, "title: T\nlogsource: {product: linux, service: sshd}\ndetection:\n  s: {action: login}\n  condition: s")
	events := []event.Event{
		at(0, "action", "login", "product", "linux", "service", "SSHD"),
		at(1, "action", "login", "product", "linux", "service", "sudo"),
		at(2, "action", "login"),
	}
	if got := len(set.Evaluate(events).Alerts); got != 1 {
		t.Fatalf("%d alerts, want 1: only the sshd event has the right source", got)
	}
}

func TestRulesThatMustBeRefused(t *testing.T) {
	cases := map[string]string{
		"no title":                        "detection:\n  s: {a: b}\n  condition: s",
		"no detection":                    "title: T",
		"detection and correlation":       "title: T\ndetection:\n  s: {a: b}\n  condition: s\ncorrelation: {type: event_count}",
		"unknown level":                   "title: T\nlevel: scary\ndetection:\n  s: {a: b}\n  condition: s",
		"unknown modifier":                detectionRule("  s: {a|base64offset: b}\n  condition: s"),
		"windash is not silently ignored": detectionRule("  s: {a|windash|contains: b}\n  condition: s"),
		"two shapes":                      detectionRule("  s: {a|contains|endswith: b}\n  condition: s"),
		"bad regex":                       detectionRule("  s: {a|re: '('}\n  condition: s"),
		"bad cidr":                        detectionRule("  s: {a|cidr: 10.0.0.300/8}\n  condition: s"),
		"number modifier with text":       detectionRule("  s: {a|gt: many}\n  condition: s"),
		"exists with text":                detectionRule("  s: {a|exists: yes please}\n  condition: s"),
		"map as value":                    detectionRule("  s: {a: {b: c}}\n  condition: s"),
		"empty selection":                 detectionRule("  s: {}\n  condition: s"),
		"no condition":                    detectionRule("  s: {a: b}"),
		"condition names nothing":         detectionRule("  s: {a: b}\n  condition: other"),
		"condition with unclosed bracket": detectionRule("  s: {a: b}\n  condition: (s"),
		"condition with extra":            detectionRule("  s: {a: b}\n  condition: s s"),
		"old aggregation":                 detectionRule("  s: {a: b}\n  condition: s | count() > 5"),
		"old timeframe":                   detectionRule("  s: {a: b}\n  timeframe: 5m\n  condition: s"),
		"logsource with a list":           "title: T\nlogsource: {product: [a, b]}\ndetection:\n  s: {a: b}\n  condition: s",
		"not yaml":                        "title: [",
		"correlation without rules":       "title: T\ncorrelation: {type: event_count, timespan: 5m, condition: {gte: 2}}",
		"correlation unknown type":        "title: T\ncorrelation: {type: magic, rules: [a], timespan: 5m, condition: {gte: 2}}",
		"correlation bad timespan":        "title: T\ncorrelation: {type: event_count, rules: [a], timespan: soon, condition: {gte: 2}}",
		"correlation timespan too long":   "title: T\ncorrelation: {type: event_count, rules: [a], timespan: 31d, condition: {gte: 2}}",
		"correlation negative timespan":   "title: T\ncorrelation: {type: event_count, rules: [a], timespan: -5m, condition: {gte: 2}}",
		"correlation lt":                  "title: T\ncorrelation: {type: event_count, rules: [a], timespan: 5m, condition: {lt: 2}}",
		"correlation zero":                "title: T\ncorrelation: {type: event_count, rules: [a], timespan: 5m, condition: {gte: 0}}",
		"correlation two numbers":         "title: T\ncorrelation: {type: event_count, rules: [a], timespan: 5m, condition: {gte: 2, gt: 3}}",
		"value_count without field":       "title: T\ncorrelation: {type: value_count, rules: [a], timespan: 5m, condition: {gte: 2}}",
		"event_count with field":          "title: T\ncorrelation: {type: event_count, rules: [a], timespan: 5m, condition: {gte: 2, field: user}}",
		"temporal with one rule":          "title: T\ncorrelation: {type: temporal, rules: [a], timespan: 5m}",
		"temporal with condition":         "title: T\ncorrelation: {type: temporal_ordered, rules: [a, b], timespan: 5m, condition: {gte: 2}}",
		"correlation same rule twice":     "title: T\ncorrelation: {type: temporal_ordered, rules: [a, a], timespan: 5m}",
		"correlation unknown key":         "title: T\ncorrelation: {type: event_count, rules: [a], timespan: 5m, condition: {gte: 2}, aliases: {}}",
		"test without expect":             detectionRule("  s: {a: b}\n  condition: s\ntests:\n  - events: [{a: b}]"),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(text), "bad.yml"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error is %v, want ErrInvalid", err)
			}
		})
	}
}

const base = "title: Fail\nname: fail\ndetection:\n  s: {outcome: failure}\n  condition: s\n---\ntitle: OK\nname: ok\ndetection:\n  s: {outcome: success}\n  condition: s\n---\n"

func TestSetsThatMustBeRefused(t *testing.T) {
	cases := map[string]string{
		"reference to nothing":        base + "title: C\ncorrelation: {type: event_count, rules: [nothing], timespan: 5m, condition: {gte: 2}}",
		"same name twice":             base + "title: Other\nname: fail\ndetection:\n  s: {a: b}\n  condition: s",
		"same rule through two names": base + "title: C\ncorrelation: {type: event_count, rules: [fail, Fail], timespan: 5m, condition: {gte: 2}}",
		"circle": base + "title: A\nname: a\ncorrelation: {type: event_count, rules: [b], timespan: 5m, condition: {gte: 2}}\n---\n" +
			"title: B\nname: b\ncorrelation: {type: event_count, rules: [a], timespan: 5m, condition: {gte: 2}}",
		"rule that counts itself": "title: A\nname: a\ncorrelation: {type: event_count, rules: [a], timespan: 5m, condition: {gte: 2}}",
		"own test fails":          "title: T\ndetection:\n  s: {a: b}\n  condition: s\ntests:\n  - events: [{a: c}]\n    expect: {alerts: 1}",
		"own test with bad time":  "title: T\ndetection:\n  s: {a: b}\n  condition: s\ntests:\n  - events: [{a: b, time: yesterday}]\n    expect: {alerts: 1}",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			parsed, err := Parse([]byte(text), "bad.yml")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewSet(parsed); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error is %v, want ErrInvalid", err)
			}
		})
	}
}

func TestTooBigRuleFileIsRefused(t *testing.T) {
	if _, err := Parse([]byte("title: T\n#"+strings.Repeat("x", maxFileBytes)), "big.yml"); !errors.Is(err, ErrTooBig) {
		t.Fatalf("error is %v, want ErrTooBig", err)
	}
}

func failures(ip string, user string, from, count, step int) []event.Event {
	var events []event.Event
	for index := 0; index < count; index++ {
		events = append(events, at(from+index*step, "outcome", "failure", "src_ip", ip, "user", user))
	}

	return events
}

const countRule = base + "title: Burst\nname: burst\nlevel: high\ncorrelation: {type: event_count, rules: [fail], group-by: [src_ip], timespan: 60s, condition: {gte: 5}}"

func TestEventCount(t *testing.T) {
	set := mustSet(t, countRule)
	cases := []struct {
		name   string
		events []event.Event
		alerts int
		count  int
	}{
		{"four are under the limit", failures("1.1.1.1", "root", 0, 4, 1), 0, 0},
		{"five reach the limit", failures("1.1.1.1", "root", 0, 5, 1), 1, 5},
		{"exactly on the edge of the window", failures("1.1.1.1", "root", 0, 5, 15), 1, 5},
		{"one second over the window", append(failures("1.1.1.1", "root", 0, 4, 15), at(61, "outcome", "failure", "src_ip", "1.1.1.1")), 0, 0},
		{"two addresses are counted apart", append(failures("1.1.1.1", "root", 0, 4, 1), failures("2.2.2.2", "root", 0, 4, 1)...), 0, 0},
		{"a long burst is one alert", failures("1.1.1.1", "root", 0, 300, 2), 1, 300},
		{"two bursts with a pause are two alerts", append(failures("1.1.1.1", "root", 0, 6, 1), failures("1.1.1.1", "root", 500, 6, 1)...), 2, 6},
		{"events without the group field are not counted", []event.Event{at(0, "outcome", "failure"), at(1, "outcome", "failure"), at(2, "outcome", "failure"), at(3, "outcome", "failure"), at(4, "outcome", "failure")}, 0, 0},
		{"successes are not counted", []event.Event{at(0, "outcome", "success", "src_ip", "1.1.1.1"), at(1, "outcome", "success", "src_ip", "1.1.1.1"), at(2, "outcome", "success", "src_ip", "1.1.1.1"), at(3, "outcome", "success", "src_ip", "1.1.1.1"), at(4, "outcome", "success", "src_ip", "1.1.1.1")}, 0, 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var alerts []*Alert
			for _, alert := range set.Evaluate(testCase.events).Alerts {
				if alert.Rule.Name == "burst" {
					alerts = append(alerts, alert)
				}
			}
			if len(alerts) != testCase.alerts {
				t.Fatalf("%d alerts, want %d", len(alerts), testCase.alerts)
			}
			if len(alerts) > 0 && alerts[0].Count != testCase.count {
				t.Fatalf("count is %d, want %d", alerts[0].Count, testCase.count)
			}
		})
	}
}

func TestBurstAlertSaysWhenAndWho(t *testing.T) {
	alerts := mustSet(t, countRule).Evaluate(failures("1.1.1.1", "root", 10, 100, 1)).Alerts
	if len(alerts) != 1 {
		t.Fatalf("%d alerts, want 1", len(alerts))
	}
	alert := alerts[0]
	if !alert.First.Equal(start.Add(10*time.Second)) || !alert.Time.Equal(start.Add(14*time.Second)) || !alert.Last.Equal(start.Add(109*time.Second)) {
		t.Fatalf("first %v, fired %v, last %v", alert.First, alert.Time, alert.Last)
	}
	if len(alert.Group) != 1 || alert.Group[0] != (Pair{"src_ip", "1.1.1.1"}) {
		t.Fatalf("group is %v", alert.Group)
	}
	if len(alert.Events) != MaxEvidence || alert.Events[0].Ref != "t:10" {
		t.Fatalf("%d events are kept, the first is %s", len(alert.Events), alert.Events[0].Ref)
	}
	if alert.Rule.Name != "burst" || alert.Rule.Level != "high" {
		t.Fatalf("rule is %s (%s)", alert.Rule.Name, alert.Rule.Level)
	}
}

func TestEvaluateSortsEventsAndLeavesTheInputAlone(t *testing.T) {
	events := failures("1.1.1.1", "root", 0, 5, 1)
	events[0], events[4] = events[4], events[0]
	alerts := mustSet(t, countRule).Evaluate(events).Alerts
	if len(alerts) != 1 || alerts[0].Events[0].Ref != "t:0" {
		t.Fatal("events that are not in the order of time must give the same alert")
	}
	if events[0].Ref != "t:4" {
		t.Fatal("the input was changed")
	}
}

func TestValueCount(t *testing.T) {
	set := mustSet(t, base+"title: Spray\nname: spray\ncorrelation: {type: value_count, rules: [fail], group-by: [src_ip], timespan: 60s, condition: {gte: 3, field: user}}")
	spray := func(users ...string) []event.Event {
		var events []event.Event
		for index, user := range users {
			events = append(events, at(index, "outcome", "failure", "src_ip", "1.1.1.1", "user", user))
		}

		return events
	}
	cases := []struct {
		name   string
		events []event.Event
		alerts int
		values int
	}{
		{"three users", spray("a", "b", "c"), 1, 3},
		{"two users many times", spray("a", "b", "a", "b", "a", "b"), 0, 0},
		{"users after the limit go into the same alert", spray("a", "b", "c", "d", "e", "a"), 1, 5},
		{"an event without the field is not a value", append(spray("a", "b"), at(2, "outcome", "failure", "src_ip", "1.1.1.1")), 0, 0},
		{"three users, the third too late", append(spray("a", "b"), at(90, "outcome", "failure", "src_ip", "1.1.1.1", "user", "c")), 0, 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			alerts := set.Evaluate(testCase.events).Alerts
			if len(alerts) != testCase.alerts {
				t.Fatalf("%d alerts, want %d", len(alerts), testCase.alerts)
			}
			if len(alerts) > 0 && len(alerts[0].Values) != testCase.values {
				t.Fatalf("values are %v, want %d of them", alerts[0].Values, testCase.values)
			}
		})
	}
}

const sequenceRules = countRule + "\n---\ntitle: Takeover\nname: takeover\nlevel: critical\ncorrelation: {type: temporal_ordered, rules: [burst, ok], group-by: [src_ip], timespan: 60s}"

func TestOrderedSequence(t *testing.T) {
	set := mustSet(t, sequenceRules)
	success := func(second int, ip string) event.Event {
		return at(second, "outcome", "success", "src_ip", ip, "user", "root")
	}
	cases := []struct {
		name     string
		events   []event.Event
		takeover int
	}{
		{"failures, then a success", append(failures("1.1.1.1", "root", 0, 5, 1), success(10, "1.1.1.1")), 1},
		{"a success first", append([]event.Event{success(0, "1.1.1.1")}, failures("1.1.1.1", "root", 1, 5, 1)...), 0},
		{"a success in the middle, before the limit", append(failures("1.1.1.1", "root", 0, 5, 2), success(5, "1.1.1.1")), 0},
		{"a success from another address", append(failures("1.1.1.1", "root", 0, 5, 1), success(10, "2.2.2.2")), 0},
		{"too few failures", append(failures("1.1.1.1", "root", 0, 4, 1), success(10, "1.1.1.1")), 0},
		{"a success long after the burst ended", append(failures("1.1.1.1", "root", 0, 5, 1), success(200, "1.1.1.1")), 0},
		{"a success soon after a long burst", append(failures("1.1.1.1", "root", 0, 200, 2), success(420, "1.1.1.1")), 1},
		{"a success in the same second as the last failure", append(failures("1.1.1.1", "root", 0, 5, 1), success(4, "1.1.1.1")), 1},
		{"two successes give one alert", append(failures("1.1.1.1", "root", 0, 5, 1), success(10, "1.1.1.1"), success(11, "1.1.1.1")), 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := 0
			for _, alert := range set.Evaluate(testCase.events).Alerts {
				if alert.Rule.Name == "takeover" {
					got++
					if len(alert.Parts) != 2 || alert.Parts[0].Rule.Name != "burst" || alert.Parts[1].Rule.Name != "ok" {
						t.Fatalf("the steps are wrong: %v", alert.Parts)
					}
					if last := alert.Parts[1].Events[0]; last.Fields["outcome"] != "success" {
						t.Fatal("the last step must be the success")
					}
				}
			}
			if got != testCase.takeover {
				t.Fatalf("%d takeover alerts, want %d", got, testCase.takeover)
			}
		})
	}
}

func TestOrderedSequenceNeedsTwoEvents(t *testing.T) {
	set := mustSet(t, "title: A\nname: a\ndetection:\n  s: {x: 1}\n  condition: s\n---\ntitle: B\nname: b\ndetection:\n  s: {y: 1}\n  condition: s\n---\n"+
		"title: Seq\nname: seq\ncorrelation: {type: temporal_ordered, rules: [a, b], group-by: [user], timespan: 60s}")
	if got := len(set.Evaluate([]event.Event{at(0, "x", "1", "y", "1", "user", "u")}).Alerts); got != 0 {
		t.Fatalf("%d alerts from one event, want 0", got)
	}
	if got := len(set.Evaluate([]event.Event{at(0, "x", "1", "user", "u"), at(0, "y", "1", "user", "u")}).Alerts); got != 1 {
		t.Fatalf("%d alerts from two events in the same second, want 1", got)
	}
	if got := len(set.Evaluate([]event.Event{at(0, "x", "1", "user", "u"), at(1, "x", "1", "y", "1", "user", "u")}).Alerts); got != 1 {
		t.Fatalf("%d alerts when the second event matches both steps, want 1", got)
	}
}

func TestValueCountCapsEvidenceWhenTheThresholdIsReached(t *testing.T) {
	set := mustSet(t, base+"title: Many users\nname: many\ncorrelation: {type: value_count, rules: [fail], timespan: 1h, condition: {gte: 205, field: user}}")
	var events []event.Event
	for index := 0; index < 210; index++ {
		events = append(events, at(index, "outcome", "failure", "user", fmt.Sprintf("user-%d", index)))
	}
	alerts := set.Evaluate(events).Alerts
	if len(alerts) != 1 || alerts[0].Count != 210 || len(alerts[0].Values) != maxValuesIn {
		t.Fatalf("want one 210-hit alert with %d values, got %v", maxValuesIn, alerts)
	}
	if alerts[0].Values[0] != "user-0" || alerts[0].Values[maxValuesIn-1] != "user-199" {
		t.Fatal("the first values must be retained in event order")
	}
}

func TestQuietAndLoudRules(t *testing.T) {
	events := append(failures("1.1.1.1", "root", 0, 5, 1), at(10, "outcome", "success", "src_ip", "1.1.1.1"))
	names := func(set Set) string {
		var list []string
		for _, alert := range set.Evaluate(events).Alerts {
			list = append(list, alert.Rule.Name)
		}

		return strings.Join(list, " ")
	}

	if got := names(mustSet(t, sequenceRules)); got != "burst takeover" {
		t.Fatalf("alerts are %q", got)
	}
	loud := strings.Replace(countRule, "timespan: 60s,", "timespan: 60s, generate: true,", 1)
	if got := names(mustSet(t, loud)); got != "fail fail fail fail fail burst ok" {
		t.Fatalf("with generate the alerts are %q", got)
	}
}

func TestTemporalInAnyOrder(t *testing.T) {
	set := mustSet(t, base+"title: Both\nname: both\ncorrelation: {type: temporal, rules: [fail, ok], group-by: [user], timespan: 30s}")
	cases := []struct {
		name   string
		events []event.Event
		alerts int
	}{
		{"failure then success", []event.Event{at(0, "outcome", "failure", "user", "a"), at(5, "outcome", "success", "user", "a")}, 1},
		{"success then failure", []event.Event{at(0, "outcome", "success", "user", "a"), at(5, "outcome", "failure", "user", "a")}, 1},
		{"too far apart", []event.Event{at(0, "outcome", "failure", "user", "a"), at(31, "outcome", "success", "user", "a")}, 0},
		{"different users", []event.Event{at(0, "outcome", "failure", "user", "a"), at(5, "outcome", "success", "user", "b")}, 0},
		{"only one kind", []event.Event{at(0, "outcome", "failure", "user", "a"), at(5, "outcome", "failure", "user", "a")}, 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := len(set.Evaluate(testCase.events).Alerts); got != testCase.alerts {
				t.Fatalf("%d alerts, want %d", got, testCase.alerts)
			}
		})
	}
}

func TestDurations(t *testing.T) {
	good := map[string]time.Duration{"30s": 30 * time.Second, "10m": 10 * time.Minute, "2h": 2 * time.Hour, "1d": 24 * time.Hour, "30d": 30 * 24 * time.Hour}
	for text, want := range good {
		if got, err := parseDuration(text); err != nil || got != want {
			t.Errorf("%s: %v, %v", text, got, err)
		}
	}
	for _, text := range []string{"", "5", "0s", "-1m", "31d", "721h", "1w", "d", "1e9d", "NaNd"} {
		if _, err := parseDuration(text); err == nil {
			t.Errorf("%q was accepted", text)
		}
	}
}

func TestLoadReadsAFolderAndRefusesABadOne(t *testing.T) {
	folder := t.TempDir()
	write := func(name, text string) {
		t.Helper()
		if err := writeFile(folder, name, text); err != nil {
			t.Fatal(err)
		}
	}
	write("a.yml", detectionRule("  s: {a: b}\n  condition: s"))
	write("sub/b.yaml", "title: U\nname: u\ndetection:\n  s: {a: c}\n  condition: s")
	write("notes.txt", "this is not a rule: [")
	set, err := Load(folder)
	if err != nil || len(set.Rules()) != 2 {
		t.Fatalf("%d rules, %v", len(set.Rules()), err)
	}

	write("c.yml", "title: [")
	if _, err := Load(folder); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error is %v, want ErrInvalid", err)
	}
	if _, err := Load(folder + "-missing"); err == nil {
		t.Fatal("a missing folder was accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(detectionRule("  s: {a|contains: b}\n  condition: s and not 1 of s*"))
	f.Add(countRule)
	f.Add(sequenceRules)
	f.Add("title: T\ndetection:\n  s: ['*', '?']\n  condition: all of them\ntests:\n  - events: [{a: 1, time: '2026-01-01T00:00:00Z'}]\n    expect: {alerts: 1}")
	f.Fuzz(func(t *testing.T, text string) {
		parsed, err := Parse([]byte(text), "fuzz.yml")
		if err != nil {
			if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrTooBig) {
				t.Fatalf("unexpected kind of error: %v", err)
			}

			return
		}
		set, err := NewSet(parsed)
		if err != nil {
			return
		}
		// A rule that loads must be able to look at any event without a panic.
		set.Evaluate([]event.Event{at(0, "a", "b", "user", "root", "src_ip", "1.1.1.1"), at(1), at(2, "message", text)})
	})
}

func FuzzCondition(f *testing.F) {
	for _, seed := range []string{"a", "a and b", "not (a or b)", "1 of a*", "all of them", "((((a", "a or", "1 of", ")"} {
		f.Add(seed)
	}
	selections := map[string]selection{"a": {}, "b": {}, "ab": {}}
	f.Fuzz(func(t *testing.T, text string) {
		parsed, err := parseCondition(text, selections)
		if err == nil {
			parsed.eval(func(name string) bool { return name == "a" })
		}
	})
}

const aliasRules = base + "title: Burst\nname: burst\ncorrelation: {type: event_count, rules: [fail], group-by: [src_ip], timespan: 60s, condition: {gte: 3}}\n---\n" +
	"title: Joined\nname: joined\ncorrelation:\n  type: temporal_ordered\n  rules: [ok, burst]\n  aliases:\n    machine: {ok: asset, burst: src_asset}\n  group-by: [machine]\n  timespan: 10m"

// A machine is "asset" where it wrote the log and "src_asset" where another host saw it. An alias lets
// one correlation follow it through both.
func TestAliasesJoinDifferentFieldsOfTheRules(t *testing.T) {
	set := mustSet(t, aliasRules)
	login := func(second int, asset string) event.Event {
		return at(second, "outcome", "success", "src_ip", "203.0.113.9", "asset", asset)
	}
	guesses := func(from int, source, asset string) []event.Event {
		var events []event.Event
		for index := 0; index < 3; index++ {
			events = append(events, at(from+index, "outcome", "failure", "src_ip", "10.0.1.10", "src_asset", source, "asset", asset))
		}

		return events
	}
	cases := []struct {
		name   string
		events []event.Event
		want   int
	}{
		{"a login on web01, then web01 guesses on app01", append([]event.Event{login(0, "web01")}, guesses(10, "web01", "app01")...), 1},
		{"the guessing host is another machine", append([]event.Event{login(0, "web01")}, guesses(10, "build01", "app01")...), 0},
		{"the login was on the host that is guessed at", append([]event.Event{login(0, "app01")}, guesses(10, "web01", "app01")...), 0},
		{"the guessing comes first", append(guesses(0, "web01", "app01"), login(10, "web01")), 0},
		{"no asset fields at all", []event.Event{at(0, "outcome", "success", "src_ip", "203.0.113.9"), at(10, "outcome", "failure", "src_ip", "10.0.1.10"), at(11, "outcome", "failure", "src_ip", "10.0.1.10"), at(12, "outcome", "failure", "src_ip", "10.0.1.10")}, 0},
		{"the first guess names another machine", append([]event.Event{login(0, "web01"), at(9, "outcome", "failure", "src_ip", "10.0.1.10", "src_asset", "other", "asset", "app01")}, guesses(10, "web01", "app01")[:2]...), 0},
		{"the guesses name two different machines", append([]event.Event{login(0, "web01")}, append(guesses(10, "web01", "app01")[:2], at(12, "outcome", "failure", "src_ip", "10.0.1.10", "src_asset", "other", "asset", "app01"))...), 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := 0
			for _, alert := range set.Evaluate(testCase.events).Alerts {
				if alert.Rule.Name != "joined" {
					continue
				}
				got++
				if len(alert.Group) != 1 || alert.Group[0] != (Pair{"machine", "web01"}) {
					t.Errorf("the group is %v", alert.Group)
				}
			}
			if got != testCase.want {
				t.Fatalf("%d joined alerts, want %d", got, testCase.want)
			}
		})
	}
}

func TestAliasesThatMustBeRefused(t *testing.T) {
	head := "title: T\ncorrelation:\n  type: temporal_ordered\n  rules: [a, b]\n  timespan: 5m\n  group-by: [machine]\n  aliases:\n"
	for name, text := range map[string]string{
		"not a map":              head + "    - machine\n",
		"a name not in group-by": head + "    other: {a: x, b: y}\n",
		"a rule without a field": head + "    machine: {a: x}\n",
		"a rule not in the list": head + "    machine: {a: x, c: y}\n",
		"one rule too many":      head + "    machine: {a: x, b: y, c: z}\n",
		"a field that is a list": head + "    machine: {a: x, b: [y]}\n",
		"an empty field":         head + "    machine: {a: x, b: ''}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(text), "bad.yml"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error is %v, want ErrInvalid", err)
			}
		})
	}
}
