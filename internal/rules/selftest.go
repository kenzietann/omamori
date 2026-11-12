package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

//go:embed builtin/*.yml
var builtinFiles embed.FS

//go:embed forensic/*.yml
var forensicFiles embed.FS

func BuiltinForensics() (Set, error) {
	var all []*Rule
	for _, source := range []struct {
		files  embed.FS
		folder string
	}{{builtinFiles, "builtin"}, {forensicFiles, "forensic"}} {
		system, err := fs.Sub(source.files, source.folder)
		if err != nil {
			return Set{}, err
		}
		parsed, err := parseFS(system)
		if err != nil {
			return Set{}, err
		}
		all = append(all, parsed...)
	}

	return NewSet(all)
}

func Builtin() (Set, error) {
	system, err := fs.Sub(builtinFiles, "builtin")
	if err != nil {
		return Set{}, err
	}

	return LoadFS(system)
}

var testStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// runTests runs the tests that the rules carry. One failed test refuses the whole set, because a rule that
// does not do what its author wrote down is not a rule to rely on.
func (set Set) runTests() error {
	for _, rule := range set.rules {
		for number, test := range rule.tests {
			name := test.Name
			if name == "" {
				name = fmt.Sprintf("number %d", number+1)
			}

			events, err := testEvents(test.Events)
			if err != nil {
				return fmt.Errorf("%w: rule %q, test %q: %s", ErrInvalid, truncate(rule.Title, 60), truncate(name, 60), err)
			}
			hits, _ := set.evaluate(events)
			if got := len(hits[rule]); got != test.Alerts {
				return fmt.Errorf("%w: rule %q, test %q: it gives %d alerts, and the test expects %d",
					ErrInvalid, truncate(rule.Title, 60), truncate(name, 60), got, test.Alerts)
			}
		}
	}

	return nil
}

func testEvents(raw []map[string]any) ([]event.Event, error) {
	events := make([]event.Event, 0, len(raw))
	for index, item := range raw {
		current := event.Event{Time: testStart.Add(time.Duration(index) * time.Second), Source: "test", Ref: fmt.Sprintf("test:%d", index+1), Fields: map[string]string{}}
		for key, value := range item {
			if key == "time" {
				moment, isTime := value.(time.Time)
				if text, isText := value.(string); isText {
					var err error
					if moment, err = time.Parse(time.RFC3339, text); err != nil {
						return nil, fmt.Errorf("the time of event %d is not valid", index+1)
					}
				} else if !isTime {
					return nil, fmt.Errorf("the time of event %d is not valid", index+1)
				}
				current.Time = moment
				continue
			}
			text, err := scalarText(value)
			if err != nil {
				return nil, fmt.Errorf("the field %q of event %d is not a simple value", truncate(key, 40), index+1)
			}
			current.Fields[event.Canonical(key)] = text
		}
		events = append(events, current)
	}

	return events, nil
}
