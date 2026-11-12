// Package rules is a detection rule engine. The rule format is a subset of Sigma (the open format for
// detection rules), so rules can be shared and read by other tools. A rule is data: it is read, matched
// against events and counted. It never runs anything.
//
// Two kinds of rule exist. A detection rule says which single events are interesting. A correlation rule
// counts the events of other rules: how many in a time window, or how many different values.
// Every rule can carry tests (events and the number of alerts that they must give), and a rule whose tests
// fail is not accepted. This is the same idea as the checker of the log triage: nothing is trusted until it is checked.
package rules

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	maxFileBytes   = 256 << 10
	maxRules       = 5000
	maxRegexLength = 1000
	maxCondition   = 500
	maxTests       = 100
	maxTestEvents  = 1000
)

var (
	ErrTooBig  = errors.New("a rule file is too big, or there are too many rules")
	ErrInvalid = errors.New("a rule is not valid")
)

var levels = []string{"informational", "low", "medium", "high", "critical"}

type Rule struct {
	Name        string
	ID          string
	Title       string
	Description string
	Level       string
	Tags        []string
	// LogSource holds the product, service and category that an event must have. Empty fits every event.
	LogSource map[string]string

	detection   *detection
	correlation *correlation
	tests       []Test
	file        string
}

// Test is one case of a rule: events, and what the rule must give.
type Test struct {
	Name   string
	Events []map[string]any
	// Alerts is the number of alerts that the rule must give for the events.
	Alerts int
}

type document struct {
	Name        string         `yaml:"name"`
	ID          string         `yaml:"id"`
	Title       string         `yaml:"title"`
	Description string         `yaml:"description"`
	Level       string         `yaml:"level"`
	Tags        []string       `yaml:"tags"`
	LogSource   map[string]any `yaml:"logsource"`
	Detection   map[string]any `yaml:"detection"`
	Correlation map[string]any `yaml:"correlation"`
	Tests       []struct {
		Name   string           `yaml:"name"`
		Events []map[string]any `yaml:"events"`
		Expect struct {
			Alerts *int `yaml:"alerts"`
		} `yaml:"expect"`
	} `yaml:"tests"`
}

type Set struct {
	rules  []*Rule
	byName map[string]*Rule
	ordered []*Rule
	quiet map[*Rule]bool
}

func (set Set) Rules() []*Rule { return set.rules }

func Parse(data []byte, file string) ([]*Rule, error) {
	if len(data) > maxFileBytes {
		return nil, ErrTooBig
	}

	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	var parsed []*Rule
	for {
		var doc document
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s is not valid YAML", ErrInvalid, filepath.Base(file))
		}

		rule, err := build(doc, file)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, rule)
	}

	return parsed, nil
}

func build(doc document, file string) (*Rule, error) {
	label := doc.Name
	if label == "" {
		label = doc.ID
	}
	if label == "" {
		label = doc.Title
	}
	fail := func(reason string) (*Rule, error) {
		return nil, fmt.Errorf("%w: rule %q in %s: %s", ErrInvalid, truncate(label, 60), filepath.Base(file), reason)
	}

	if doc.Title == "" {
		return fail("it has no title")
	}
	if (doc.Detection == nil) == (doc.Correlation == nil) {
		return fail("it needs a detection or a correlation, and not both")
	}
	level := strings.ToLower(doc.Level)
	if level == "" {
		level = "medium"
	}
	if !slices.Contains(levels, level) {
		return fail("the level is not known")
	}

	rule := &Rule{Name: doc.Name, ID: doc.ID, Title: doc.Title, Description: doc.Description, Level: level, Tags: doc.Tags, file: file}
	for key, value := range doc.LogSource {
		text, isText := value.(string)
		switch {
		case key == "definition":
		case (key != "product" && key != "service" && key != "category") || !isText || text == "":
			return fail("the logsource can have product, service and category")
		default:
			if rule.LogSource == nil {
				rule.LogSource = map[string]string{}
			}
			rule.LogSource[key] = text
		}
	}

	var err error
	if doc.Detection != nil {
		rule.detection, err = parseDetection(doc.Detection)
	} else {
		rule.correlation, err = parseCorrelation(doc.Correlation)
	}
	if err != nil {
		return fail(err.Error())
	}

	if len(doc.Tests) > maxTests {
		return fail("it has too many tests")
	}
	for _, test := range doc.Tests {
		if test.Expect.Alerts == nil {
			return fail("a test needs expect: alerts")
		}
		if len(test.Events) > maxTestEvents {
			return fail("a test has too many events")
		}
		rule.tests = append(rule.tests, Test{Name: test.Name, Events: test.Events, Alerts: *test.Expect.Alerts})
	}

	return rule, nil
}

func Load(directory string) (Set, error) {
	return LoadFS(os.DirFS(directory))
}

func LoadFS(system fs.FS) (Set, error) {
	all, err := parseFS(system)
	if err != nil {
		return Set{}, err
	}

	return NewSet(all)
}

func parseFS(system fs.FS) ([]*Rule, error) {
	var files []string
	err := fs.WalkDir(system, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}

		return nil
	})
	if err != nil {
		return nil, errors.New("the rules folder cannot be read")
	}
	slices.Sort(files)

	var all []*Rule
	for _, path := range files {
		data, err := readLimited(system, path)
		if err != nil {
			return nil, err
		}
		parsed, err := Parse(data, path)
		if err != nil {
			return nil, err
		}
		if all = append(all, parsed...); len(all) > maxRules {
			return nil, ErrTooBig
		}
	}

	return all, nil
}

func NewSet(parsed []*Rule) (Set, error) {
	set := Set{byName: map[string]*Rule{}, quiet: map[*Rule]bool{}}
	for _, rule := range parsed {
		if err := set.add(rule); err != nil {
			return Set{}, err
		}
	}
	if err := set.link(); err != nil {
		return Set{}, err
	}

	return set, set.runTests()
}

func (set *Set) add(rule *Rule) error {
	for _, key := range rule.keys() {
		if _, taken := set.byName[key]; taken {
			return fmt.Errorf("%w: two rules have the name %q", ErrInvalid, truncate(key, 60))
		}
		set.byName[key] = rule
	}
	set.rules = append(set.rules, rule)

	return nil
}

func (rule *Rule) keys() []string {
	var keys []string
	for _, key := range []string{rule.Name, rule.ID, rule.Title} {
		if key != "" && !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}

	return keys
}

func (set *Set) link() error {
	const (
		visiting = 1
		done     = 2
	)
	state := map[*Rule]int{}
	generated := map[*Rule]bool{}

	var visit func(rule *Rule) error
	visit = func(rule *Rule) error {
		switch state[rule] {
		case done:
			return nil
		case visiting:
			return fmt.Errorf("%w: rule %q refers to itself through other rules", ErrInvalid, truncate(rule.Title, 60))
		}
		state[rule] = visiting
		if rule.correlation != nil {
			referenced := map[*Rule]bool{}
			for _, reference := range rule.correlation.references {
				target, found := set.byName[reference]
				if !found {
					return fmt.Errorf("%w: rule %q refers to a rule that does not exist", ErrInvalid, truncate(rule.Title, 60))
				}
				if referenced[target] {
					return fmt.Errorf("%w: rule %q refers to the same rule through different names", ErrInvalid, truncate(rule.Title, 60))
				}
				referenced[target] = true
				if err := visit(target); err != nil {
					return err
				}
				// A correlation that is counted by another one still gives its own alerts: a burst of failed
				// logins is worth an alert with or without the success that follows it.
				if target.correlation == nil {
					set.quiet[target] = true
				}
				if rule.correlation.generate {
					generated[target] = true
				}
			}
		}
		state[rule] = done
		set.ordered = append(set.ordered, rule)

		return nil
	}

	for _, rule := range set.rules {
		if err := visit(rule); err != nil {
			return err
		}
	}
	for rule := range generated {
		delete(set.quiet, rule)
	}

	return nil
}

func readLimited(system fs.FS, path string) ([]byte, error) {
	file, err := system.Open(path)
	if err != nil {
		return nil, errors.New("a rule file cannot be read")
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, errors.New("a rule file cannot be read")
	}
	if len(data) > maxFileBytes {
		return nil, ErrTooBig
	}

	return data, nil
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}

	return text[:limit] + "..."
}

func parseDuration(text string) (time.Duration, error) {
	unit := time.Duration(1)
	if days, isDays := strings.CutSuffix(text, "d"); isDays {
		text, unit = days+"h", 24
	}
	duration, err := time.ParseDuration(text)
	if err != nil || duration <= 0 || duration > 30*24*time.Hour/unit {
		return 0, errors.New("the timespan is not valid. Write it like 30s, 10m, 2h or 1d")
	}

	return duration * unit, nil
}

func compileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexLength {
		return nil, errors.New("a regular expression is too long")
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, errors.New("a regular expression is not valid")
	}

	return compiled, nil
}

func (rule *Rule) IsCorrelation() bool { return rule.correlation != nil }
