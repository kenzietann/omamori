// Package filerules reads and matches file rules: rules that look at the content of a file, in the way of
// YARA. A rule names strings (plain text, bytes in hex, or a regular expression) and a condition over them.
// A rule is data. It is read, matched against bytes and counted, and it never runs anything.
//
// Regular expressions are those of Go (RE2): they take a time that grows with the length of the file and
// never more, so a rule cannot make a scan hang. Plain text and hex are searched without them.
//
// Every rule can carry tests (a text or bytes, and whether the rule must match them). A rule whose tests fail
// is not accepted, like the detection rules.
package filerules

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	maxFileBytes    = 256 << 10
	maxRules        = 500
	maxStrings      = 64
	maxTextBytes    = 512
	maxHexBytes     = 256
	maxRegexLength  = 1000
	maxCondition    = 500
	maxTests        = 50
	maxTestBytes    = 64 << 10
	maxPaths        = 32
	maxExcerptBytes = 160
	// MaxScanBytes is the most of one file that a rule looks at. A longer file is looked at up to it.
	MaxScanBytes = 8 << 20
)

var (
	ErrTooBig  = errors.New("a file rule file is too big, or there are too many file rules")
	ErrInvalid = errors.New("a file rule is not valid")
)

var (
	levels   = []string{"informational", "low", "medium", "high", "critical"}
	namePart = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Rule is one file rule.
type Rule struct {
	Name        string
	ID          string
	Title       string
	Description string
	Level       string
	Tags        []string
	// Paths are the folders (relative to the top of the system, like tmp/ or var/www/) that a file must be in.
	// Empty fits every file.
	Paths []string

	strings   []*pattern
	byName    map[string]*pattern
	condition node
	maxSize   int64
	tests     []test
	file      string
}

type test struct {
	name  string
	path  string
	data  []byte
	match bool
}

type pattern struct {
	name   string
	text   []byte
	noCase bool
	hex    []byte
	mask   []bool
	regex  *regexp.Regexp
	at     int
}

type document struct {
	Name        string                    `yaml:"name"`
	ID          string                    `yaml:"id"`
	Title       string                    `yaml:"title"`
	Description string                    `yaml:"description"`
	Level       string                    `yaml:"level"`
	Tags        []string                  `yaml:"tags"`
	Paths       []string                  `yaml:"paths"`
	MaxSize     int64                     `yaml:"max_size"`
	Strings     map[string]stringDocument `yaml:"strings"`
	Condition   string                    `yaml:"condition"`
	Tests       []struct {
		Name  string `yaml:"name"`
		Path  string `yaml:"path"`
		Text  string `yaml:"text"`
		Hex   string `yaml:"hex"`
		Match *bool  `yaml:"match"`
	} `yaml:"tests"`
}

type stringDocument struct {
	Text   string `yaml:"text"`
	Hex    string `yaml:"hex"`
	Regex  string `yaml:"regex"`
	NoCase bool   `yaml:"nocase"`
	At     *int   `yaml:"at"`
}

// Set is a list of file rules whose names are all different and whose tests all pass.
type Set struct {
	rules []*Rule
}

func (set Set) Rules() []*Rule { return set.rules }

// Parse reads the rules of one file. A file can hold several rules, split by ---.
func Parse(data []byte, file string) ([]*Rule, error) {
	if len(data) > maxFileBytes {
		return nil, ErrTooBig
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var parsed []*Rule
	for {
		var doc document
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s is not valid YAML, or it has a key that file rules do not have", ErrInvalid, path.Base(file))
		}
		rule, err := build(doc, file)
		if err != nil {
			return nil, err
		}
		if parsed = append(parsed, rule); len(parsed) > maxRules {
			return nil, ErrTooBig
		}
	}

	return parsed, nil
}

func build(doc document, file string) (*Rule, error) {
	label := doc.Name
	if label == "" {
		label = doc.Title
	}
	fail := func(reason string) (*Rule, error) {
		return nil, fmt.Errorf("%w: rule %q in %s: %s", ErrInvalid, truncate(label, 60), path.Base(file), reason)
	}

	if !namePart.MatchString(doc.Name) {
		return fail("the name must be small letters, digits and _, and start with a letter")
	}
	if strings.TrimSpace(doc.Title) == "" {
		return fail("it has no title")
	}
	level := strings.ToLower(doc.Level)
	if level == "" {
		level = "medium"
	}
	if !slices.Contains(levels, level) {
		return fail("the level is not known")
	}
	if doc.MaxSize < 0 || doc.MaxSize > MaxScanBytes {
		return fail(fmt.Sprintf("max_size must be between 1 and %d", MaxScanBytes))
	}
	rule := &Rule{
		Name: doc.Name, ID: doc.ID, Title: doc.Title, Description: doc.Description, Level: level, Tags: doc.Tags,
		byName: map[string]*pattern{}, maxSize: doc.MaxSize, file: file,
	}

	if len(doc.Paths) > maxPaths {
		return fail("it has too many paths")
	}
	for _, folder := range doc.Paths {
		clean := strings.TrimSuffix(strings.TrimPrefix(folder, "/"), "/")
		if clean == "" || !fs.ValidPath(clean) || strings.ContainsAny(clean, "*?[") {
			return fail("a path must be a folder like tmp/ or var/www/, with no * in it")
		}
		rule.Paths = append(rule.Paths, clean+"/")
	}

	if len(doc.Strings) == 0 {
		return fail("it has no strings")
	}
	if len(doc.Strings) > maxStrings {
		return fail("it has too many strings")
	}
	names := make([]string, 0, len(doc.Strings))
	for name := range doc.Strings {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !namePart.MatchString(name) || reserved[name] {
			return fail(fmt.Sprintf("the string name %q must be small letters, digits and _, and not a word of the condition", truncate(name, 40)))
		}
		compiled, err := compileString(name, doc.Strings[name])
		if err != nil {
			return fail(fmt.Sprintf("string %s: %s", name, err))
		}
		rule.strings = append(rule.strings, compiled)
		rule.byName[name] = compiled
	}

	if strings.TrimSpace(doc.Condition) == "" {
		return fail("it has no condition")
	}
	condition, err := parseCondition(doc.Condition, names)
	if err != nil {
		return fail(err.Error())
	}
	rule.condition = condition

	if len(doc.Tests) == 0 {
		return fail("it needs a test that matches and a test that does not")
	}
	if len(doc.Tests) > maxTests {
		return fail("it has too many tests")
	}
	for index, current := range doc.Tests {
		name := current.Name
		if name == "" {
			name = fmt.Sprintf("number %d", index+1)
		}
		if current.Match == nil {
			return fail(fmt.Sprintf("test %q needs match: true or match: false", truncate(name, 40)))
		}
		if (current.Text == "") == (current.Hex == "") {
			return fail(fmt.Sprintf("test %q needs a text or a hex, and not both", truncate(name, 40)))
		}
		data := []byte(current.Text)
		if current.Hex != "" {
			if data, err = hex.DecodeString(strings.Join(strings.Fields(current.Hex), "")); err != nil {
				return fail(fmt.Sprintf("test %q: the hex is not valid", truncate(name, 40)))
			}
		}
		if len(data) > maxTestBytes {
			return fail(fmt.Sprintf("test %q is too long", truncate(name, 40)))
		}
		where := current.Path
		if where == "" {
			where = "tmp/test"
		}
		if !fs.ValidPath(where) {
			return fail(fmt.Sprintf("test %q: the path is not valid", truncate(name, 40)))
		}
		rule.tests = append(rule.tests, test{name: name, path: where, data: data, match: *current.Match})
	}

	return rule, nil
}

func compileString(name string, doc stringDocument) (*pattern, error) {
	kinds := 0
	for _, given := range []string{doc.Text, doc.Hex, doc.Regex} {
		if given != "" {
			kinds++
		}
	}
	if kinds != 1 {
		return nil, errors.New("it needs one of text, hex or regex")
	}
	compiled := &pattern{name: name, noCase: doc.NoCase, at: -1}
	if doc.At != nil {
		if doc.Regex != "" {
			return nil, errors.New("at works with text and hex, not with regex (write ^ and \\A in the regex)")
		}
		if *doc.At < 0 || *doc.At > MaxScanBytes {
			return nil, errors.New("at is not a usable place in a file")
		}
		compiled.at = *doc.At
	}

	switch {
	case doc.Text != "":
		if len(doc.Text) > maxTextBytes {
			return nil, errors.New("the text is too long")
		}
		compiled.text = []byte(doc.Text)
		if doc.NoCase {
			compiled.text = lowerASCII(compiled.text)
		}
	case doc.Hex != "":
		if doc.NoCase {
			return nil, errors.New("nocase does not fit hex")
		}
		bytesOf, mask, err := parseHex(doc.Hex)
		if err != nil {
			return nil, err
		}
		compiled.hex, compiled.mask = bytesOf, mask
	default:
		if len(doc.Regex) > maxRegexLength {
			return nil, errors.New("the regular expression is too long")
		}
		expression := doc.Regex
		if doc.NoCase {
			expression = "(?i)" + expression
		}
		regex, err := regexp.Compile(expression)
		if err != nil {
			return nil, errors.New("the regular expression is not valid")
		}
		if regex.MatchString("") {
			return nil, errors.New("the regular expression matches an empty text, so it matches every file")
		}
		compiled.regex = regex
	}

	return compiled, nil
}

// parseHex reads bytes like "7f 45 4c 46" or "4d5a ?? 00". ?? fits every byte. Two bytes in a row must be fixed,
// so that a search has something to look for.
func parseHex(text string) ([]byte, []bool, error) {
	joined := strings.Join(strings.Fields(text), "")
	if len(joined)%2 != 0 {
		return nil, nil, errors.New("the hex must have two digits for each byte")
	}
	if len(joined)/2 > maxHexBytes {
		return nil, nil, errors.New("the hex is too long")
	}
	var data []byte
	var mask []bool
	run, longest := 0, 0
	for index := 0; index < len(joined); index += 2 {
		pair := joined[index : index+2]
		if pair == "??" {
			data, mask = append(data, 0), append(mask, false)
			run = 0
			continue
		}
		value, err := hex.DecodeString(pair)
		if err != nil {
			return nil, nil, errors.New("the hex is not valid. Write bytes like 7f 45 4c 46, and ?? for any byte")
		}
		data, mask = append(data, value[0]), append(mask, true)
		run++
		longest = max(longest, run)
	}
	if longest < 2 {
		return nil, nil, errors.New("the hex needs two fixed bytes in a row")
	}

	return data, mask, nil
}

func lowerASCII(data []byte) []byte {
	lowered := make([]byte, len(data))
	for index, character := range data {
		if 'A' <= character && character <= 'Z' {
			character += 'a' - 'A'
		}
		lowered[index] = character
	}

	return lowered
}

// NewSet checks that the names are all different and runs the tests of every rule. One failed test refuses
// the whole set.
func NewSet(parsed []*Rule) (Set, error) {
	seen := map[string]bool{}
	for _, rule := range parsed {
		for _, key := range []string{rule.Name, rule.ID} {
			if key == "" {
				continue
			}
			if seen[key] {
				return Set{}, fmt.Errorf("%w: two file rules have the name or id %q", ErrInvalid, truncate(key, 60))
			}
			seen[key] = true
		}
	}
	for _, rule := range parsed {
		for _, current := range rule.tests {
			got := rule.Match(current.path, current.data) != nil
			if got != current.match {
				want := "match"
				if !current.match {
					want = "not match"
				}

				return Set{}, fmt.Errorf("%w: file rule %q, test %q: the rule must %s and it does not", ErrInvalid, truncate(rule.Name, 60), truncate(current.name, 60), want)
			}
		}
	}

	return Set{rules: parsed}, nil
}

// Load reads every .yml and .yaml file in a folder and its subfolders.
func Load(directory string) (Set, error) {
	return LoadFS(os.DirFS(directory))
}

func LoadFS(system fs.FS) (Set, error) {
	var files []string
	err := fs.WalkDir(system, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type().IsRegular() && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			files = append(files, name)
		}

		return nil
	})
	if err != nil {
		return Set{}, errors.New("the file rules folder cannot be read")
	}
	sort.Strings(files)

	var all []*Rule
	for _, name := range files {
		data, err := readLimited(system, name)
		if err != nil {
			return Set{}, err
		}
		parsed, err := Parse(data, name)
		if err != nil {
			return Set{}, err
		}
		if all = append(all, parsed...); len(all) > maxRules {
			return Set{}, ErrTooBig
		}
	}

	return NewSet(all)
}

func readLimited(system fs.FS, name string) ([]byte, error) {
	file, err := system.Open(name)
	if err != nil {
		return nil, errors.New("a file rule file cannot be read")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, errors.New("a file rule file cannot be read")
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
