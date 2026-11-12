package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kenzietann/omamori/internal/event"
)

const (
	maxSelections = 100
	maxValues     = 2000
	maxValueBytes = 2000
)

type detection struct {
	selections map[string]selection
	condition  node
}

type selection struct {
	alternatives []alternative
}

type alternative struct {
	fields   []fieldMatch
	keywords []func(string) bool
}

type fieldMatch struct {
	field string
	// all says that every matcher must fit. Without it one is enough.
	all      bool
	matchers []func(value string, present bool) bool
}

func (found detection) match(candidate event.Event) bool {
	return found.condition.eval(func(name string) bool { return found.selections[name].match(candidate) })
}

func (chosen selection) match(candidate event.Event) bool {
	for _, option := range chosen.alternatives {
		if option.match(candidate) {
			return true
		}
	}

	return false
}

func (option alternative) match(candidate event.Event) bool {
	for _, field := range option.fields {
		value, present := candidate.Get(field.field)
		if !field.match(value, present) {
			return false
		}
	}
	if len(option.keywords) == 0 {
		return true
	}
	for _, value := range candidate.Fields {
		for _, keyword := range option.keywords {
			if keyword(value) {
				return true
			}
		}
	}

	return false
}

func (field fieldMatch) match(value string, present bool) bool {
	for _, matcher := range field.matchers {
		if matcher(value, present) != field.all {
			return !field.all
		}
	}

	return field.all
}

func parseDetection(raw map[string]any) (*detection, error) {
	if len(raw) > maxSelections {
		return nil, errors.New("it has too many selections")
	}
	if _, old := raw["timeframe"]; old {
		return nil, errors.New("\"timeframe\" is the old way to count. Write a correlation rule")
	}

	conditionText, err := conditionOf(raw["condition"])
	if err != nil {
		return nil, err
	}

	selections := map[string]selection{}
	for name, body := range raw {
		if name == "condition" {
			continue
		}
		parsed, err := parseSelection(body)
		if err != nil {
			return nil, fmt.Errorf("selection %q: %w", truncate(name, 40), err)
		}
		selections[name] = parsed
	}
	if len(selections) == 0 {
		return nil, errors.New("it has no selection")
	}

	condition, err := parseCondition(conditionText, selections)
	if err != nil {
		return nil, err
	}

	return &detection{selections: selections, condition: condition}, nil
}

func conditionOf(raw any) (string, error) {
	switch typed := raw.(type) {
	case string:
		if strings.Contains(typed, "|") {
			return "", errors.New("a condition with \"|\" is the old way to count. Write a correlation rule")
		}

		return typed, nil
	case []any:
		var parts []string
		for _, item := range typed {
			text, err := conditionOf(item)
			if err != nil {
				return "", err
			}
			if _, nested := item.([]any); nested || text == "" {
				return "", errors.New("the condition is not valid")
			}
			parts = append(parts, "("+text+")")
		}
		if len(parts) == 0 {
			return "", errors.New("the condition is empty")
		}

		return strings.Join(parts, " or "), nil
	}

	return "", errors.New("it has no condition")
}

func parseSelection(raw any) (selection, error) {
	switch typed := raw.(type) {
	case map[string]any:
		option, err := parseFields(typed)

		return selection{alternatives: []alternative{option}}, err
	case []any:
		if len(typed) == 0 || len(typed) > maxValues {
			return selection{}, errors.New("its list is empty or too long")
		}
		var parsed selection
		var keywords alternative
		for _, item := range typed {
			if fields, isMap := item.(map[string]any); isMap {
				option, err := parseFields(fields)
				if err != nil {
					return selection{}, err
				}
				parsed.alternatives = append(parsed.alternatives, option)
				continue
			}
			text, err := scalarText(item)
			if err != nil || text == "" {
				return selection{}, errors.New("a keyword is not a text")
			}
			matcher, err := textMatcher(text, "contains", false)
			if err != nil {
				return selection{}, err
			}
			keywords.keywords = append(keywords.keywords, matcher)
		}
		if len(keywords.keywords) > 0 {
			parsed.alternatives = append(parsed.alternatives, keywords)
		}

		return parsed, nil
	}

	return selection{}, errors.New("it must be a map or a list")
}

func parseFields(raw map[string]any) (alternative, error) {
	if len(raw) == 0 {
		return alternative{}, errors.New("it is empty")
	}

	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)

	var option alternative
	for _, name := range names {
		field, err := parseField(name, raw[name])
		if err != nil {
			return alternative{}, fmt.Errorf("field %q: %w", truncate(name, 60), err)
		}
		option.fields = append(option.fields, field)
	}

	return option, nil
}

type modifiers struct {
	shape           string
	all, cased      bool
	regexIgnoreCase bool
}

func parseModifiers(parts []string) (modifiers, error) {
	var parsed modifiers
	for _, part := range parts {
		switch part {
		case "contains", "startswith", "endswith", "re", "cidr", "exists", "gt", "gte", "lt", "lte":
			if parsed.shape != "" {
				return modifiers{}, errors.New("two modifiers that cannot be used together")
			}
			parsed.shape = part
		case "all":
			parsed.all = true
		case "cased":
			parsed.cased = true
		case "i":
			parsed.regexIgnoreCase = true
		default:
			return modifiers{}, fmt.Errorf("the modifier %q is not supported", truncate(part, 20))
		}
	}
	if parsed.regexIgnoreCase && parsed.shape != "re" {
		return modifiers{}, errors.New("the modifier \"i\" is only for \"re\"")
	}

	return parsed, nil
}

func parseField(key string, raw any) (fieldMatch, error) {
	parts := strings.Split(key, "|")
	if parts[0] == "" {
		return fieldMatch{}, errors.New("it has no name")
	}
	mods, err := parseModifiers(parts[1:])
	if err != nil {
		return fieldMatch{}, err
	}

	values, isList := raw.([]any)
	if !isList {
		values = []any{raw}
	}
	if len(values) == 0 || len(values) > maxValues {
		return fieldMatch{}, errors.New("its list of values is empty or too long")
	}

	field := fieldMatch{field: parts[0], all: mods.all}
	for _, value := range values {
		matcher, err := valueMatcher(value, mods)
		if err != nil {
			return fieldMatch{}, err
		}
		field.matchers = append(field.matchers, matcher)
	}

	return field, nil
}

func valueMatcher(raw any, mods modifiers) (func(string, bool) bool, error) {
	if mods.shape == "exists" {
		wanted, isBool := raw.(bool)
		if !isBool {
			return nil, errors.New("\"exists\" needs true or false")
		}

		return func(_ string, present bool) bool { return present == wanted }, nil
	}
	if raw == nil {
		if mods.shape != "" {
			return nil, errors.New("an empty value cannot have a modifier")
		}

		return func(value string, present bool) bool { return !present || value == "" }, nil
	}

	text, err := scalarText(raw)
	if err != nil {
		return nil, err
	}
	if len(text) > maxValueBytes {
		return nil, errors.New("a value is too long")
	}

	var matcher func(string) bool
	switch mods.shape {
	case "re":
		pattern := text
		if mods.regexIgnoreCase {
			pattern = "(?i)" + pattern
		}
		compiled, err := compileRegex(pattern)
		if err != nil {
			return nil, err
		}
		matcher = compiled.MatchString
	case "cidr":
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, errors.New("a network like 10.0.0.0/8 is expected")
		}
		matcher = func(value string) bool {
			address, err := netip.ParseAddr(value)

			return err == nil && prefix.Contains(address.Unmap())
		}
	case "gt", "gte", "lt", "lte":
		limit, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, errors.New("a number is expected")
		}
		shape := mods.shape
		matcher = func(value string) bool {
			number, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return false
			}
			switch shape {
			case "gt":
				return number > limit
			case "gte":
				return number >= limit
			case "lt":
				return number < limit
			}

			return number <= limit
		}
	default:
		matcher, err = textMatcher(text, mods.shape, mods.cased)
		if err != nil {
			return nil, err
		}
	}

	return func(value string, present bool) bool { return present && matcher(value) }, nil
}

func scalarText(raw any) (string, error) {
	switch typed := raw.(type) {
	case string:
		return typed, nil
	case int:
		return strconv.Itoa(typed), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case uint64:
		return strconv.FormatUint(typed, 10), nil
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(typed), nil
	}

	return "", errors.New("a value must be a text, a number, true or false")
}

// textMatcher compares text as Sigma does: without regard to case, with * for any text and ? for one
// character. A backslash before * or ? takes away its meaning. shape is "", contains, startswith or endswith.
func textMatcher(pattern, shape string, cased bool) (func(string) bool, error) {
	var expression strings.Builder
	wildcards := false
	var literal strings.Builder

	runes := []rune(pattern)
	for index := 0; index < len(runes); index++ {
		character := runes[index]
		switch {
		case character == '\\' && index+1 < len(runes) && (runes[index+1] == '*' || runes[index+1] == '?' || runes[index+1] == '\\'):
			index++
			expression.WriteString(regexp.QuoteMeta(string(runes[index])))
			literal.WriteRune(runes[index])
		case character == '*':
			wildcards = true
			expression.WriteString(".*")
		case character == '?':
			wildcards = true
			expression.WriteString(".")
		default:
			expression.WriteString(regexp.QuoteMeta(string(character)))
			literal.WriteRune(character)
		}
	}

	if !wildcards {
		wanted := literal.String()
		if !cased {
			wanted = strings.ToLower(wanted)
		}
		compare := map[string]func(string, string) bool{
			"": func(value, wanted string) bool { return value == wanted }, "contains": strings.Contains,
			"startswith": strings.HasPrefix, "endswith": strings.HasSuffix,
		}[shape]

		return func(value string) bool {
			if !cased {
				value = strings.ToLower(value)
			}

			return compare(value, wanted)
		}, nil
	}

	prefix, suffix := "^", "$"
	if shape == "contains" || shape == "endswith" {
		prefix = ""
	}
	if shape == "contains" || shape == "startswith" {
		suffix = ""
	}
	flags := "(?s)"
	if !cased {
		flags = "(?is)"
	}
	compiled, err := compileRegex(flags + prefix + "(?:" + expression.String() + ")" + suffix)
	if err != nil {
		return nil, err
	}

	return compiled.MatchString, nil
}
