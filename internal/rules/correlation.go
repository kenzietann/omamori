package rules

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	eventCount      = "event_count"
	valueCount      = "value_count"
	temporal        = "temporal"
	temporalOrdered = "temporal_ordered"

	maxReferences = 20
	maxGroupBy    = 10
	maxThreshold  = 1_000_000
)

type correlation struct {
	kind       string
	references []string
	groupBy    []string
	timespan   time.Duration
	threshold  int
	field      string
	generate   bool
	// aliases gives a group-by name a different field for each rule of the list, as in Sigma:
	// aliases[name][index of the rule] is the field.
	aliases map[string][]string
}

func parseCorrelation(raw map[string]any) (*correlation, error) {
	parsed := &correlation{}
	for key := range raw {
		if !slices.Contains([]string{"type", "rules", "group-by", "timespan", "condition", "generate", "aliases"}, key) {
			return nil, fmt.Errorf("the correlation key %q is not supported", truncate(key, 30))
		}
	}

	kind, _ := raw["type"].(string)
	if !slices.Contains([]string{eventCount, valueCount, temporal, temporalOrdered}, kind) {
		return nil, errors.New("the correlation type must be event_count, value_count, temporal or temporal_ordered")
	}
	parsed.kind = kind

	var err error
	if parsed.references, err = textList(raw["rules"], maxReferences); err != nil || len(parsed.references) == 0 {
		return nil, errors.New("\"rules\" must be a list of rule names")
	}
	if hasDuplicate(parsed.references) {
		return nil, errors.New("\"rules\" names a rule twice")
	}
	if raw["group-by"] != nil {
		if parsed.groupBy, err = textList(raw["group-by"], maxGroupBy); err != nil {
			return nil, errors.New("\"group-by\" must be a list of field names")
		}
	}

	if raw["aliases"] != nil {
		if parsed.aliases, err = parseAliases(raw["aliases"], parsed.references, parsed.groupBy); err != nil {
			return nil, err
		}
	}

	timespan, _ := raw["timespan"].(string)
	if parsed.timespan, err = parseDuration(timespan); err != nil {
		return nil, err
	}

	if raw["generate"] != nil {
		generate, isBool := raw["generate"].(bool)
		if !isBool {
			return nil, errors.New("\"generate\" must be true or false")
		}
		parsed.generate = generate
	}

	condition, hasCondition := raw["condition"].(map[string]any)
	if raw["condition"] != nil && !hasCondition {
		return nil, errors.New("the condition of a correlation must be a map, for example gte: 10")
	}

	if kind == temporal || kind == temporalOrdered {
		if hasCondition {
			return nil, errors.New("a temporal correlation takes no condition: every rule of the list must have a hit")
		}
		if len(parsed.references) < 2 {
			return nil, errors.New("a temporal correlation needs two rules or more")
		}

		return parsed, nil
	}

	if !hasCondition {
		return nil, errors.New("it needs a condition, for example gte: 10")
	}
	for key, value := range condition {
		switch key {
		case "gte", "gt":
			number, isInt := value.(int)
			if !isInt || parsed.threshold != 0 {
				return nil, errors.New("the condition needs one whole number")
			}
			if key == "gt" {
				number++
			}
			if number < 1 || number > maxThreshold {
				return nil, errors.New("the number of the condition is too small or too big")
			}
			parsed.threshold = number
		case "field":
			field, isText := value.(string)
			if !isText || field == "" {
				return nil, errors.New("\"field\" must be a field name")
			}
			parsed.field = field
		case "lt", "lte", "eq":
			return nil, fmt.Errorf("the condition %q is not supported. Only gte and gt are", key)
		default:
			return nil, fmt.Errorf("the condition key %q is not known", truncate(key, 20))
		}
	}
	if parsed.threshold == 0 {
		return nil, errors.New("it needs a condition, for example gte: 10")
	}
	if (kind == valueCount) != (parsed.field != "") {
		return nil, errors.New("value_count needs \"field\" in its condition, and event_count must not have it")
	}

	return parsed, nil
}

func textList(raw any, limit int) ([]string, error) {
	if single, isText := raw.(string); isText {
		raw = []any{single}
	}
	items, isList := raw.([]any)
	if !isList || len(items) > limit {
		return nil, errors.New("not a list")
	}

	var list []string
	for _, item := range items {
		text, isText := item.(string)
		if !isText || strings.TrimSpace(text) == "" {
			return nil, errors.New("not a text")
		}
		list = append(list, text)
	}

	return list, nil
}

func hasDuplicate(list []string) bool {
	seen := map[string]bool{}
	for _, item := range list {
		if seen[item] {
			return true
		}
		seen[item] = true
	}

	return false
}

// parseAliases reads "aliases": for a name of group-by, the field that each rule of the list uses for it.
// Every rule of the list must have a field, so that no hit falls out of the grouping without a word.
func parseAliases(raw any, references, groupBy []string) (map[string][]string, error) {
	names, isMap := raw.(map[string]any)
	if !isMap || len(names) == 0 || len(names) > maxGroupBy {
		return nil, errors.New("\"aliases\" must be a map from a group-by name to the field of each rule")
	}
	aliases := map[string][]string{}
	for name, value := range names {
		if !slices.Contains(groupBy, name) {
			return nil, fmt.Errorf("the alias %q is not in group-by", truncate(name, 30))
		}
		fields, isMap := value.(map[string]any)
		if !isMap || len(fields) != len(references) {
			return nil, fmt.Errorf("the alias %q needs one field for every rule of the list", truncate(name, 30))
		}
		list := make([]string, len(references))
		for index, reference := range references {
			field, isText := fields[reference].(string)
			if !isText || strings.TrimSpace(field) == "" {
				return nil, fmt.Errorf("the alias %q has no field for the rule %q", truncate(name, 30), truncate(reference, 40))
			}
			list[index] = field
		}
		aliases[name] = list
	}

	return aliases, nil
}
