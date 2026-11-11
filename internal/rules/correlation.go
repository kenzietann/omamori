package rules

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Kinds of correlation, with the names of the Sigma correlation format.
const (
	eventCount      = "event_count"
	valueCount      = "value_count"
	temporal        = "temporal"
	temporalOrdered = "temporal_ordered"

	maxReferences = 20
	maxGroupBy    = 10
	maxThreshold  = 1_000_000
)

// correlation counts the hits of other rules.
//
//   - event_count: at least threshold hits in the timespan.
//   - value_count: at least threshold different values of a field in the timespan.
//   - temporal: every rule of the list has a hit, each not later than the timespan after the others.
//   - temporal_ordered: the same, in the order of the list.
//
// For the two temporal kinds the timespan is the longest wait between the end of one step and the next step.
// A burst of failed logins that lasts an hour, and a success one minute after it, fit a timespan of ten minutes.
type correlation struct {
	kind       string
	references []string
	groupBy    []string
	timespan   time.Duration
	threshold  int
	field      string
	// generate says that the rules of the list also give their own alerts.
	generate bool
}

func parseCorrelation(raw map[string]any) (*correlation, error) {
	parsed := &correlation{}
	for key := range raw {
		if !slices.Contains([]string{"type", "rules", "group-by", "timespan", "condition", "generate"}, key) {
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
