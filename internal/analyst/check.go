package analyst

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const maxResponseBytes = 128 << 10

var wireFields = map[string]bool{"claims": true, "kind": true, "alerts": true, "evidence": true,
	"count": true, "first": true, "last": true, "entity": true, "actions": true}

var actionCatalog = []Action{
	{ID: "preserve_evidence", Text: "Keep the original logs and record their source and collection time before making changes."},
	{ID: "review_authentication", Text: "Review the cited authentication events and verify the activity with the account owner."},
	{ID: "verify_change", Text: "Check whether the activity matches an approved change, maintenance task or expected automation."},
	{ID: "review_web_requests", Text: "Review the cited requests alongside application responses and server logs to determine their effect."},
	{ID: "inspect_host", Text: "Collect read-only host context around the cited time, including related processes, accounts and scheduled tasks."},
}

// Actions returns a copy of the defensive suggestions the model may select. They are review steps,
// not findings and never executable commands.
func Actions() []Action { return slices.Clone(actionCatalog) }

type snapshotIndex struct {
	alerts   map[string]Alert
	entities map[string]Entity
	evidence map[string]Evidence
	owner    map[string]string
}

func indexSnapshot(snapshot Snapshot) (snapshotIndex, bool) {
	index := snapshotIndex{alerts: map[string]Alert{}, entities: map[string]Entity{}, evidence: map[string]Evidence{}, owner: map[string]string{}}
	if snapshot.Version != Version || len(snapshot.Alerts) > MaxAlerts || snapshot.Coverage.IncludedAlerts != len(snapshot.Alerts) ||
		snapshot.Coverage.TotalAlerts < len(snapshot.Alerts) || snapshot.Coverage.OmittedAlerts != snapshot.Coverage.TotalAlerts-len(snapshot.Alerts) {
		return index, false
	}
	for _, entity := range snapshot.Entities {
		if entity.ID == "" || !slices.Contains(entityFields, entity.Field) {
			return index, false
		}
		if _, exists := index.entities[entity.ID]; exists {
			return index, false
		}
		index.entities[entity.ID] = entity
	}
	for _, alert := range snapshot.Alerts {
		if alert.ID == "" || alert.Count < 1 || len(alert.Evidence) > MaxEvidence {
			return index, false
		}
		if _, exists := index.alerts[alert.ID]; exists {
			return index, false
		}
		first, firstErr := time.Parse(time.RFC3339Nano, alert.First)
		last, lastErr := time.Parse(time.RFC3339Nano, alert.Last)
		if firstErr != nil || lastErr != nil || last.Before(first) {
			return index, false
		}
		for _, id := range alert.Entities {
			if _, found := index.entities[id]; !found {
				return index, false
			}
		}
		index.alerts[alert.ID] = alert
		for _, evidence := range alert.Evidence {
			if evidence.ID == "" {
				return index, false
			}
			if _, exists := index.evidence[evidence.ID]; exists {
				return index, false
			}
			if _, err := time.Parse(time.RFC3339Nano, evidence.Time); err != nil {
				return index, false
			}
			for _, id := range evidence.Entities {
				if !slices.Contains(alert.Entities, id) {
					return index, false
				}
			}
			index.evidence[evidence.ID], index.owner[evidence.ID] = evidence, alert.ID
		}
	}
	return index, true
}

// Check accepts only structured facts supported by the snapshot. It never displays text outside that
// schema, and every successful Finding is rebuilt from the local evidence rather than copied from AI.
func Check(snapshot Snapshot, text string) Result {
	result := NotRun(snapshot)
	index, valid := indexSnapshot(snapshot)
	response, err := parseResponse(text)
	if !valid || err != nil {
		result.Status = StatusInvalid
		result.Rejected = append(result.Rejected, Rejection{Reason: "the AI response was not a valid structured review"})
		return result
	}
	seen := map[string]bool{}
	covered := map[string]bool{}
	for number, claim := range response.Claims {
		finding, reason := index.check(claim)
		if reason == "" {
			ids := slices.Clone(claim.Alerts)
			sort.Strings(ids)
			key := claim.Kind + ":" + strings.Join(ids, ",") + ":" + claim.Entity
			if seen[key] {
				reason = "the same claim was supplied more than once"
			}
			seen[key] = true
		}
		if reason != "" {
			result.Rejected = append(result.Rejected, Rejection{Claim: number + 1, Reason: reason})
			continue
		}
		result.Verified = append(result.Verified, finding)
		for _, id := range finding.Alerts {
			covered[id] = true
		}
	}
	result.Unreviewed = []string{}
	for _, alert := range snapshot.Alerts {
		if !covered[alert.ID] {
			result.Unreviewed = append(result.Unreviewed, alert.ID)
		}
	}
	result.Status = StatusComplete
	if len(result.Rejected) > 0 || len(result.Unreviewed) > 0 || result.Coverage.OmittedAlerts > 0 || result.Coverage.RulesCut > 0 {
		result.Status = StatusPartial
	}
	return result
}

func parseResponse(text string) (Response, error) {
	if len(text) == 0 || len(text) > maxResponseBytes || !utf8.ValidString(text) {
		return Response{}, errors.New("invalid response")
	}
	data := []byte(text)
	if err := uniqueKeys(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return Response{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil || response.Claims == nil || len(response.Claims) > MaxClaims {
		return Response{}, errors.New("invalid claims")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Response{}, errors.New("trailing content")
	}
	return response, nil
}

// encoding/json otherwise silently accepts duplicate object keys. An ambiguous schema is not a claim.
func uniqueKeys(decoder *json.Decoder, depth int) error {
	if depth > 12 {
		return errors.New("too deeply nested")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			// Struct decoding is case-insensitive; the wire schema is deliberately exact.
			if !ok || !wireFields[key] || seen[key] {
				return errors.New("duplicate key")
			}
			seen[key] = true
			if err := uniqueKeys(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueKeys(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected delimiter")
	}
	_, err = decoder.Token()
	return err
}

// AlertSummary, RelatedSummary and WeakTimeNote are the only texts of a finding. The checker and the store
// both use them, so a stored finding reads the same as a checked one and holds no text from the model.
func AlertSummary(id, title string, count int) string {
	return fmt.Sprintf("%s: the rule %q matched %d events or hits. A rule match alone does not prove compromise.", id, title, count)
}

func RelatedSummary(alerts int, entity Entity) string {
	return fmt.Sprintf("%d alerts share %s=%s within 24 hours. A shared entity is a review lead, not proof of one attacker or a causal chain.", alerts, entity.Field, entity.Value)
}

// HasWeakTimes says that an item has only the time of the last change of its file.
func HasWeakTimes(evidence []Evidence) bool {
	for _, item := range evidence {
		if item.Fields[TimeSourceField] == WeakTimeSource {
			return true
		}
	}

	return false
}

func WeakTimeNote(weak bool) string {
	if !weak {
		return ""
	}

	return " Some cited items have only the time of the last change of their file, so these times do not say when or in which order things happened."
}

func (index snapshotIndex) check(claim Claim) (Finding, string) {
	finding := Finding{Kind: claim.Kind, Alerts: []string{}, Evidence: []Evidence{}, Actions: []Action{}}
	if claim.Kind != "alert" && claim.Kind != "related" {
		return finding, "the claim kind is not supported"
	}
	if claim.Kind == "alert" && (len(claim.Alerts) != 1 || claim.Entity != "" || claim.Count == nil) ||
		claim.Kind == "related" && (len(claim.Alerts) < 2 || len(claim.Alerts) > MaxRelated || claim.Entity == "" || claim.Count != nil) {
		return finding, "the claim does not have the required alert facts"
	}
	seenAlerts := map[string]bool{}
	var first, last time.Time
	for _, id := range claim.Alerts {
		alert, found := index.alerts[id]
		if !found || seenAlerts[id] {
			return finding, "an alert identifier is unknown or repeated"
		}
		seenAlerts[id] = true
		finding.Alerts = append(finding.Alerts, id)
		start, _ := time.Parse(time.RFC3339Nano, alert.First)
		end, _ := time.Parse(time.RFC3339Nano, alert.Last)
		if first.IsZero() || start.Before(first) {
			first = start
		}
		if last.IsZero() || end.After(last) {
			last = end
		}
	}
	finding.First, finding.Last = stamp(first), stamp(last)
	if claim.First != "" && claim.First != finding.First || claim.Last != "" && claim.Last != finding.Last {
		return finding, "the claimed time range differs from the alerts"
	}
	if len(claim.Evidence) == 0 || len(claim.Evidence) > MaxEvidence*MaxRelated {
		return finding, "the claim needs bounded evidence citations"
	}
	seenEvidence, citedAlerts := map[string]bool{}, map[string]bool{}
	for _, id := range claim.Evidence {
		evidence, found := index.evidence[id]
		owner := index.owner[id]
		if !found || seenEvidence[id] || !seenAlerts[owner] {
			return finding, "an evidence citation is unknown, repeated or belongs to another alert"
		}
		seenEvidence[id], citedAlerts[owner] = true, true
		if claim.Kind == "related" && !slices.Contains(evidence.Entities, claim.Entity) {
			return finding, "the cited evidence does not support the shared entity"
		}
		finding.Evidence = append(finding.Evidence, evidence)
	}
	for _, id := range claim.Alerts {
		if !citedAlerts[id] {
			return finding, "the claim does not cite evidence for every alert"
		}
	}
	if claim.Kind == "alert" {
		alert := index.alerts[claim.Alerts[0]]
		if *claim.Count != alert.Count {
			return finding, "the claimed count differs from the detected alert"
		}
		finding.Count = alert.Count
		finding.Summary = AlertSummary(alert.ID, alert.Title, alert.Count)
	} else {
		entity, found := index.entities[claim.Entity]
		if !found {
			return finding, "the shared entity is unknown"
		}
		for _, id := range claim.Alerts {
			if !slices.Contains(index.alerts[id].Entities, entity.ID) {
				return finding, "the entity is not shared by every alert"
			}
		}
		if last.Sub(first) > 24*time.Hour {
			return finding, "the related alerts span more than 24 hours"
		}
		finding.Entity = &entity
		finding.Summary = RelatedSummary(len(claim.Alerts), entity)
	}
	// The model cannot leave this out and cannot add it: it is read from the cited evidence.
	finding.WeakTimes = HasWeakTimes(finding.Evidence)
	finding.Summary += WeakTimeNote(finding.WeakTimes)
	if len(claim.Actions) > len(actionCatalog) {
		return finding, "a suggested action is unknown or repeated"
	}
	seenActions := map[string]bool{}
	for _, id := range claim.Actions {
		found := false
		for _, action := range actionCatalog {
			if id == action.ID {
				if seenActions[id] {
					return finding, "a suggested action is unknown or repeated"
				}
				seenActions[id], found = true, true
				finding.Actions = append(finding.Actions, action)
			}
		}
		if !found {
			return finding, "a suggested action is unknown or repeated"
		}
	}
	return finding, ""
}
