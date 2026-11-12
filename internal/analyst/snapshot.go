package analyst

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

const (
	snapshotBudget        = MaxRequestBytes - 12<<10
	maxEvidenceFieldRunes = 200
	maxEvidenceTextRunes  = 1600
)

var evidenceFields = []string{
	event.Service, event.Action, event.Outcome, event.User, event.SourceIP, event.DestIP, event.Host,
	event.Process, event.Command, event.URL, event.Method, event.Status, event.Signature, event.AuthBy, event.Message,
	event.Collector, event.Product, event.Category, event.EventID, event.SourcePort, event.DestPort, event.Protocol,
	"parent_process", "parent_command", "process_id", "process_guid", "logon_type", "user_domain",
	"policy_action", "rule_id", "rule_severity", "dns_query", "dns_type", "dns_rcode", "tls_sni", "http_host",
	"conn_state", "bytes_sent", "bytes_received", "uid", "flow_id",
	"wazuh_rule_id", "wazuh_level", "agent_id", "signature_id", "signature_category", "app_protocol",
	"flow_state", "bytes_to_server", "bytes_to_client", "tls_version", "target_user", "auth_status", "auth_substatus",
	"parent_process_id", "parent_process_guid",
	// Fields of artifacts from the forensic triage. Log events do not have them, so the snapshot of a
	// log-only run, and with it every earlier recording, stays the same byte for byte.
	"asset", "src_asset", "dst_asset",
	TimeSourceField, "unit", "exec_key", "schedule", "key_type", "fingerprint", "key_options", "target", "shell", "pid", "local_address", "local_port",
}

const (
	TimeSourceField = "time_source"
	WeakTimeSource  = "file_modified"
)

var entityFields = []string{event.SourceIP, event.User, event.Host}

// An asset is one machine of the asset list, whether it wrote the event or stands at one end of a
// connection. The three fields give one kind of entity, so that alerts about one machine can be related.
const assetEntity = "asset"

var assetFields = []string{"asset", "src_asset", "dst_asset"}
var severity = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

type snapshotBuilder struct {
	clean      sanitizer.Sanitizer
	entities   []Entity
	identities map[string]string
	sources    map[string]string
}

func (builder *snapshotBuilder) cleaned(text string) string {
	clean, _ := builder.clean.Sanitize(strings.ToValidUTF8(text, "?"))
	clean = strings.Map(func(character rune) rune {
		if character < ' ' || character == 0x7f || character == '\u2028' || character == '\u2029' {
			return ' '
		}
		return character
	}, clean)
	return clean
}

func (builder *snapshotBuilder) text(text string, limit int) string {
	clean := builder.cleaned(text)
	if utf8.RuneCountInString(clean) > limit {
		clean = string([]rune(clean)[:limit]) + "…"
	}
	return clean
}

// evidenceText counts the displayed ellipsis within its budget. Without a cumulative budget,
// many source-specific fields can make even one sampled alert exceed the entire request limit.
func (builder *snapshotBuilder) evidenceText(text string, remaining int) (string, bool) {
	clean := builder.cleaned(text)
	maximum := min(maxEvidenceFieldRunes, remaining)
	if utf8.RuneCountInString(clean) <= maximum {
		return clean, false
	}
	if maximum == 0 {
		return "", true
	}
	return string([]rune(clean)[:maximum-1]) + "…", true
}

func (builder *snapshotBuilder) entity(field, raw string) string {
	if raw == "" {
		return ""
	}
	key := field + "\x00" + raw
	if id, exists := builder.identities[key]; exists {
		return id
	}
	id := fmt.Sprintf("n%d", len(builder.entities)+1)
	builder.identities[key] = id
	builder.entities = append(builder.entities, Entity{ID: id, Field: field, Value: builder.text(raw, 160)})
	return id
}

func addID(ids []string, id string) []string {
	if id != "" && !slices.Contains(ids, id) {
		return append(ids, id)
	}
	return ids
}

// BuildSnapshot takes a bounded, sanitized copy. Its IDs are in the same severity order as the detection
// report. No wall-clock run time, output directory or absolute source path enters this copy.
func BuildSnapshot(outcome detect.Outcome) (Snapshot, error) {
	snapshot := Snapshot{Version: Version, Alerts: []Alert{}, Entities: []Entity{}}
	snapshot.Coverage.TotalAlerts = len(outcome.Result.Alerts)
	snapshot.Coverage.SkippedFiles = len(outcome.Intake.Skipped)
	snapshot.Coverage.RulesCut = len(outcome.Result.Cut)
	for _, file := range outcome.Intake.Files {
		snapshot.Coverage.MalformedLines += file.Malformed
	}
	ordered := append([]*rules.Alert{}, outcome.Result.Alerts...)
	for _, alert := range ordered {
		if alert == nil || alert.Rule == nil || alert.Count < 1 || alert.First.IsZero() || alert.Last.IsZero() || alert.Last.Before(alert.First) {
			return Snapshot{}, ErrSnapshot
		}
		if _, known := severity[alert.Rule.Level]; !known {
			return Snapshot{}, ErrSnapshot
		}
	}
	sort.SliceStable(ordered, func(first, second int) bool {
		return severity[ordered[first].Rule.Level] > severity[ordered[second].Rule.Level]
	})
	if len(ordered) > MaxAlerts {
		ordered = ordered[:MaxAlerts]
	}
	builder := snapshotBuilder{identities: map[string]string{}, sources: map[string]string{}}
	for index, alert := range ordered {
		current := Alert{ID: fmt.Sprintf("a%d", index+1), Rule: builder.text(alert.Rule.Name, 100), Title: builder.text(alert.Rule.Title, 180),
			Level: alert.Rule.Level, Count: alert.Count, First: stamp(alert.First), Last: stamp(alert.Last), Entities: []string{}, Evidence: []Evidence{}}
		for _, field := range entityFields {
			for _, pair := range alert.Group {
				if event.Canonical(pair.Field) == field {
					current.Entities = addID(current.Entities, builder.entity(field, pair.Value))
				}
			}
		}
		// Spread evidence across the retained events: a sequence's final success must not disappear behind
		// a long first step. The engine already retains a bounded share from every sequence part.
		selected := SampleEvidence(alert.Events)
		current.OmittedEvidence = max(alert.Count, len(alert.Events)) - len(selected)
		for number, original := range selected {
			if original.Time.IsZero() {
				return Snapshot{}, ErrSnapshot
			}
			item := Evidence{ID: fmt.Sprintf("%s_e%d", current.ID, number+1), Ref: builder.reference(original.Ref),
				Time: stamp(original.Time), Fields: map[string]string{}, Entities: []string{}}
			remaining := maxEvidenceTextRunes
			for _, field := range evidenceFields {
				if value, found := original.Get(field); found {
					text, shortened := builder.evidenceText(value, remaining)
					if shortened {
						item.TruncatedFields++
					}
					if text != "" || !shortened {
						item.Fields[field] = text
						remaining -= utf8.RuneCountInString(text)
					}
				}
			}
			for _, field := range entityFields {
				if value, found := original.Get(field); found {
					id := builder.entity(field, value)
					item.Entities = addID(item.Entities, id)
					current.Entities = addID(current.Entities, id)
				}
			}
			for _, field := range assetFields {
				if value, found := original.Fields[field]; found {
					id := builder.entity(assetEntity, value)
					item.Entities = addID(item.Entities, id)
					current.Entities = addID(current.Entities, id)
				}
			}
			current.Evidence = append(current.Evidence, item)
		}
		snapshot.Alerts = append(snapshot.Alerts, current)
	}
	snapshot.Entities = builder.entities
	for {
		refreshCoverage(&snapshot)
		data, err := json.Marshal(snapshot)
		if err != nil {
			return Snapshot{}, ErrSnapshot
		}
		if len(data) <= snapshotBudget {
			if _, err := Request(snapshot); err == nil {
				break
			}
		}
		if len(snapshot.Alerts) == 0 {
			return Snapshot{}, ErrSnapshot
		}
		snapshot.Alerts = snapshot.Alerts[:len(snapshot.Alerts)-1]
		pruneEntities(&snapshot)
	}
	if snapshot.Entities == nil {
		snapshot.Entities = []Entity{}
	}
	return snapshot, nil
}

func stamp(moment time.Time) string { return moment.UTC().Format(time.RFC3339Nano) }

func SampleEvidence(events []event.Event) []event.Event {
	if len(events) <= MaxEvidence {
		return events
	}
	selected := make([]event.Event, 0, MaxEvidence)
	for index := 0; index < MaxEvidence; index++ {
		selected = append(selected, events[index*(len(events)-1)/(MaxEvidence-1)])
	}
	return selected
}

func (builder *snapshotBuilder) reference(reference string) string {
	file, line := reference, ""
	if split := strings.LastIndex(reference, ":"); split >= 0 {
		if number, err := strconv.Atoi(reference[split+1:]); err == nil && number > 0 {
			file, line = reference[:split], reference[split:]
		}
	}
	source, found := builder.sources[file]
	if !found {
		source = fmt.Sprintf("s%d", len(builder.sources)+1)
		builder.sources[file] = source
	}
	file = path.Base(strings.ReplaceAll(file, "\\", "/"))
	return source + "/" + builder.text(file, 100) + line
}

func refreshCoverage(snapshot *Snapshot) {
	snapshot.Coverage.IncludedAlerts = len(snapshot.Alerts)
	snapshot.Coverage.OmittedAlerts = snapshot.Coverage.TotalAlerts - len(snapshot.Alerts)
	snapshot.Coverage.OmittedEvidence = 0
	snapshot.Coverage.TruncatedFields = 0
	for _, alert := range snapshot.Alerts {
		snapshot.Coverage.OmittedEvidence += alert.OmittedEvidence
		for _, item := range alert.Evidence {
			snapshot.Coverage.TruncatedFields += item.TruncatedFields
		}
	}
}

func pruneEntities(snapshot *Snapshot) {
	used := map[string]bool{}
	for _, alert := range snapshot.Alerts {
		for _, id := range alert.Entities {
			used[id] = true
		}
	}
	kept := []Entity{}
	for _, entity := range snapshot.Entities {
		if used[entity.ID] {
			kept = append(kept, entity)
		}
	}
	snapshot.Entities = kept
}
