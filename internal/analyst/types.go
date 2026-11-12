package analyst

import "errors"

const (
	Version         = 1
	MaxAlerts       = 100
	MaxEvidence     = 8
	MaxClaims       = 200
	MaxRelated      = 8
	MaxRequestBytes = 256 << 10
)

var ErrSnapshot = errors.New("the alert evidence cannot be prepared for analysis")

type Coverage struct {
	TotalAlerts    int `json:"total_alerts"`
	IncludedAlerts int `json:"included_alerts"`
	OmittedAlerts  int `json:"omitted_alerts"`
	OmittedEvidence int `json:"omitted_evidence"`
	TruncatedFields int `json:"truncated_fields"`
	MalformedLines  int `json:"malformed_lines"`
	SkippedFiles    int `json:"skipped_files"`
	RulesCut        int `json:"rules_cut"`
}

// Entity IDs preserve exact underlying equality even when two labels are redacted differently.
type Entity struct {
	ID    string `json:"id"`
	Field string `json:"field"`
	Value string `json:"value"`
}

type Evidence struct {
	ID              string            `json:"id"`
	Ref             string            `json:"ref"`
	Time            string            `json:"time"`
	Fields          map[string]string `json:"fields"`
	Entities        []string          `json:"entities"`
	TruncatedFields int               `json:"truncated_fields"`
}

type Alert struct {
	ID              string     `json:"id"`
	Rule            string     `json:"rule"`
	Title           string     `json:"title"`
	Level           string     `json:"level"`
	Count           int        `json:"count"`
	First           string     `json:"first"`
	Last            string     `json:"last"`
	Entities        []string   `json:"entities"`
	Evidence        []Evidence `json:"evidence"`
	OmittedEvidence int        `json:"omitted_evidence"`
}

type Snapshot struct {
	Version  int      `json:"version"`
	Coverage Coverage `json:"coverage"`
	Alerts   []Alert  `json:"alerts"`
	Entities []Entity `json:"entities"`
}

// Claim is the complete model-facing schema. The model supplies identifiers and checkable facts only.
// An alert claim needs one alert and its exact count. A related claim needs 2..8 alerts and one shared
// entity; count must be absent. Both need evidence for each alert. First/Last, if present, must match.
type Claim struct {
	Kind     string   `json:"kind"`
	Alerts   []string `json:"alerts"`
	Evidence []string `json:"evidence"`
	Count    *int     `json:"count,omitempty"`
	First    string   `json:"first,omitempty"`
	Last     string   `json:"last,omitempty"`
	Entity   string   `json:"entity,omitempty"`
	Actions  []string `json:"actions,omitempty"`
}

type Response struct {
	Claims []Claim `json:"claims"`
}

// Finding is reconstructed from the supplied evidence. Summary is written by code, never copied from AI prose.
type Finding struct {
	Kind     string     `json:"kind"`
	Alerts   []string   `json:"alerts"`
	Evidence []Evidence `json:"evidence"`
	Summary  string     `json:"summary"`
	Count    int        `json:"count,omitempty"`
	First    string     `json:"first"`
	Last     string     `json:"last"`
	Entity   *Entity    `json:"entity,omitempty"`
	Actions  []Action   `json:"suggested_actions"`
	WeakTimes bool `json:"weak_times,omitempty"`
}

type Action struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type Rejection struct {
	Claim  int    `json:"claim"`
	Reason string `json:"reason"`
}

const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
	StatusInvalid  = "invalid"
	StatusNotRun   = "not_run"
)

type Result struct {
	Version    int         `json:"version"`
	Status     string      `json:"status"`
	Coverage   Coverage    `json:"coverage"`
	Verified   []Finding   `json:"verified"`
	Rejected   []Rejection `json:"rejected"`
	Unreviewed []string    `json:"unreviewed_alerts"`
}

func NotRun(snapshot Snapshot) Result {
	result := Result{Version: Version, Status: StatusNotRun, Coverage: snapshot.Coverage,
		Verified: []Finding{}, Rejected: []Rejection{}, Unreviewed: []string{}}
	for _, alert := range snapshot.Alerts {
		result.Unreviewed = append(result.Unreviewed, alert.ID)
	}
	return result
}
