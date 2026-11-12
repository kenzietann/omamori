package store

import (
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrConfig   = errors.New("the storage configuration is not valid")
	ErrDatabase = errors.New("the storage operation failed")
	ErrInvalid  = errors.New("the stored record or query is not valid")
	ErrNotFound = errors.New("the stored record was not found")
	ErrConflict = errors.New("the stored record conflicts with an existing version")
	ErrVersion  = errors.New("the database schema version is not supported")
)

type Config struct {
	Driver string
	DSN    string
}

type RunInput struct {
	ID       string          `json:"id,omitempty"`
	Made     time.Time       `json:"made"`
	Mode     string          `json:"mode"`
	Label    string          `json:"label,omitempty"`
	Events   []Event         `json:"events"`
	Alerts   []Alert         `json:"alerts"`
	Analysis json.RawMessage `json:"analysis,omitempty"`
	Coverage json.RawMessage `json:"coverage,omitempty"`
}

type Run struct {
	ID         string          `json:"id"`
	Digest     string          `json:"digest"`
	Made       time.Time       `json:"made"`
	Mode       string          `json:"mode"`
	Label      string          `json:"label,omitempty"`
	EventCount int             `json:"event_count"`
	AlertCount int             `json:"alert_count"`
	Analysis   json.RawMessage `json:"analysis,omitempty"`
	Coverage   json.RawMessage `json:"coverage,omitempty"`
}

type Event struct {
	ID     string            `json:"id"`
	RunID  string            `json:"run_id,omitempty"`
	Time   time.Time         `json:"time"`
	Source string            `json:"source"`
	Ref    string            `json:"ref"`
	Fields map[string]string `json:"fields"`
}

type Alert struct {
	ID       string            `json:"id"`
	RunID    string            `json:"run_id,omitempty"`
	Rule     string            `json:"rule"`
	Title    string            `json:"title"`
	Level    string            `json:"level"`
	Time     time.Time         `json:"time"`
	First    time.Time         `json:"first"`
	Last     time.Time         `json:"last"`
	Count    int               `json:"count"`
	Group    map[string]string `json:"group,omitempty"`
	EventIDs []string          `json:"event_ids"`
	Payload  json.RawMessage   `json:"payload,omitempty"`
}

// Query has bounded pagination. From and To are inclusive. Field/Value is an exact
// match on sanitized stored values; Text is a literal case-insensitive substring.
type Query struct {
	RunID, CaseID, Text, Source, Level, Rule, Field, Value, Status string
	From, To                                                       time.Time
	Limit, Offset                                                  int
}

type AlertRef struct {
	RunID   string `json:"run_id"`
	AlertID string `json:"alert_id"`
}

type CaseInput struct {
	Title  string `json:"title"`
	Notes  string `json:"notes"`
	Status string `json:"status"`
}

type Case struct {
	ID      string     `json:"id"`
	Title   string     `json:"title"`
	Notes   string     `json:"notes"`
	Status  string     `json:"status"`
	Version int        `json:"version"`
	Created time.Time  `json:"created"`
	Updated time.Time  `json:"updated"`
	Alerts  []AlertRef `json:"alerts"`
}

type TimelineEntry struct {
	Kind  string    `json:"kind"`
	Time  time.Time `json:"time"`
	RunID string    `json:"run_id"`
	ID    string    `json:"id"`
	Event *Event    `json:"event,omitempty"`
	Alert *Alert    `json:"alert,omitempty"`
}
