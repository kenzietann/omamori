package store

import (
	"context"
	"encoding/json"
)

func (db *DB) GetEvent(ctx context.Context, runID, id string) (Event, error) {
	if !identifier.MatchString(runID) || !identifier.MatchString(id) {
		return Event{}, ErrInvalid
	}
	var text string
	if err := db.sql.QueryRowContext(ctx, db.bind(`SELECT document FROM omamori_events WHERE run_id=? AND event_id=?`), runID, id).Scan(&text); err != nil {
		return Event{}, dbError(ctx, err)
	}
	var value Event
	if json.Unmarshal([]byte(text), &value) != nil {
		return Event{}, ErrDatabase
	}
	return value, nil
}
func (db *DB) GetAlert(ctx context.Context, runID, id string) (Alert, error) {
	if !identifier.MatchString(runID) || !identifier.MatchString(id) {
		return Alert{}, ErrInvalid
	}
	var text string
	if err := db.sql.QueryRowContext(ctx, db.bind(`SELECT document FROM omamori_alerts WHERE run_id=? AND alert_id=?`), runID, id).Scan(&text); err != nil {
		return Alert{}, dbError(ctx, err)
	}
	var value Alert
	if json.Unmarshal([]byte(text), &value) != nil {
		return Alert{}, ErrDatabase
	}
	return value, nil
}
