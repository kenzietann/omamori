package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

func (db *DB) conditions(kind string, query Query) (string, []any) {
	alias, moment := "e", "event_time"
	if kind == "alert" {
		alias, moment = "a", "alert_time"
	}
	where, args := []string{"1=1"}, []any{}
	add := func(condition string, values ...any) {
		where = append(where, condition)
		args = append(args, values...)
	}
	if query.RunID != "" {
		add(alias+`.run_id=?`, query.RunID)
	}
	if !query.From.IsZero() {
		add(alias+`.`+moment+`>=?`, query.From.UnixNano())
	}
	if !query.To.IsZero() {
		add(alias+`.`+moment+`<=?`, query.To.UnixNano())
	}
	if query.Text != "" {
		add(alias+`.search_text LIKE ? ESCAPE '!'`, like(query.Text))
	}
	if query.CaseID != "" {
		if kind == "alert" {
			add(`EXISTS(SELECT 1 FROM omamori_case_alerts c WHERE c.run_id=a.run_id AND c.alert_id=a.alert_id AND c.case_id=?)`, query.CaseID)
		} else {
			condition := `EXISTS(SELECT 1 FROM omamori_alert_events l JOIN omamori_case_alerts c ON c.run_id=l.run_id AND c.alert_id=l.alert_id JOIN omamori_alerts a ON a.run_id=l.run_id AND a.alert_id=l.alert_id WHERE l.run_id=e.run_id AND l.event_id=e.event_id AND c.case_id=?`
			values := []any{query.CaseID}
			if query.Level != "" {
				condition += ` AND a.level=?`
				values = append(values, query.Level)
			}
			if query.Rule != "" {
				condition += ` AND a.rule_name=?`
				values = append(values, query.Rule)
			}
			add(condition+`)`, values...)
		}
	}
	if query.Source != "" {
		if kind == "event" {
			add(`e.source=?`, query.Source)
		} else {
			add(`EXISTS(SELECT 1 FROM omamori_alert_events l JOIN omamori_events e ON e.run_id=l.run_id AND e.event_id=l.event_id WHERE l.run_id=a.run_id AND l.alert_id=a.alert_id AND e.source=?)`, query.Source)
		}
	}
	if kind == "alert" {
		if query.Level != "" {
			add(`a.level=?`, query.Level)
		}
		if query.Rule != "" {
			add(`a.rule_name=?`, query.Rule)
		}
	} else if query.CaseID == "" && (query.Level != "" || query.Rule != "") {
		condition := `EXISTS(SELECT 1 FROM omamori_alert_events l JOIN omamori_alerts a ON a.run_id=l.run_id AND a.alert_id=l.alert_id WHERE l.run_id=e.run_id AND l.event_id=e.event_id`
		var values []any
		if query.Level != "" {
			condition += ` AND a.level=?`
			values = append(values, query.Level)
		}
		if query.Rule != "" {
			condition += ` AND a.rule_name=?`
			values = append(values, query.Rule)
		}
		add(condition+`)`, values...)
	}
	if query.Field != "" {
		if kind == "event" {
			add(`EXISTS(SELECT 1 FROM omamori_event_fields f WHERE f.run_id=e.run_id AND f.event_id=e.event_id AND f.field_name=? AND f.value_hash=? AND f.field_value=?)`, query.Field, hash(query.Value), query.Value)
		} else {
			add(`(EXISTS(SELECT 1 FROM omamori_alert_fields f WHERE f.run_id=a.run_id AND f.alert_id=a.alert_id AND f.field_name=? AND f.value_hash=? AND f.field_value=?) OR EXISTS(SELECT 1 FROM omamori_alert_events l JOIN omamori_event_fields f ON f.run_id=l.run_id AND f.event_id=l.event_id WHERE l.run_id=a.run_id AND l.alert_id=a.alert_id AND f.field_name=? AND f.value_hash=? AND f.field_value=?))`, query.Field, hash(query.Value), query.Value, query.Field, hash(query.Value), query.Value)
		}
	}
	return strings.Join(where, " AND "), args
}

func (db *DB) SearchEvents(ctx context.Context, query Query) ([]Event, error) {
	query, err := normalizeQuery(query)
	if err != nil {
		return nil, err
	}
	if query.Status != "" {
		return nil, ErrInvalid
	}
	where, args := db.conditions("event", query)
	args = append(args, query.Limit, query.Offset)
	rows, err := db.sql.QueryContext(ctx, db.bind(`SELECT e.document FROM omamori_events e WHERE `+where+` ORDER BY e.event_time DESC,e.run_id ASC,e.event_id ASC LIMIT ? OFFSET ?`), args...)
	if err != nil {
		return nil, dbError(ctx, err)
	}
	defer rows.Close()
	result := []Event{}
	for rows.Next() {
		var document string
		var event Event
		if err := rows.Scan(&document); err != nil {
			return nil, dbError(ctx, err)
		}
		if json.Unmarshal([]byte(document), &event) != nil {
			return nil, ErrDatabase
		}
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError(ctx, err)
	}
	return result, nil
}

func (db *DB) SearchAlerts(ctx context.Context, query Query) ([]Alert, error) {
	query, err := normalizeQuery(query)
	if err != nil {
		return nil, err
	}
	if query.Status != "" {
		return nil, ErrInvalid
	}
	where, args := db.conditions("alert", query)
	args = append(args, query.Limit, query.Offset)
	rows, err := db.sql.QueryContext(ctx, db.bind(`SELECT a.document FROM omamori_alerts a WHERE `+where+` ORDER BY a.alert_time DESC,a.run_id ASC,a.alert_id ASC LIMIT ? OFFSET ?`), args...)
	if err != nil {
		return nil, dbError(ctx, err)
	}
	defer rows.Close()
	result := []Alert{}
	for rows.Next() {
		var document string
		var alert Alert
		if err := rows.Scan(&document); err != nil {
			return nil, dbError(ctx, err)
		}
		if json.Unmarshal([]byte(document), &alert) != nil {
			return nil, ErrDatabase
		}
		result = append(result, alert)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError(ctx, err)
	}
	return result, nil
}

func (db *DB) Timeline(ctx context.Context, query Query) ([]TimelineEntry, error) {
	query, err := normalizeQuery(query)
	if err != nil {
		return nil, err
	}
	if query.Status != "" {
		return nil, ErrInvalid
	}
	eventWhere, eventArgs := db.conditions("event", query)
	alertWhere, alertArgs := db.conditions("alert", query)
	statement := `SELECT kind,run_id,item_id,moment,document FROM (SELECT 'event' AS kind,e.run_id,e.event_id AS item_id,e.event_time AS moment,e.document FROM omamori_events e WHERE ` + eventWhere +
		` UNION ALL SELECT 'alert' AS kind,a.run_id,a.alert_id AS item_id,a.alert_time AS moment,a.document FROM omamori_alerts a WHERE ` + alertWhere + `) timeline ORDER BY moment ASC,run_id ASC,kind ASC,item_id ASC LIMIT ? OFFSET ?`
	args := append(eventArgs, alertArgs...)
	args = append(args, query.Limit, query.Offset)
	rows, err := db.sql.QueryContext(ctx, db.bind(statement), args...)
	if err != nil {
		return nil, dbError(ctx, err)
	}
	defer rows.Close()
	result := []TimelineEntry{}
	for rows.Next() {
		var item TimelineEntry
		var moment int64
		var document string
		if err := rows.Scan(&item.Kind, &item.RunID, &item.ID, &moment, &document); err != nil {
			return nil, dbError(ctx, err)
		}
		item.Time = time.Unix(0, moment).UTC()
		if item.Kind == "event" {
			item.Event = &Event{}
			err = json.Unmarshal([]byte(document), item.Event)
		} else {
			item.Alert = &Alert{}
			err = json.Unmarshal([]byte(document), item.Alert)
		}
		if err != nil {
			return nil, ErrDatabase
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError(ctx, err)
	}
	return result, nil
}
