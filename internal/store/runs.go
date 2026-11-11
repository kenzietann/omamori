package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func (db *DB) SaveRun(ctx context.Context, input RunInput) (Run, error) {
	if err := ctx.Err(); err != nil {
		return Run{}, err
	}
	input, digest, err := normalizeRun(input)
	if err != nil {
		return Run{}, err
	}
	if old, err := db.GetRun(ctx, input.ID); err == nil {
		if old.Digest == digest {
			return old, nil
		}
		return Run{}, ErrConflict
	} else if !errors.Is(err, ErrNotFound) {
		return Run{}, err
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, dbError(ctx, err)
	}
	defer tx.Rollback()
	result := Run{ID: input.ID, Digest: digest, Made: input.Made, Mode: input.Mode, Label: input.Label, EventCount: len(input.Events), AlertCount: len(input.Alerts), Analysis: input.Analysis, Coverage: input.Coverage}
	_, err = tx.ExecContext(ctx, db.bind(`INSERT INTO omamori_runs(id,digest,made_ns,mode,label,search_text,event_count,alert_count,analysis,coverage) VALUES(?,?,?,?,?,?,?,?,?,?)`), result.ID, result.Digest, result.Made.UnixNano(), result.Mode, result.Label, strings.ToLower(result.Label+"\n"+result.Mode), result.EventCount, result.AlertCount, string(result.Analysis), string(result.Coverage))
	if err != nil {
		tx.Rollback()
		if old, readErr := db.GetRun(ctx, input.ID); readErr == nil {
			if old.Digest == digest {
				return old, nil
			}
			return Run{}, ErrConflict
		}
		return Run{}, dbError(ctx, err)
	}
	statements := map[string]*sql.Stmt{}
	defer func() {
		for _, statement := range statements {
			statement.Close()
		}
	}()
	exec := func(query string, args ...any) error {
		statement := statements[query]
		if statement == nil {
			var err error
			statement, err = tx.PrepareContext(ctx, db.bind(query))
			if err != nil {
				return err
			}
			statements[query] = statement
		}
		_, err := statement.ExecContext(ctx, args...)
		return err
	}
	for _, current := range input.Events {
		current.RunID = input.ID
		document, _ := json.Marshal(current)
		if err := exec(`INSERT INTO omamori_events(run_id,event_id,event_time,source,document,search_text) VALUES(?,?,?,?,?,?)`, input.ID, current.ID, current.Time.UnixNano(), current.Source, string(document), strings.ToLower(current.Source+"\n"+current.Ref+"\n"+fieldText(current.Fields))); err != nil {
			return Run{}, dbError(ctx, err)
		}
		for name, value := range current.Fields {
			if err := exec(`INSERT INTO omamori_event_fields(run_id,event_id,field_name,field_value,value_hash) VALUES(?,?,?,?,?)`, input.ID, current.ID, name, value, hash(value)); err != nil {
				return Run{}, dbError(ctx, err)
			}
		}
	}
	for _, current := range input.Alerts {
		current.RunID = input.ID
		document, _ := json.Marshal(current)
		if err := exec(`INSERT INTO omamori_alerts(run_id,alert_id,alert_time,rule_name,level,document,search_text) VALUES(?,?,?,?,?,?,?)`, input.ID, current.ID, current.Time.UnixNano(), current.Rule, current.Level, string(document), strings.ToLower(current.Rule+"\n"+current.Title+"\n"+current.Level+"\n"+fieldText(current.Group))); err != nil {
			return Run{}, dbError(ctx, err)
		}
		for name, value := range current.Group {
			if err := exec(`INSERT INTO omamori_alert_fields(run_id,alert_id,field_name,field_value,value_hash) VALUES(?,?,?,?,?)`, input.ID, current.ID, name, value, hash(value)); err != nil {
				return Run{}, dbError(ctx, err)
			}
		}
		for _, eventID := range current.EventIDs {
			if err := exec(`INSERT INTO omamori_alert_events(run_id,alert_id,event_id) VALUES(?,?,?)`, input.ID, current.ID, eventID); err != nil {
				return Run{}, dbError(ctx, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return Run{}, dbError(ctx, err)
	}
	return result, nil
}

type scanner interface{ Scan(...any) error }

func scanRun(row scanner) (Run, error) {
	var run Run
	var moment int64
	var analysis, coverage string
	err := row.Scan(&run.ID, &run.Digest, &moment, &run.Mode, &run.Label, &run.EventCount, &run.AlertCount, &analysis, &coverage)
	run.Made = time.Unix(0, moment).UTC()
	if analysis != "" {
		run.Analysis = json.RawMessage(analysis)
	}
	if coverage != "" {
		run.Coverage = json.RawMessage(coverage)
	}
	return run, err
}

const runColumns = `r.id,r.digest,r.made_ns,r.mode,r.label,r.event_count,r.alert_count,r.analysis,r.coverage`

func (db *DB) GetRun(ctx context.Context, id string) (Run, error) {
	if !identifier.MatchString(id) {
		return Run{}, ErrInvalid
	}
	run, err := scanRun(db.sql.QueryRowContext(ctx, db.bind(`SELECT `+runColumns+` FROM omamori_runs r WHERE r.id=?`), id))
	if err != nil {
		return Run{}, dbError(ctx, err)
	}
	return run, nil
}

func (db *DB) ListRuns(ctx context.Context, query Query) ([]Run, error) {
	query, err := normalizeQuery(query)
	if err != nil {
		return nil, err
	}
	if query.Status != "" {
		return nil, ErrInvalid
	}
	where, args := []string{"1=1"}, []any{}
	add := func(sql string, value any) { where = append(where, sql); args = append(args, value) }
	if query.RunID != "" {
		add("r.id=?", query.RunID)
	}
	if query.CaseID != "" {
		add(`EXISTS(SELECT 1 FROM omamori_case_alerts c WHERE c.run_id=r.id AND c.case_id=?)`, query.CaseID)
	}
	if !query.From.IsZero() {
		add("r.made_ns>=?", query.From.UnixNano())
	}
	if !query.To.IsZero() {
		add("r.made_ns<=?", query.To.UnixNano())
	}
	if query.Text != "" {
		add(`r.search_text LIKE ? ESCAPE '!'`, like(query.Text))
	}
	if query.Source != "" || query.Field != "" || query.Level != "" || query.Rule != "" {
		filtered := Query{CaseID: query.CaseID, Source: query.Source, Field: query.Field, Value: query.Value, Level: query.Level, Rule: query.Rule}
		kind, table, alias := "event", "omamori_events", "e"
		if query.Level != "" || query.Rule != "" {
			kind, table, alias = "alert", "omamori_alerts", "a"
		}
		condition, values := db.conditions(kind, filtered)
		where = append(where, `EXISTS(SELECT 1 FROM `+table+` `+alias+` WHERE `+alias+`.run_id=r.id AND `+condition+`)`)
		args = append(args, values...)
	}
	args = append(args, query.Limit, query.Offset)
	rows, err := db.sql.QueryContext(ctx, db.bind(`SELECT `+runColumns+` FROM omamori_runs r WHERE `+strings.Join(where, " AND ")+` ORDER BY r.made_ns DESC,r.id ASC LIMIT ? OFFSET ?`), args...)
	if err != nil {
		return nil, dbError(ctx, err)
	}
	defer rows.Close()
	result := []Run{}
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, dbError(ctx, err)
		}
		result = append(result, run)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError(ctx, err)
	}
	return result, nil
}
