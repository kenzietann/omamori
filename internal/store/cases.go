package store

import (
	"context"
	"strings"
	"time"
)

func (db *DB) CreateCase(ctx context.Context, input CaseInput) (Case, error) {
	input, err := normalizeCase(input)
	if err != nil {
		return Case{}, err
	}
	id, err := randomID("c_")
	if err != nil {
		return Case{}, err
	}
	now := time.Now().UTC()
	_, err = db.sql.ExecContext(ctx, db.bind(`INSERT INTO omamori_cases(id,title,notes,search_text,status,version,created_ns,updated_ns) VALUES(?,?,?,?,?,?,?,?)`), id, input.Title, input.Notes, strings.ToLower(input.Title+"\n"+input.Notes), input.Status, 1, now.UnixNano(), now.UnixNano())
	if err != nil {
		return Case{}, dbError(ctx, err)
	}
	return Case{ID: id, Title: input.Title, Notes: input.Notes, Status: input.Status, Version: 1, Created: now, Updated: now, Alerts: []AlertRef{}}, nil
}

func (db *DB) UpdateCase(ctx context.Context, id string, version int, input CaseInput) (Case, error) {
	if !identifier.MatchString(id) || version < 1 {
		return Case{}, ErrInvalid
	}
	input, err := normalizeCase(input)
	if err != nil {
		return Case{}, err
	}
	result, err := db.sql.ExecContext(ctx, db.bind(`UPDATE omamori_cases SET title=?,notes=?,search_text=?,status=?,version=version+1,updated_ns=? WHERE id=? AND version=?`), input.Title, input.Notes, strings.ToLower(input.Title+"\n"+input.Notes), input.Status, time.Now().UTC().UnixNano(), id, version)
	if err != nil {
		return Case{}, dbError(ctx, err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Case{}, ErrDatabase
	}
	if count == 0 {
		if _, err := db.GetCase(ctx, id); err != nil {
			return Case{}, err
		}
		return Case{}, ErrConflict
	}
	return db.GetCase(ctx, id)
}

const caseColumns = `c.id,c.title,c.notes,c.status,c.version,c.created_ns,c.updated_ns`

func scanCase(row scanner) (Case, error) {
	var value Case
	var made, updated int64
	err := row.Scan(&value.ID, &value.Title, &value.Notes, &value.Status, &value.Version, &made, &updated)
	value.Created = time.Unix(0, made).UTC()
	value.Updated = time.Unix(0, updated).UTC()
	value.Alerts = []AlertRef{}
	return value, err
}

func (db *DB) GetCase(ctx context.Context, id string) (Case, error) {
	if !identifier.MatchString(id) {
		return Case{}, ErrInvalid
	}
	result, err := scanCase(db.sql.QueryRowContext(ctx, db.bind(`SELECT `+caseColumns+` FROM omamori_cases c WHERE c.id=?`), id))
	if err != nil {
		return Case{}, dbError(ctx, err)
	}
	links, err := db.caseLinks(ctx, id)
	if err != nil {
		return Case{}, err
	}
	result.Alerts = links
	return result, nil
}
func (db *DB) caseLinks(ctx context.Context, id string) ([]AlertRef, error) {
	rows, err := db.sql.QueryContext(ctx, db.bind(`SELECT run_id,alert_id FROM omamori_case_alerts WHERE case_id=? ORDER BY run_id,alert_id`), id)
	if err != nil {
		return nil, dbError(ctx, err)
	}
	defer rows.Close()
	result := []AlertRef{}
	for rows.Next() {
		var item AlertRef
		if err := rows.Scan(&item.RunID, &item.AlertID); err != nil {
			return nil, dbError(ctx, err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, dbError(ctx, err)
	}
	return result, nil
}

func (db *DB) ListCases(ctx context.Context, query Query) ([]Case, error) {
	query, err := normalizeQuery(query)
	if err != nil {
		return nil, err
	}
	if query.Status != "" && query.Status != "open" && query.Status != "investigating" && query.Status != "closed" {
		return nil, ErrInvalid
	}
	where, args := []string{"1=1"}, []any{}
	add := func(condition string, values ...any) {
		where = append(where, condition)
		args = append(args, values...)
	}
	if query.CaseID != "" {
		add(`c.id=?`, query.CaseID)
	}
	if query.Status != "" {
		add(`c.status=?`, query.Status)
	}
	if query.Text != "" {
		add(`c.search_text LIKE ? ESCAPE '!'`, like(query.Text))
	}
	if query.RunID != "" {
		add(`EXISTS(SELECT 1 FROM omamori_case_alerts l WHERE l.case_id=c.id AND l.run_id=?)`, query.RunID)
	}
	if query.Source != "" || query.Field != "" || query.Level != "" || query.Rule != "" {
		condition, values := db.conditions("alert", Query{RunID: query.RunID, Source: query.Source, Field: query.Field, Value: query.Value, Level: query.Level, Rule: query.Rule})
		add(`EXISTS(SELECT 1 FROM omamori_case_alerts l JOIN omamori_alerts a ON a.run_id=l.run_id AND a.alert_id=l.alert_id WHERE l.case_id=c.id AND `+condition+`)`, values...)
	}
	if !query.From.IsZero() {
		add(`c.created_ns>=?`, query.From.UnixNano())
	}
	if !query.To.IsZero() {
		add(`c.created_ns<=?`, query.To.UnixNano())
	}
	args = append(args, query.Limit, query.Offset)
	rows, err := db.sql.QueryContext(ctx, db.bind(`SELECT `+caseColumns+` FROM omamori_cases c WHERE `+strings.Join(where, " AND ")+` ORDER BY c.updated_ns DESC,c.id ASC LIMIT ? OFFSET ?`), args...)
	if err != nil {
		return nil, dbError(ctx, err)
	}
	result := []Case{}
	for rows.Next() {
		value, err := scanCase(rows)
		if err != nil {
			rows.Close()
			return nil, dbError(ctx, err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, dbError(ctx, err)
	}
	rows.Close()
	for i := range result {
		links, err := db.caseLinks(ctx, result[i].ID)
		if err != nil {
			return nil, err
		}
		result[i].Alerts = links
	}
	return result, nil
}

func (db *DB) AddCaseAlert(ctx context.Context, caseID, runID, alertID string) error {
	return db.changeCaseAlert(ctx, caseID, runID, alertID, true)
}
func (db *DB) RemoveCaseAlert(ctx context.Context, caseID, runID, alertID string) error {
	return db.changeCaseAlert(ctx, caseID, runID, alertID, false)
}
func (db *DB) changeCaseAlert(ctx context.Context, caseID, runID, alertID string, add bool) error {
	if !identifier.MatchString(caseID) || !identifier.MatchString(runID) || !identifier.MatchString(alertID) {
		return ErrInvalid
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return dbError(ctx, err)
	}
	defer tx.Rollback()
	lock := `SELECT version FROM omamori_cases WHERE id=?`
	if db.driver != "sqlite" {
		lock += ` FOR UPDATE`
	}
	var version int
	if err := tx.QueryRowContext(ctx, db.bind(lock), caseID).Scan(&version); err != nil {
		return dbError(ctx, err)
	}
	var existing int
	if err := tx.QueryRowContext(ctx, db.bind(`SELECT COUNT(*) FROM omamori_alerts WHERE run_id=? AND alert_id=?`), runID, alertID).Scan(&existing); err != nil {
		return dbError(ctx, err)
	}
	if existing == 0 {
		return ErrNotFound
	}
	if err := tx.QueryRowContext(ctx, db.bind(`SELECT COUNT(*) FROM omamori_case_alerts WHERE case_id=? AND run_id=? AND alert_id=?`), caseID, runID, alertID).Scan(&existing); err != nil {
		return dbError(ctx, err)
	}
	if add && existing == 0 {
		_, err = tx.ExecContext(ctx, db.bind(`INSERT INTO omamori_case_alerts(case_id,run_id,alert_id) VALUES(?,?,?)`), caseID, runID, alertID)
	} else if !add && existing > 0 {
		_, err = tx.ExecContext(ctx, db.bind(`DELETE FROM omamori_case_alerts WHERE case_id=? AND run_id=? AND alert_id=?`), caseID, runID, alertID)
	} else {
		return nil
	}
	if err != nil {
		return dbError(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, db.bind(`UPDATE omamori_cases SET version=version+1,updated_ns=? WHERE id=?`), time.Now().UTC().UnixNano(), caseID); err != nil {
		return dbError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return dbError(ctx, err)
	}
	return nil
}
