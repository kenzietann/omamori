package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type DB struct {
	sql    *sql.DB
	driver string
}

// Open uses a SQLite file path (or :memory:) or a configured PostgreSQL/MariaDB DSN.
// Driver diagnostics can contain credentials, so public errors never repeat them.
func Open(ctx context.Context, config Config) (*DB, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	driver := strings.ToLower(config.Driver)
	if driver == "" {
		driver = "sqlite"
	}
	name, dsn := driver, config.DSN
	switch driver {
	case "sqlite":
		var err error
		dsn, err = sqliteDSN(dsn)
		if err != nil {
			return nil, err
		}
	case "postgres", "postgresql":
		driver, name = "postgres", "pgx"
	case "mariadb", "mysql":
		driver, name = "mariadb", "mysql"
	default:
		return nil, ErrConfig
	}
	if dsn == "" {
		return nil, ErrConfig
	}
	connection, err := sql.Open(name, dsn)
	if err != nil {
		return nil, ErrConfig
	}
	if driver == "sqlite" {
		connection.SetMaxOpenConns(1)
		connection.SetMaxIdleConns(1)
	} else {
		connection.SetMaxOpenConns(8)
		connection.SetMaxIdleConns(2)
		connection.SetConnMaxLifetime(5 * time.Minute)
	}
	db := &DB{sql: connection, driver: driver}
	if err := connection.PingContext(ctx); err != nil {
		connection.Close()
		return nil, dbError(ctx, err)
	}
	if err := db.migrate(ctx); err != nil {
		connection.Close()
		return nil, err
	}
	return db, nil
}

func sqliteDSN(path string) (string, error) {
	if path == ":memory:" {
		return ":memory:?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate", nil
	}
	if path == "" || strings.HasPrefix(path, "file:") || strings.ContainsAny(path, "?\x00") {
		return "", ErrConfig
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", ErrConfig
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
		return "", ErrConfig
	}
	info, err := os.Lstat(absolute)
	if err == nil && !info.Mode().IsRegular() {
		return "", ErrConfig
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", ErrConfig
	}
	if errors.Is(err, os.ErrNotExist) {
		file, openErr := os.OpenFile(absolute, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			if !errors.Is(openErr, os.ErrExist) {
				return "", ErrConfig
			}
			if existing, err := os.Lstat(absolute); err != nil || !existing.Mode().IsRegular() {
				return "", ErrConfig
			}
		} else if file.Close() != nil {
			return "", ErrConfig
		}
	}
	address := url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
	query := url.Values{}
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Set("_txlock", "immediate")
	address.RawQuery = query.Encode()
	return address.String(), nil
}

func (db *DB) Close() error {
	if err := db.sql.Close(); err != nil {
		return ErrDatabase
	}
	return nil
}

func dbError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return ErrDatabase
}

func (db *DB) bind(query string) string {
	if db.driver != "postgres" {
		return query
	}
	var out strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			out.WriteByte('$')
			out.WriteString(strconv.Itoa(n))
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

type executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (db *DB) migrate(ctx context.Context) error {
	textType, suffix := "TEXT", ""
	if db.driver == "mariadb" {
		textType = "LONGTEXT"
		suffix = " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin"
	}
	create := func(body string) string { return strings.ReplaceAll(body, "$TEXT", textType) + suffix }
	statements := []string{
		create(`CREATE TABLE IF NOT EXISTS omamori_runs (id VARCHAR(80) PRIMARY KEY, digest VARCHAR(64) NOT NULL, made_ns BIGINT NOT NULL, mode VARCHAR(40) NOT NULL, label $TEXT NOT NULL, search_text $TEXT NOT NULL, event_count BIGINT NOT NULL, alert_count BIGINT NOT NULL, analysis $TEXT NOT NULL, coverage $TEXT NOT NULL)`),
		create(`CREATE TABLE IF NOT EXISTS omamori_events (run_id VARCHAR(80) NOT NULL, event_id VARCHAR(80) NOT NULL, event_time BIGINT NOT NULL, source VARCHAR(100) NOT NULL, document $TEXT NOT NULL, search_text $TEXT NOT NULL, PRIMARY KEY(run_id,event_id), FOREIGN KEY(run_id) REFERENCES omamori_runs(id))`),
		create(`CREATE TABLE IF NOT EXISTS omamori_alerts (run_id VARCHAR(80) NOT NULL, alert_id VARCHAR(80) NOT NULL, alert_time BIGINT NOT NULL, rule_name VARCHAR(200) NOT NULL, level VARCHAR(20) NOT NULL, document $TEXT NOT NULL, search_text $TEXT NOT NULL, PRIMARY KEY(run_id,alert_id), FOREIGN KEY(run_id) REFERENCES omamori_runs(id))`),
		create(`CREATE TABLE IF NOT EXISTS omamori_event_fields (run_id VARCHAR(80) NOT NULL,event_id VARCHAR(80) NOT NULL,field_name VARCHAR(200) NOT NULL,field_value $TEXT NOT NULL,value_hash VARCHAR(64) NOT NULL,PRIMARY KEY(run_id,event_id,field_name),FOREIGN KEY(run_id,event_id) REFERENCES omamori_events(run_id,event_id))`),
		create(`CREATE TABLE IF NOT EXISTS omamori_alert_fields (run_id VARCHAR(80) NOT NULL,alert_id VARCHAR(80) NOT NULL,field_name VARCHAR(200) NOT NULL,field_value $TEXT NOT NULL,value_hash VARCHAR(64) NOT NULL,PRIMARY KEY(run_id,alert_id,field_name),FOREIGN KEY(run_id,alert_id) REFERENCES omamori_alerts(run_id,alert_id))`),
		create(`CREATE TABLE IF NOT EXISTS omamori_alert_events (run_id VARCHAR(80) NOT NULL,alert_id VARCHAR(80) NOT NULL,event_id VARCHAR(80) NOT NULL,PRIMARY KEY(run_id,alert_id,event_id),FOREIGN KEY(run_id,alert_id) REFERENCES omamori_alerts(run_id,alert_id),FOREIGN KEY(run_id,event_id) REFERENCES omamori_events(run_id,event_id))`),
		create(`CREATE TABLE IF NOT EXISTS omamori_cases (id VARCHAR(80) PRIMARY KEY,title $TEXT NOT NULL,notes $TEXT NOT NULL,search_text $TEXT NOT NULL,status VARCHAR(20) NOT NULL,version BIGINT NOT NULL,created_ns BIGINT NOT NULL,updated_ns BIGINT NOT NULL)`),
		create(`CREATE TABLE IF NOT EXISTS omamori_case_alerts (case_id VARCHAR(80) NOT NULL,run_id VARCHAR(80) NOT NULL,alert_id VARCHAR(80) NOT NULL,PRIMARY KEY(case_id,run_id,alert_id),FOREIGN KEY(case_id) REFERENCES omamori_cases(id),FOREIGN KEY(run_id,alert_id) REFERENCES omamori_alerts(run_id,alert_id))`),
		`CREATE INDEX IF NOT EXISTS omamori_events_time ON omamori_events(event_time,run_id,event_id)`,
		`CREATE INDEX IF NOT EXISTS omamori_events_source ON omamori_events(source,event_time)`,
		`CREATE INDEX IF NOT EXISTS omamori_alerts_time ON omamori_alerts(alert_time,run_id,alert_id)`,
		`CREATE INDEX IF NOT EXISTS omamori_fields_lookup ON omamori_event_fields(field_name,value_hash)`,
		`CREATE INDEX IF NOT EXISTS omamori_alert_fields_lookup ON omamori_alert_fields(field_name,value_hash)`,
	}
	// PostgreSQL and SQLite DDL is transactional. MariaDB implicitly commits DDL, so each
	// step is idempotent and the version row is written only after every step succeeds.
	var target executor = db.sql
	var transaction *sql.Tx
	if db.driver != "mariadb" {
		var err error
		transaction, err = db.sql.BeginTx(ctx, nil)
		if err != nil {
			return dbError(ctx, err)
		}
		defer transaction.Rollback()
		target = transaction
	}
	if _, err := target.ExecContext(ctx, create(`CREATE TABLE IF NOT EXISTS omamori_schema (version INTEGER PRIMARY KEY, applied_ns BIGINT NOT NULL)`)); err != nil {
		return dbError(ctx, err)
	}
	var version int
	if err := target.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM omamori_schema`).Scan(&version); err != nil {
		return dbError(ctx, err)
	}
	if version > 1 || version < 0 {
		return ErrVersion
	}
	if version == 0 {
		for _, statement := range statements {
			if _, err := target.ExecContext(ctx, statement); err != nil {
				return dbError(ctx, err)
			}
		}
		if _, err := target.ExecContext(ctx, db.bind(`INSERT INTO omamori_schema(version,applied_ns) VALUES(?,?)`), 1, time.Now().UTC().UnixNano()); err != nil {
			return dbError(ctx, err)
		}
	}
	if transaction != nil {
		if err := transaction.Commit(); err != nil {
			return dbError(ctx, err)
		}
	}
	return nil
}
