package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/store"
)

const usageStore = `usage: omamori store <command> [flags]
Commands:
  init                         initialize or verify the configured database
  runs                         list stored runs
  run <id>                     show a run and its analysis/coverage
  search                       search events (add --kind alerts for alerts)
  timeline                     chronological events and alerts across runs
  cases list|show <id>|create|update <id>|add <id>|remove <id>

Database: SQLite by default; --db chooses its file. PostgreSQL/MariaDB use
OMAMORI_DB_DRIVER=postgres|mariadb and OMAMORI_DB_DSN. Credentials are never flags.
Query flags: --run, --case, --text, --source, --level, --rule, --field, --value,
             --from/--to RFC3339, --limit (default 50), --offset (default 0).
Case flags: --title, --notes, --status open|investigating|closed.
Update requires --version. Add/remove require --run and --alert.
All query and case results are JSON. --timeout defaults to 30s.`

type storageFlags struct {
	enabled bool
	path    string
}

func (chosen *storageFlags) bind(flags *flag.FlagSet, enableFlag bool) {
	if enableFlag {
		flags.BoolVar(&chosen.enabled, "store", false, "save the sanitized run for search, cases and timelines")
	}
	flags.StringVar(&chosen.path, "db", "", "SQLite database file (also enables storage)")
}

func (chosen storageFlags) wanted() bool { return chosen.enabled || chosen.path != "" }

// Database credentials come only from the environment and are never included in diagnostics.
func (chosen storageFlags) config(env environment) (store.Config, error) {
	lookup := env.lookupEnv
	if lookup == nil {
		lookup = func(string) string { return "" }
	}
	driver := strings.ToLower(strings.TrimSpace(lookup("OMAMORI_DB_DRIVER")))
	if driver == "" {
		driver = "sqlite"
	}
	if driver != "sqlite" && driver != "postgres" && driver != "mariadb" {
		return store.Config{}, store.ErrConfig
	}
	dsn := lookup("OMAMORI_DB_DSN")
	if driver != "sqlite" {
		if chosen.path != "" || strings.TrimSpace(dsn) == "" {
			return store.Config{}, store.ErrConfig
		}
		return store.Config{Driver: driver, DSN: dsn}, nil
	}
	if chosen.path != "" {
		dsn = chosen.path
	}
	if dsn == "" {
		if env.home == nil {
			return store.Config{}, store.ErrConfig
		}
		home, err := env.home()
		if err != nil || home == "" {
			return store.Config{}, store.ErrConfig
		}
		dsn = filepath.Join(home, "omamori-data", "omamori.db")
	}
	if dsn == ":memory:" || strings.HasPrefix(dsn, "file:") || strings.ContainsAny(dsn, "?\x00") {
		return store.Config{}, store.ErrConfig
	}
	absolute, err := filepath.Abs(dsn)
	if err != nil {
		return store.Config{}, store.ErrConfig
	}
	return store.Config{Driver: driver, DSN: absolute}, nil
}

func (chosen storageFlags) open(ctx context.Context, env environment, sources []string) (*store.DB, error) {
	config, err := chosen.config(env)
	if err != nil {
		return nil, err
	}
	if config.Driver == "sqlite" {
		for _, source := range sources {
			for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
				if err := pathguard.CheckOutputFolder(source, config.DSN+suffix); err != nil {
					return nil, errors.New("the SQLite database must not overlap the input logs")
				}
			}
		}
	}
	return store.Open(ctx, config)
}

func runStore(args []string, env environment) int {
	if len(args) == 0 {
		fmt.Fprintln(env.stderr, usageStore)
		return exitUsage
	}
	command, rest := args[0], args[1:]
	caseAction := ""
	if command == "cases" {
		if len(rest) == 0 {
			fmt.Fprintln(env.stderr, usageStore)
			return exitUsage
		}
		caseAction, rest = rest[0], rest[1:]
	}
	flags := flag.NewFlagSet("store", flag.ContinueOnError)
	var database storageFlags
	database.bind(flags, false)
	query := store.Query{}
	var kind, from, to, title, notes, status, alertID string
	var version int
	var timeout time.Duration
	flags.StringVar(&query.RunID, "run", "", "run identifier")
	flags.StringVar(&query.CaseID, "case", "", "case identifier")
	flags.StringVar(&query.Text, "text", "", "literal case-insensitive text search")
	flags.StringVar(&query.Source, "source", "", "event source")
	flags.StringVar(&query.Level, "level", "", "alert severity")
	flags.StringVar(&query.Rule, "rule", "", "rule name")
	flags.StringVar(&query.Field, "field", "", "exact event field name")
	flags.StringVar(&query.Value, "value", "", "exact event field value")
	flags.StringVar(&from, "from", "", "inclusive first RFC3339 timestamp")
	flags.StringVar(&to, "to", "", "inclusive last RFC3339 timestamp")
	flags.IntVar(&query.Limit, "limit", 50, "maximum rows")
	flags.IntVar(&query.Offset, "offset", 0, "rows to skip")
	flags.StringVar(&kind, "kind", "events", "events or alerts")
	flags.StringVar(&title, "title", "", "case title")
	flags.StringVar(&notes, "notes", "", "case notes")
	flags.StringVar(&status, "status", "", "case status")
	flags.IntVar(&version, "version", 0, "expected case version for an update")
	flags.StringVar(&alertID, "alert", "", "alert identifier within a run")
	flags.DurationVar(&timeout, "timeout", 30*time.Second, "operation timeout")
	positional, err := splitFlags(flags, rest)
	if err != nil || timeout <= 0 || query.Limit < 1 || query.Limit > 500 || query.Offset < 0 {
		fmt.Fprintln(env.stderr, usageStore)
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	if from != "" {
		query.From, err = time.Parse(time.RFC3339Nano, from)
		if err != nil {
			return fail(errors.New("--from must be an RFC3339 timestamp"))
		}
	}
	if to != "" {
		query.To, err = time.Parse(time.RFC3339Nano, to)
		if err != nil {
			return fail(errors.New("--to must be an RFC3339 timestamp"))
		}
	}
	query.Status = status
	needsID := command == "run" || command == "cases" && (caseAction == "show" || caseAction == "update" || caseAction == "add" || caseAction == "remove")
	validCommand := command == "init" || command == "runs" || command == "run" || command == "search" || command == "timeline" ||
		command == "cases" && (caseAction == "list" || caseAction == "show" || caseAction == "create" || caseAction == "update" || caseAction == "add" || caseAction == "remove")
	if !validCommand || needsID && len(positional) != 1 || !needsID && len(positional) != 0 ||
		command == "search" && kind != "events" && kind != "alerts" ||
		caseAction == "update" && version < 1 || (caseAction == "add" || caseAction == "remove") && (query.RunID == "" || alertID == "") {
		fmt.Fprintln(env.stderr, usageStore)
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	db, err := database.open(ctx, env, nil)
	if err != nil {
		return fail(err)
	}
	defer db.Close()
	var result any
	switch command {
	case "init":
		config, _ := database.config(env)
		result = map[string]any{"status": "ready", "driver": config.Driver}
	case "runs":
		result, err = db.ListRuns(ctx, query)
	case "run":
		result, err = db.GetRun(ctx, positional[0])
	case "search":
		if kind == "alerts" {
			result, err = db.SearchAlerts(ctx, query)
		} else {
			result, err = db.SearchEvents(ctx, query)
		}
	case "timeline":
		result, err = db.Timeline(ctx, query)
	case "cases":
		switch caseAction {
		case "list":
			result, err = db.ListCases(ctx, query)
		case "show":
			result, err = db.GetCase(ctx, positional[0])
		case "create":
			result, err = db.CreateCase(ctx, store.CaseInput{Title: title, Notes: notes, Status: status})
		case "update":
			current, readErr := db.GetCase(ctx, positional[0])
			if readErr != nil {
				return fail(readErr)
			}
			update := store.CaseInput{Title: current.Title, Notes: current.Notes, Status: current.Status}
			flags.Visit(func(option *flag.Flag) {
				switch option.Name {
				case "title":
					update.Title = title
				case "notes":
					update.Notes = notes
				case "status":
					update.Status = status
				}
			})
			result, err = db.UpdateCase(ctx, positional[0], version, update)
		case "add", "remove":
			if caseAction == "add" {
				err = db.AddCaseAlert(ctx, positional[0], query.RunID, alertID)
			} else {
				err = db.RemoveCaseAlert(ctx, positional[0], query.RunID, alertID)
			}
			if err == nil {
				result, err = db.GetCase(ctx, positional[0])
			}
		}
	}
	if err != nil {
		return fail(err)
	}
	encoder := json.NewEncoder(env.stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fail(errors.New("the stored result could not be displayed"))
	}
	return exitOK
}
