package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kenzietann/omamori/internal/appconfig"
	"github.com/kenzietann/omamori/internal/dashboard"
	"github.com/kenzietann/omamori/internal/taskrun"
)

const usageDashboard = "usage: omamori dashboard [--port 8765] [--db SQLite-file] [--output folder] [evidence-root]"

func runDashboard(args []string, env environment) int {
	flags := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	var database storageFlags
	database.bind(flags, false)
	var port int
	var output string
	flags.IntVar(&port, "port", 8765, "loopback port, or 0 for an available port")
	flags.StringVar(&output, "output", "", "report output folder")
	paths, err := splitFlags(flags, args)
	if err != nil || len(paths) > 1 || port < 0 || port > 65535 {
		fmt.Fprintln(env.stderr, usageDashboard)
		return exitUsage
	}
	root := "."
	if len(paths) == 1 {
		root = paths[0]
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = serveDashboard(ctx, env, root, output, port, database, func(link, evidence string) {
		fmt.Fprintf(env.stdout, "Omamori local dashboard\nEvidence root: %s\nOpen this private session link:\n%s\nKeep this terminal open. Press Ctrl+C to stop.\n", evidence, link)
	})
	if err != nil {
		fmt.Fprintln(env.stderr, "omamori:", err)
		return exitFailed
	}
	return exitOK
}

// serveDashboard runs the local dashboard until the context ends. The command line and the home screen both
// use it, so there is one way to start the server: bound to 127.0.0.1, with a private link for the session.
// ready gets that link when the server listens.
func serveDashboard(ctx context.Context, env environment, root, output string, port int, database storageFlags, ready func(link, evidence string)) error {
	fail := func(err error) error { return err }
	var err error
	root, err = filepath.Abs(root)
	if err != nil {
		return fail(dashboard.ErrConfig)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return fail(dashboard.ErrConfig)
	}
	chosen := settings{output: output}
	if err := chosen.chooseOutput(env.home); err != nil {
		return fail(err)
	}
	config, err := database.config(env)
	if err != nil {
		return fail(err)
	}
	connectionCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	db, err := database.open(connectionCtx, env, nil)
	cancel()
	if err != nil {
		return fail(err)
	}
	defer db.Close()
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fail(fmt.Errorf("the dashboard port is unavailable"))
	}
	defer listener.Close()
	var saved appconfig.Settings
	if env.settingsPath != nil {
		if path, e := env.settingsPath(); e == nil {
			saved, _ = appconfig.Load(path)
		}
	}
	lookup := env.lookupEnv
	if lookup == nil {
		lookup = func(string) string { return "" }
	}
	defaults := mergeDefaults(settings{provider: lookup("OMAMORI_PROVIDER"), model: lookup("OMAMORI_MODEL")}, saved)
	options := dashboard.Config{DB: db, Root: root, Provider: taskrun.Config{OutputBase: chosen.output, LookupEnv: lookup, Keys: env.keys, Now: env.now, NewProvider: env.newProvider}, DefaultProvider: defaults.ProviderID, DefaultModel: defaults.Model, DefaultReasoning: defaults.Reasoning}
	if config.Driver == "sqlite" {
		options.DatabasePath = config.DSN
	}
	handler, err := dashboard.New(options, listener.Addr().String())
	if err != nil {
		return fail(err)
	}
	defer handler.Close()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	ready(handler.URL(), root)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if err != nil && err != http.ErrServerClosed {
			return fail(fmt.Errorf("the dashboard server stopped unexpectedly"))
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			server.Close()
		}
	}
	return nil
}
