package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kenzietann/omamori/internal/assets"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/indicators"
	"github.com/kenzietann/omamori/internal/replay"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/runstore"
	"github.com/kenzietann/omamori/internal/store"
	"github.com/kenzietann/omamori/internal/tui"
)

// expandPath reads a path typed in the home screen. ~/ is the home folder; other relative paths are
// relative to the folder Omamori was started in, as for the commands.
func (b backend) expandPath(text string) (string, error) {
	path := strings.TrimSpace(text)
	if path == "~" {
		path = "~/"
	}
	if rest, found := strings.CutPrefix(path, "~/"); found {
		home := b.env.home
		if home == nil {
			home = os.UserHomeDir
		}
		folder, err := home()
		if err != nil || folder == "" {
			return "", errors.New("no home folder was found for ~")
		}
		path = filepath.Join(folder, rest)
	}
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" {
		return "", errors.New("a path is not usable")
	}

	return absolute, nil
}

// homeRules gives the built-in rules, or the rules of the folder from the form.
func (b backend) homeRules(options tui.Options, forensic bool) (rules.Set, string, error) {
	if options.Rules == "" {
		if forensic {
			set, err := rules.BuiltinForensics()
			return set, "built-in, with the rules for artifacts", err
		}
		set, err := rules.Builtin()
		return set, "built-in", err
	}
	folder, err := b.expandPath(options.Rules)
	if err != nil {
		return rules.Set{}, "", err
	}
	set, err := rules.Load(folder)
	if err != nil {
		return rules.Set{}, "", err
	}
	if len(set.Rules()) == 0 {
		return rules.Set{}, "", errors.New("the rules folder has no rule")
	}

	return set, "from a folder", nil
}

// homeLists reads the asset list and the indicator list of the form, when they are given.
func (b backend) homeLists(options tui.Options) (*assets.List, *indicators.List, error) {
	var machines *assets.List
	var known *indicators.List
	if options.Assets != "" {
		path, err := b.expandPath(options.Assets)
		if err != nil {
			return nil, nil, err
		}
		if machines, err = assets.Load(path); err != nil {
			return nil, nil, err
		}
	}
	if options.Indicators != "" {
		path, err := b.expandPath(options.Indicators)
		if err != nil {
			return nil, nil, err
		}
		if known, err = indicators.Load(path); err != nil {
			return nil, nil, err
		}
	}

	return machines, known, nil
}

// homeSnapshots gives the absolute paths of the saved ps and ss output of the form.
func (b backend) homeSnapshots(options tui.Options) (string, string, error) {
	var paths [2]string
	for index, text := range []string{options.Processes, options.Sockets} {
		if text == "" {
			continue
		}
		path, err := b.expandPath(text)
		if err != nil {
			return "", "", err
		}
		paths[index] = path
	}

	return paths[0], paths[1], nil
}

func (b backend) homeRecording(options tui.Options) (*replay.Recording, error) {
	path, err := b.expandPath(options.Recording)
	if err != nil {
		return nil, err
	}
	recorded, err := replay.Load(path)
	if err != nil {
		return nil, err
	}

	return &recorded, nil
}

func (b backend) storageEnv() environment {
	env := b.env
	if env.home == nil {
		env.home = os.UserHomeDir
	}
	if env.lookupEnv == nil {
		env.lookupEnv = b.config.LookupEnv
	}

	return env
}

// storeWhere says in words where a run will be stored. It opens nothing: the database is only opened for a run.
func (b backend) storeWhere() (string, error) {
	cfg, err := (storageFlags{enabled: true}).config(b.storageEnv())
	if err != nil {
		return "", err
	}
	if cfg.Driver == "sqlite" {
		return cfg.DSN, nil
	}

	return "the configured database server", nil
}

func (b backend) openStore(ctx context.Context, sources []string) (*store.DB, error) {
	return (storageFlags{enabled: true}).open(ctx, b.storageEnv(), sources)
}

func (b backend) storeOutcome(ctx context.Context, outcome detect.Outcome, sources []string) (string, error) {
	db, err := b.openStore(ctx, sources)
	if err != nil {
		return "", err
	}
	defer db.Close()
	run, err := runstore.Save(ctx, db, outcome, nil)
	if err != nil {
		return "", err
	}

	return run.ID, nil
}

func parseSeed(text string, fallback int64) (int64, error) {
	if text == "" {
		return fallback, nil
	}
	seed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("the seed must be a whole number")
	}

	return seed, nil
}
