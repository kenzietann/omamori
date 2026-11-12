// Package appconfig keeps the choices of the user (provider, model, reasoning level) in one small
// file, so they do not have to be made again. It never holds a key: keys go to the keystore.
package appconfig

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrBadValue = errors.New("these settings cannot be saved")
	ErrCorrupt  = errors.New("the settings file cannot be read")
	ErrWrite    = errors.New("the settings file cannot be written")
)

const (
	fileName      = "settings.json"
	folderName    = "omamori"
	maxFileBytes  = 4096
	maxModelRunes = 200
)

var (
	providerPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	reasoningPattern = regexp.MustCompile(`^[a-z]{3,10}$`)
)

type Settings struct {
	Provider  string `json:"provider,omitempty"`
	Model     string `json:"model,omitempty"`
	Reasoning string `json:"reasoning,omitempty"`
}

func Path() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		return "", ErrWrite
	}

	return filepath.Join(base, folderName, fileName), nil
}

func validModel(model string) bool {
	if utf8.RuneCountInString(model) > maxModelRunes || !utf8.ValidString(model) {
		return false
	}
	for _, character := range model {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}

	return true
}

func (settings Settings) Valid() bool {
	return (settings.Provider == "" || providerPattern.MatchString(settings.Provider)) &&
		validModel(settings.Model) &&
		(settings.Reasoning == "" || reasoningPattern.MatchString(settings.Reasoning))
}

// cleaned drops the fields that are not well formed. A file that was edited by hand must not stop the program.
func (settings Settings) cleaned() Settings {
	if settings.Provider != "" && !providerPattern.MatchString(settings.Provider) {
		settings.Provider = ""
	}
	if !validModel(settings.Model) {
		settings.Model = ""
	}
	settings.Model = strings.TrimSpace(settings.Model)
	if settings.Reasoning != "" && !reasoningPattern.MatchString(settings.Reasoning) {
		settings.Reasoning = ""
	}

	return settings
}

func Load(path string) (Settings, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return Settings{}, ErrCorrupt
	}

	file, err := os.Open(path)
	if err != nil {
		return Settings{}, ErrCorrupt
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil || len(data) > maxFileBytes {
		return Settings{}, ErrCorrupt
	}

	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return Settings{}, ErrCorrupt
	}

	return settings.cleaned(), nil
}

// Save writes the file. It writes a new file next to the old one and then renames it,
// so a stop in the middle never leaves half a file. Only the user can read it.
func Save(path string, settings Settings) error {
	settings.Model = strings.TrimSpace(settings.Model)
	if !settings.Valid() {
		return ErrBadValue
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return ErrWrite
	}

	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return ErrWrite
	}
	temporary, err := os.CreateTemp(directory, ".settings-*")
	if err != nil {
		return ErrWrite
	}
	defer os.Remove(temporary.Name())

	if _, err := temporary.Write(append(data, '\n')); err != nil {
		temporary.Close()
		return ErrWrite
	}
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return ErrWrite
	}
	if err := temporary.Close(); err != nil {
		return ErrWrite
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return ErrWrite
	}

	return nil
}
