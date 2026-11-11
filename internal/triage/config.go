// Package triage is Task B: the log triage. The AI reads an sshd auth.log and proposes findings (claims).
// Omamori reads the same log itself, recomputes every claim from the parsed lines, and accepts only the
// claims that the log proves. It also finds the two attack patterns itself, and says which ones the AI missed.
package triage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

var ErrConfig = errors.New("the triage settings cannot be used")

const maxConfigBytes = 4096

// Config holds the numbers of the two scenarios. They are test values, so they are settings and not facts.
type Config struct {
	// Window is inclusive: exactly this long is inside, one second more is outside.
	Window           time.Duration
	FailureThreshold int
	SprayThreshold   int
	// Year and Location are needed because the log lines have no year and no time zone.
	Year     int
	Location *time.Location
	// ZoneName is the name of Location, for the report.
	ZoneName string
}

// Defaults are the values of the PRD: 10 minutes, 5 failures, 5 different user names.
func Defaults(now time.Time) Config {
	return Config{Window: 10 * time.Minute, FailureThreshold: 5, SprayThreshold: 5, Year: now.Year(), Location: time.Local, ZoneName: "Local"}
}

func (config Config) Validate() error {
	if config.Window < time.Minute || config.Window > 24*time.Hour || config.FailureThreshold < 2 || config.FailureThreshold > 1000 ||
		config.SprayThreshold < 2 || config.SprayThreshold > 1000 || config.Year < 1970 || config.Year > 2200 || config.Location == nil {
		return ErrConfig
	}

	return nil
}

// fileConfig is the JSON file. A missing setting keeps its default.
type fileConfig struct {
	WindowMinutes    *int    `json:"window_minutes"`
	FailureThreshold *int    `json:"failure_threshold"`
	SprayThreshold   *int    `json:"spray_threshold"`
	Year             *int    `json:"year"`
	TimeZone         *string `json:"time_zone"`
}

// LoadConfig reads the settings file. A file that is not there gives the defaults.
func LoadConfig(path string, now time.Time) (Config, error) {
	config := Defaults(now)
	if path == "" {
		return config, nil
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return config, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		return Config{}, ErrConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, ErrConfig
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil || len(data) > maxConfigBytes {
		return Config{}, ErrConfig
	}

	var decoded fileConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil || decoder.More() {
		return Config{}, ErrConfig
	}

	if decoded.WindowMinutes != nil {
		config.Window = time.Duration(*decoded.WindowMinutes) * time.Minute
	}
	if decoded.FailureThreshold != nil {
		config.FailureThreshold = *decoded.FailureThreshold
	}
	if decoded.SprayThreshold != nil {
		config.SprayThreshold = *decoded.SprayThreshold
	}
	if decoded.Year != nil {
		config.Year = *decoded.Year
	}
	if decoded.TimeZone != nil {
		location, err := time.LoadLocation(*decoded.TimeZone)
		if err != nil || *decoded.TimeZone == "" {
			return Config{}, ErrConfig
		}
		config.Location, config.ZoneName = location, *decoded.TimeZone
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}

	return config, nil
}
