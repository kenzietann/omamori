// Package keystore keeps an API key in the macOS Keychain, so the user types it only once.
// The key is never written to a file by Omamori and never put on a command line, where other
// programs could read it. On other systems nothing is saved, and the key stays in memory.
package keystore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// The errors have fixed texts. They never hold a key.
var (
	ErrUnavailable = errors.New("saving the key is not available on this system")
	ErrNotFound    = errors.New("no saved key")
	ErrBadValue    = errors.New("this key or provider cannot be saved")
	ErrFailed      = errors.New("the keychain did not answer as expected")
)

const (
	DefaultService = "omamori"
	maxKeyBytes    = 400
	securityTool   = "/usr/bin/security"
	notFoundStatus = 44
	waitForTool    = 15 * time.Second
)

var (
	// A name must start with a letter or a digit, so that it can never look like an option of the tool.
	providerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	servicePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Runner starts the security tool. It returns what the tool printed and its exit status.
type Runner func(ctx context.Context, stdin string, args ...string) (stdout string, status int, err error)

type Store struct {
	service string
	run     Runner
	system  string
}

// New makes a store for the Keychain of this machine.
func New(service string) (*Store, error) {
	return newStore(service, runSecurity, runtime.GOOS)
}

func newStore(service string, run Runner, system string) (*Store, error) {
	if !servicePattern.MatchString(service) {
		return nil, ErrBadValue
	}

	return &Store{service: service, run: run, system: system}, nil
}

// Available says whether keys can be saved here.
func (store *Store) Available() bool {
	return store.system == "darwin"
}

func runSecurity(ctx context.Context, stdin string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, waitForTool)
	defer cancel()

	command := exec.CommandContext(ctx, securityTool, args...)
	command.Stdin = strings.NewReader(stdin)
	var stdout bytes.Buffer
	command.Stdout = &stdout

	err := command.Run()
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return stdout.String(), exitError.ExitCode(), nil
	}
	if err != nil {
		return "", -1, ErrFailed
	}

	return stdout.String(), 0, nil
}

func validKey(key string) bool {
	if key == "" || len(key) > maxKeyBytes {
		return false
	}
	for _, character := range key {
		if character < '!' || character > '~' {
			return false
		}
	}

	return true
}

// Set saves the key for a provider. An older key of the same provider is replaced.
// The key goes to the tool through its standard input, in hexadecimal form, so it is not visible
// in the list of running programs and needs no quoting.
func (store *Store) Set(ctx context.Context, providerID, key string) error {
	if !store.Available() {
		return ErrUnavailable
	}
	if !providerPattern.MatchString(providerID) || !validKey(key) {
		return ErrBadValue
	}

	command := "add-generic-password -U -s " + store.service + " -a " + providerID + " -X " + hex.EncodeToString([]byte(key)) + "\n"
	_, status, err := store.run(ctx, command, "-i")
	if err != nil || status != 0 {
		return ErrFailed
	}

	return nil
}

// Get returns the saved key of a provider, or ErrNotFound.
func (store *Store) Get(ctx context.Context, providerID string) (string, error) {
	if !store.Available() {
		return "", ErrUnavailable
	}
	if !providerPattern.MatchString(providerID) {
		return "", ErrBadValue
	}

	stdout, status, err := store.run(ctx, "", "find-generic-password", "-s", store.service, "-a", providerID, "-w")
	switch {
	case err != nil:
		return "", ErrFailed
	case status == notFoundStatus:
		return "", ErrNotFound
	case status != 0:
		return "", ErrFailed
	}

	key := strings.TrimSuffix(stdout, "\n")
	if !validKey(key) {
		return "", ErrFailed
	}

	return key, nil
}

// Delete removes the saved key of a provider. A key that is not there is not an error.
func (store *Store) Delete(ctx context.Context, providerID string) error {
	if !store.Available() {
		return ErrUnavailable
	}
	if !providerPattern.MatchString(providerID) {
		return ErrBadValue
	}

	_, status, err := store.run(ctx, "", "delete-generic-password", "-s", store.service, "-a", providerID)
	if err != nil || (status != 0 && status != notFoundStatus) {
		return ErrFailed
	}

	return nil
}
