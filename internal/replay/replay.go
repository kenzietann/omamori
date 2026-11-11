// Package replay records the answers of the AI during a live run, and plays them back later through
// the real pipeline (the guard, the tools, the report). It never makes a network call: the player is a
// provider that only reads a recording. Each recorded step holds the hash of the cleaned request that it
// answers. If the real request is different, the run stops with an error. It never falls back to a live call.
package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/sanitizer"
)

const (
	Version = 1
	// SourceLive is a recording of a real run. SourceScripted is written by hand, and the screen says so.
	SourceLive     = "live"
	SourceScripted = "scripted"

	maxFileBytes = 8 << 20
	maxSteps     = 1000
	maxTextRunes = 200000
	maxCalls     = 50
	maxArguments = 20
	maxValueRune = 4000
	maxNameRunes = 100
)

// The error texts are fixed. They never hold a value from a file.
var (
	ErrBadRecording = errors.New("the recording is not valid")
	ErrUnreadable   = errors.New("the recording cannot be read")
)

var (
	hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	taskPattern = regexp.MustCompile(`^[a-z]{3,20}$`)
	logPattern  = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
)

type Call struct {
	ID        string            `json:"id,omitempty"`
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

type Answer struct {
	Text       string `json:"text,omitempty"`
	ToolCalls  []Call `json:"tool_calls,omitempty"`
	TokensUsed int    `json:"tokens_used,omitempty"`
}

type Step struct {
	// RequestHash is empty only in a scripted recording, where nobody can compute it by hand.
	RequestHash string `json:"request_hash,omitempty"`
	Answer      Answer `json:"answer"`
}

// Settings are the numbers of a log triage when it was recorded. A replay uses them, so that it reads the log
// the same way, unless the user gives other settings.
type Settings struct {
	WindowMinutes    int    `json:"window_minutes"`
	FailureThreshold int    `json:"failure_threshold"`
	SprayThreshold   int    `json:"spray_threshold"`
	Year             int    `json:"year"`
	TimeZone         string `json:"time_zone"`
}

func (settings Settings) valid() bool {
	return settings.WindowMinutes >= 1 && settings.WindowMinutes <= 1440 && settings.FailureThreshold >= 2 && settings.FailureThreshold <= 1000 &&
		settings.SprayThreshold >= 2 && settings.SprayThreshold <= 1000 && settings.Year >= 1970 && settings.Year <= 2200 &&
		settings.TimeZone != "" && utf8.RuneCountInString(settings.TimeZone) <= maxNameRunes && utf8.ValidString(settings.TimeZone)
}

type Recording struct {
	Version  int    `json:"version"`
	Source   string `json:"source"`
	Task     string `json:"task"`
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	// Log is the log file of a log triage, relative to the project folder.
	Log string `json:"log,omitempty"`
	// Triage holds the settings of a log triage. It is empty for the exposure check.
	Triage *Settings `json:"triage,omitempty"`
	Steps  []Step    `json:"steps"`
}

// Fingerprint is the hash of a cleaned request. It covers the system prompt, every message, and the tools.
func Fingerprint(request outbound.Request) string {
	encoded, _ := json.Marshal(request)
	sum := sha256.Sum256(encoded)

	return hex.EncodeToString(sum[:])
}

// Validate checks a recording against the schema. A recording from a file is not trusted.
func (recording Recording) Validate() error {
	if recording.Version != Version || (recording.Source != SourceLive && recording.Source != SourceScripted) ||
		!taskPattern.MatchString(recording.Task) || len(recording.Steps) == 0 || len(recording.Steps) > maxSteps {
		return ErrBadRecording
	}
	if utf8.RuneCountInString(recording.Provider) > maxNameRunes || utf8.RuneCountInString(recording.Model) > maxNameRunes ||
		!utf8.ValidString(recording.Provider+recording.Model) || (recording.Log != "" && !logPattern.MatchString(recording.Log)) {
		return ErrBadRecording
	}

	if recording.Triage != nil && !recording.Triage.valid() {
		return ErrBadRecording
	}

	for _, step := range recording.Steps {
		if step.RequestHash == "" && recording.Source == SourceLive || step.RequestHash != "" && !hashPattern.MatchString(step.RequestHash) {
			return ErrBadRecording
		}
		answer := step.Answer
		if utf8.RuneCountInString(answer.Text) > maxTextRunes || !utf8.ValidString(answer.Text) || answer.TokensUsed < 0 ||
			len(answer.ToolCalls) > maxCalls || (answer.Text == "" && len(answer.ToolCalls) == 0) {
			return ErrBadRecording
		}
		for _, call := range answer.ToolCalls {
			if !outbound.ValidToolCall(outbound.ToolCall{ID: call.ID, Name: call.Name, Arguments: call.Arguments}) || len(call.Arguments) > maxArguments {
				return ErrBadRecording
			}
			for _, value := range call.Arguments {
				if utf8.RuneCountInString(value) > maxValueRune || !utf8.ValidString(value) {
					return ErrBadRecording
				}
			}
		}
	}

	return nil
}

// Parse reads a recording from JSON and validates it.
func Parse(data []byte) (Recording, error) {
	if len(data) > maxFileBytes {
		return Recording{}, ErrBadRecording
	}

	var recording Recording
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&recording); err != nil || decoder.More() {
		return Recording{}, ErrBadRecording
	}
	if err := recording.Validate(); err != nil {
		return Recording{}, err
	}

	return recording, nil
}

// Load reads a recording file.
func Load(path string) (Recording, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return Recording{}, ErrUnreadable
	}
	file, err := os.Open(path)
	if err != nil {
		return Recording{}, ErrUnreadable
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return Recording{}, ErrUnreadable
	}

	return Parse(data)
}

// JSON is the text of the recording, ready to be written to a new file.
func (recording Recording) JSON() (string, error) {
	if err := recording.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.MarshalIndent(recording, "", "  ")
	if err != nil {
		return "", ErrBadRecording
	}

	return string(encoded) + "\n", nil
}

// Recorder is a provider that passes every request to another provider and records the answers.
type Recorder struct {
	inner     outbound.Provider
	mutex     sync.Mutex
	recording Recording
}

func NewRecorder(inner outbound.Provider, task, model, log string) *Recorder {
	return &Recorder{inner: inner, recording: Recording{Version: Version, Source: SourceLive, Task: task, Provider: inner.Name(), Model: model, Log: log}}
}

func (recorder *Recorder) Name() string { return recorder.inner.Name() }

// SetTriage keeps the settings of the log triage in the recording.
func (recorder *Recorder) SetTriage(settings Settings) {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()

	recorder.recording.Triage = &settings
}

func (recorder *Recorder) Send(ctx context.Context, safe outbound.SafeRequest) (outbound.Response, error) {
	response, err := recorder.inner.Send(ctx, safe)
	if err != nil {
		return response, err
	}

	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.recording.Steps = append(recorder.recording.Steps, Step{RequestHash: Fingerprint(safe.Request()), Answer: cleanAnswer(response)})

	return response, nil
}

// Recording is a copy of what was recorded so far.
func (recorder *Recorder) Recording() Recording {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()

	copied := recorder.recording
	copied.Steps = slices.Clone(recorder.recording.Steps)
	if recorder.recording.Triage != nil {
		settings := *recorder.recording.Triage
		copied.Triage = &settings
	}

	return copied
}

// cleanAnswer removes supported sensitive values from an answer, because a recording is a file that
// Omamori creates, and no such file may hold a sensitive value.
func cleanAnswer(response outbound.Response) Answer {
	textSanitizer := &sanitizer.Sanitizer{}
	clean := func(text string) string {
		cleaned, _ := textSanitizer.Sanitize(strings.ToValidUTF8(text, "?"))
		return cleaned
	}

	answer := Answer{Text: clean(response.Text), TokensUsed: max(response.TokensUsed, 0)}
	for _, call := range response.ToolCalls {
		recorded := Call{ID: call.ID, Name: call.Name}
		if len(call.Arguments) > 0 {
			recorded.Arguments = make(map[string]string, len(call.Arguments))
			for key, value := range call.Arguments {
				recorded.Arguments[key] = clean(value)
			}
		}
		answer.ToolCalls = append(answer.ToolCalls, recorded)
	}

	return answer
}

// Player is a provider that answers from a recording. It has no network code.
type Player struct {
	recording Recording
	next      int
}

func NewPlayer(recording Recording) (*Player, error) {
	if err := recording.Validate(); err != nil {
		return nil, err
	}

	return &Player{recording: recording}, nil
}

func (player *Player) Name() string { return "REPLAY" }

// Source says if the recording is live or scripted.
func (player *Player) Source() string { return player.recording.Source }

func (player *Player) Send(ctx context.Context, safe outbound.SafeRequest) (outbound.Response, error) {
	if err := ctx.Err(); err != nil {
		return outbound.Response{}, err
	}
	if player.next >= len(player.recording.Steps) {
		return outbound.Response{}, &outbound.ProviderError{Detail: fmt.Sprintf("replay: the recording has no answer for request %d", player.next+1)}
	}

	step := player.recording.Steps[player.next]
	if step.RequestHash != "" && step.RequestHash != Fingerprint(safe.Request()) {
		return outbound.Response{}, &outbound.ProviderError{Detail: fmt.Sprintf("replay: request %d does not match the recording", player.next+1)}
	}
	player.next++

	response := outbound.Response{Text: step.Answer.Text, TokensUsed: step.Answer.TokensUsed}
	for _, call := range step.Answer.ToolCalls {
		response.ToolCalls = append(response.ToolCalls, outbound.ToolCall{ID: call.ID, Name: call.Name, Arguments: maps(call.Arguments)})
	}

	return response, nil
}

func maps(arguments map[string]string) map[string]string {
	copied := make(map[string]string, len(arguments))
	for key, value := range arguments {
		copied[key] = value
	}

	return copied
}
