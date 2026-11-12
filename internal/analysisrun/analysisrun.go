package analysisrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kenzietann/omamori/internal/analyst"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/eventlog"
	"github.com/kenzietann/omamori/internal/htmlreport"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/replay"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/runstore"
	"github.com/kenzietann/omamori/internal/sanitizer"
	"github.com/kenzietann/omamori/internal/store"
	"github.com/kenzietann/omamori/internal/taskrun"
)

var (
	ErrSetup        = errors.New("the alert analyst could not be prepared")
	ErrNotConfirmed = errors.New("the sanitized alert review has not been confirmed")
	ErrAlreadyRun   = errors.New("this alert review has already run")
	ErrOutput       = errors.New("the analysis output could not be saved")
	ErrRecording    = errors.New("the recording is not an alert analyst recording")
)

const (
	StatusComplete   = "complete"
	StatusIncomplete = "incomplete"
)

// Config holds shared provider dependencies and output settings plus every original input path.
// Provider.Limits.MaxTokens, when positive, rejects an answer whose reported token usage exceeds it.
// It is a post-response acceptance limit, not a strict provider spending limit. One request may retry.
type Config struct {
	Provider taskrun.Config
	Sources  []string
	Store runstore.Writer
	Base Base
}

type Base struct {
	Report string
	Files map[string]string
	Prefix string
}

var reservedFiles = []string{"report.md", "report.html", "alerts.json", "analysis.json", "events.jsonl", "recording.json"}

type Progress struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
	Attempt int    `json:"attempt,omitempty"`
}

type Result struct {
	Version         int            `json:"version"`
	Analysis        analyst.Result `json:"analysis"`
	Complete        bool           `json:"complete"`
	Status          string         `json:"status"`
	Reason          string         `json:"reason,omitempty"`
	Requests        int            `json:"requests"`
	Tokens          int            `json:"tokens"`
	Mode            string         `json:"mode"`
	RecordingStatus string         `json:"recording_status"`
	SavedTo         string         `json:"-"`
	RunID           string         `json:"run_id,omitempty"`
}

type Session struct {
	mutex       sync.Mutex
	confirmed   bool
	started     bool
	config      Config
	snapshot    analyst.Snapshot
	request     outbound.Request
	sender      *outbound.Sender
	recorder    *replay.Recorder
	mode        string
	label       string
	directory   string
	baseReport  string
	baseAlerts  string
	noAlerts    bool
	storedInput *store.RunInput
	extraFiles  []extraFile
}

type extraFile struct{ name, content string }

// Prepare reads no additional logs, writes no files, and makes no provider requests.
// The detection result is rendered now so later caller mutation cannot change the reviewed evidence.
func Prepare(ctx context.Context, config Config, outcome detect.Outcome, setup taskrun.Setup) (*Session, error) {
	if len(config.Sources) == 0 || config.Provider.OutputBase == "" {
		return nil, ErrSetup
	}
	config.Sources = append([]string(nil), config.Sources...)
	if config.Provider.Now == nil {
		config.Provider.Now = time.Now
	}
	snapshot, err := analyst.BuildSnapshot(outcome)
	if err != nil {
		return nil, err
	}
	request, err := analyst.Request(snapshot)
	if err != nil {
		return nil, err
	}
	alerts, err := detect.JSON(outcome)
	if err != nil {
		return nil, ErrSetup
	}
	report, prefix := config.Base.Report, config.Base.Prefix
	if report == "" {
		report = detect.Markdown(outcome)
	}
	if prefix == "" {
		prefix = "analyze"
	}
	session := &Session{
		config: config, snapshot: snapshot, request: request, baseReport: report, baseAlerts: alerts,
		mode: "live", noAlerts: snapshot.Coverage.TotalAlerts == 0 && setup.Recording == nil,
	}
	for name, content := range config.Base.Files {
		if slices.Contains(reservedFiles, name) {
			return nil, ErrSetup
		}
		session.extraFiles = append(session.extraFiles, extraFile{name, content})
	}
	sort.Slice(session.extraFiles, func(first, second int) bool { return session.extraFiles[first].name < session.extraFiles[second].name })
	session.config.Base = Base{}
	if config.Store != nil {
		input, err := runstore.Build(outcome, nil)
		if err != nil {
			return nil, err
		}
		session.storedInput = &input
	}
	session.directory = filepath.Join(config.Provider.OutputBase, prefix+"-"+config.Provider.Now().UTC().Format("20060102-150405"))
	for _, source := range config.Sources {
		if source == "" {
			return nil, ErrSetup
		}
		if err := pathguard.CheckOutputFolder(source, session.directory); err != nil {
			return nil, err
		}
	}
	if session.noAlerts {
		session.mode = "local"
		return session, nil
	}

	var provider outbound.Provider
	if setup.Recording != nil {
		encoded, err := setup.Recording.JSON()
		if err != nil {
			return nil, ErrRecording
		}
		recording, err := replay.Parse([]byte(encoded))
		if err != nil {
			return nil, ErrRecording
		}
		if recording.Task != "analyst" || len(recording.Steps) != 1 || recording.Log != "" || recording.Triage != nil {
			return nil, ErrRecording
		}
		player, err := replay.NewPlayer(recording)
		if err != nil {
			return nil, ErrRecording
		}
		provider = player
		session.mode, session.label = "replay", "REPLAY"
		if recording.Source == replay.SourceScripted {
			session.mode, session.label = "scripted_replay", "REPLAY (scripted answers)"
		}
	} else {
		resolved, err := taskrun.ResolveProvider(ctx, config.Provider, setup)
		if err != nil {
			return nil, err
		}
		session.recorder = replay.NewRecorder(resolved.Provider, "analyst", resolved.Model, "")
		provider = session.recorder
	}
	root := config.Provider.Target
	if root == "" {
		root = config.Sources[0]
	}
	session.sender, err = outbound.New(provider, root)
	if err != nil {
		return nil, ErrSetup
	}
	return session, nil
}

func (session *Session) Preview() (outbound.Request, error) {
	if session.noAlerts {
		return outbound.Request{System: "No alerts were detected. No AI request will be sent."}, nil
	}
	return session.sender.Preview(session.request)
}

func (session *Session) ConsentText() string {
	if session.noAlerts {
		return "No alerts were detected. Nothing will be sent to an AI provider."
	}
	if session.label != "" {
		return session.label + ": recorded answers are checked against the current alert evidence. Nothing is sent to a provider."
	}
	return session.sender.ConsentText() + " Only the bounded alert evidence is included; no tools are available to the AI."
}

func (session *Session) Label() string { return session.label }

func (session *Session) Confirm() {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if !session.started {
		session.confirmed = true
	}
}

// Run makes one guarded request (with the sender's bounded transient retries), checks its structured
// claims, and saves the deterministic findings even when the AI fails. Replay never creates a provider.
func (session *Session) Run(ctx context.Context, progress func(Progress)) (Result, error) {
	session.mutex.Lock()
	if session.started {
		session.mutex.Unlock()
		return Result{}, ErrAlreadyRun
	}
	if !session.confirmed && !session.noAlerts && session.label == "" {
		session.mutex.Unlock()
		return Result{}, ErrNotConfirmed
	}
	session.started = true
	if session.sender != nil {
		session.sender.Authorize()
	}
	session.mutex.Unlock()
	if progress == nil {
		progress = func(Progress) {}
	}
	result := Result{Version: 1, Analysis: analyst.NotRun(session.snapshot), Status: StatusIncomplete, Mode: session.mode}
	writer, err := reportwriter.NewRun(session.config.Sources, session.directory)
	if err != nil {
		return result, err
	}
	result.SavedTo = session.directory
	appender, err := writer.Open("events.jsonl")
	if err != nil {
		return result, ErrOutput
	}
	log := eventlog.New(appender, session.config.Provider.Now)
	if err := log.Record("analysis_start", "", true, "started", session.mode); err != nil {
		result.Reason = "event logging failed"
	} else if session.noAlerts {
		result.Analysis = analyst.Check(session.snapshot, `{"claims":[]}`)
		result.Status, result.Complete, result.Reason = StatusComplete, true, "no alerts; no AI request was needed"
		if result.Analysis.Status != analyst.StatusComplete {
			result.Status, result.Complete, result.Reason = StatusIncomplete, false, "no alerts; rule evaluation was incomplete and no AI request was needed"
		}
	} else if ctx.Err() != nil {
		result.Reason = "cancelled"
	} else {
		session.review(ctx, log, progress, &result)
	}
	session.saveRecording(writer, &result)
	if err := log.Record("analysis_end", "", result.Complete, result.Status, result.Reason); err != nil {
		result.Status, result.Complete, result.Reason = StatusIncomplete, false, "event logging failed"
	}
	if err := log.Close(); err != nil {
		result.Status, result.Complete, result.Reason = StatusIncomplete, false, "event logging failed"
	}
	if session.config.Store != nil {
		progress(Progress{Stage: "storing", Message: "saving the sanitized run for search and cases"})
		analysis := &runstore.Analysis{Version: result.Version, Analysis: result.Analysis, Complete: result.Complete,
			Status: result.Status, Reason: result.Reason, Requests: result.Requests, Tokens: result.Tokens,
			Mode: result.Mode, RecordingStatus: result.RecordingStatus}
		input, buildErr := runstore.WithAnalysis(*session.storedInput, analysis)
		var saved store.Run
		var saveErr error
		if buildErr == nil {
			saved, saveErr = session.config.Store.SaveRun(ctx, input)
		}
		if buildErr != nil || saveErr != nil {
			result.Status, result.Complete = StatusIncomplete, false
			result.Reason += "; the sanitized run could not be stored"
		} else {
			result.RunID = saved.ID
		}
	}
	progress(Progress{Stage: "saving", Message: "saving detection findings and checked analysis"})
	if err := session.save(writer, result); err != nil {
		return result, err
	}
	progress(Progress{Stage: result.Status, Message: result.Reason, Attempt: result.Requests})
	return result, nil
}

func (session *Session) review(ctx context.Context, log *eventlog.Log, progress func(Progress), result *Result) {
	attempt := 0
	session.sender.Observe(func(request outbound.Request) error {
		attempt++
		progress(Progress{Stage: "sending", Message: "reviewing the sanitized alert evidence", Attempt: attempt})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return log.Record("provider_request", "", true, "prepared", fmt.Sprintf("attempt %d; %d messages; %d tools", attempt, len(request.Messages), len(request.Tools)))
	})
	response, err := session.sender.Send(ctx, session.request)
	result.Requests = session.sender.Attempts()
	result.Tokens = max(0, response.TokensUsed)
	if err != nil {
		if ctx.Err() != nil {
			result.Reason = "cancelled"
		} else {
			result.Reason = failureReason(err)
		}
		return
	}
	if ctx.Err() != nil {
		result.Reason = "cancelled"
		return
	}
	if err := log.Record("provider_response", "", true, "received", fmt.Sprintf("%d tokens reported", result.Tokens)); err != nil {
		result.Reason = "event logging failed"
		return
	}
	if len(response.ToolCalls) != 0 {
		result.Reason = "the AI requested tools; this review permits no tools"
		return
	}
	if response.TokensUsed < 0 {
		result.Reason = "the provider returned invalid usage information"
		return
	}
	if limit := session.config.Provider.Limits.MaxTokens; limit > 0 && response.TokensUsed > limit {
		result.Reason = "the reported token usage exceeded the acceptance limit"
		return
	}
	progress(Progress{Stage: "checking", Message: "checking AI claims against alert evidence"})
	result.Analysis = analyst.Check(session.snapshot, response.Text)
	switch result.Analysis.Status {
	case analyst.StatusComplete:
		result.Status, result.Complete, result.Reason = StatusComplete, true, "all included alerts were reviewed with verified claims"
	case analyst.StatusPartial:
		result.Reason = "some claims were rejected or some alerts were not reviewed"
	default:
		result.Reason = "the AI did not return a valid structured review"
	}
}

func failureReason(err error) string {
	switch {
	case errors.Is(err, outbound.ErrCancelled), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled"
	case errors.Is(err, outbound.ErrLogFailed):
		return "event logging failed"
	case errors.Is(err, outbound.ErrAuth):
		return "the provider rejected the API key"
	case errors.Is(err, outbound.ErrRefused):
		return "the provider declined the request"
	case errors.Is(err, outbound.ErrInvalidRequest), errors.Is(err, outbound.ErrUnsafeRequest):
		return "the request could not pass the outbound guard"
	default:
		return "the provider failed or the replay did not match the alert evidence"
	}
}

func (session *Session) save(writer *reportwriter.Writer, result Result) error {
	report := strings.Replace(session.baseReport,
		"- No AI was used for this report. Every alert comes from a rule, and the lines that made it fire are listed.",
		"- Detection findings come from local rules. The checked AI review is shown separately below.", 1)
	if session.label != "" {
		report = "**" + session.label + ": recorded answers were checked. Nothing was sent to a provider.**\n\n" + report
	}
	report += "\n## Analysis run\n\nStatus: " + result.Status + "\n\n" + result.Reason + ".\n\n" + analyst.Markdown(result.Analysis)
	// Rule titles and filenames can also contain supported sensitive data.
	report, _ = (&sanitizer.Sanitizer{}).Sanitize(report)
	analysis, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return ErrOutput
	}
	alerts, err := sanitizeJSON(session.baseAlerts)
	if err != nil {
		return ErrOutput
	}
	// The added files are written as they were given: a manifest must stay byte for byte what its hash was made of.
	files := append([]extraFile{
		{"report.md", report}, {"report.html", htmlreport.Render(report)}, {"alerts.json", alerts}, {"analysis.json", string(analysis) + "\n"},
	}, session.extraFiles...)
	for _, file := range files {
		if err := writer.Write(file.name, file.content); err != nil {
			return ErrOutput
		}
	}
	return nil
}

func (session *Session) saveRecording(writer *reportwriter.Writer, result *Result) {
	result.RecordingStatus = "none"
	if session.label != "" {
		result.RecordingStatus = "replayed"
	}
	if session.recorder == nil {
		return
	}
	recording := session.recorder.Recording()
	if len(recording.Steps) == 0 {
		return
	}
	text, err := recording.JSON()
	if err == nil {
		err = writer.Write("recording.json", text)
	}
	if err == nil {
		result.RecordingStatus = "saved"
		return
	}
	// An unusable model answer must not turn already checked local evidence into an output failure.
	result.Status, result.Complete, result.RecordingStatus = StatusIncomplete, false, "unavailable"
	result.Reason += "; the AI response could not be recorded"
}

// sanitizeJSON keeps the machine-readable detection schema intact while cleaning text originating
// in custom rule metadata too. Each string gets its own sanitizer, so map iteration cannot affect it.
func sanitizeJSON(text string) (string, error) {
	var document any
	if err := json.Unmarshal([]byte(text), &document); err != nil {
		return "", err
	}
	var walk func(any) any
	walk = func(value any) any {
		switch typed := value.(type) {
		case string:
			cleaned, _ := (&sanitizer.Sanitizer{}).Sanitize(typed)
			return cleaned
		case []any:
			for index := range typed {
				typed[index] = walk(typed[index])
			}
		case map[string]any:
			cleaned := make(map[string]any, len(typed))
			for key, item := range typed {
				cleaned[walk(key).(string)] = walk(item)
			}
			return cleaned
		}
		return value
	}
	data, err := json.MarshalIndent(walk(document), "", "  ")
	return string(data) + "\n", err
}
