package ruledraft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kenzietann/omamori/internal/htmlreport"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/replay"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/taskrun"
)

const (
	recordingTask = "ruledraft"
	MaxAttempts   = 5
)

var (
	ErrSetup        = errors.New("the rule draft could not be prepared")
	ErrNotConfirmed = errors.New("the request for the rule draft has not been confirmed")
	ErrAlreadyRun   = errors.New("this rule draft has already run")
	ErrOutput       = errors.New("the output of the rule draft could not be saved")
	ErrRecording    = errors.New("the recording is not a recording of a rule draft")
)

// Config holds what the session needs besides the input. Sources are the paths that were read: the output
// folder must not be inside them or around them.
type Config struct {
	Provider taskrun.Config
	Sources  []string
	// Attempts is how many answers the AI may give. After a refused answer it is told the fixed reasons.
	Attempts int
}

// Result is what a run gives. Attempts holds the verdict on each answer, in order.
type Result struct {
	Version  int       `json:"version"`
	Accepted bool      `json:"accepted"`
	Reason   string    `json:"reason"`
	Attempts []Verdict `json:"attempts"`
	Requests int       `json:"requests"`
	Tokens   int       `json:"tokens"`
	Mode     string    `json:"mode"`
	SavedTo  string    `json:"-"`
	// RuleFile is the path of the accepted rule. It is empty when no rule was accepted.
	RuleFile string `json:"-"`
}

// Session freezes the input and the first request. It runs once, and only after Confirm, like every
// other run that sends something.
type Session struct {
	mutex     sync.Mutex
	confirmed bool
	started   bool
	config    Config
	prepared  *Prepared
	request   outbound.Request
	sender    *outbound.Sender
	recorder  *replay.Recorder
	mode      string
	label     string
	directory string
}

func NewSession(ctx context.Context, config Config, input Input, setup taskrun.Setup) (*Session, error) {
	if len(config.Sources) == 0 || config.Provider.OutputBase == "" {
		return nil, ErrSetup
	}
	if config.Attempts == 0 {
		config.Attempts = 3
	}
	if config.Attempts < 1 || config.Attempts > MaxAttempts {
		return nil, fmt.Errorf("%w: between 1 and %d attempts are possible", ErrSetup, MaxAttempts)
	}
	config.Sources = append([]string(nil), config.Sources...)
	if config.Provider.Now == nil {
		config.Provider.Now = time.Now
	}
	prepared, err := Prepare(input)
	if err != nil {
		return nil, err
	}
	request, err := prepared.Request()
	if err != nil {
		return nil, err
	}
	session := &Session{config: config, prepared: prepared, request: request, mode: "live"}
	session.directory = filepath.Join(config.Provider.OutputBase, "rule-"+config.Provider.Now().UTC().Format("20060102-150405"))
	for _, source := range config.Sources {
		if source == "" || pathguard.CheckOutputFolder(source, session.directory) != nil {
			return nil, fmt.Errorf("%w: the output folder must not be inside the logs or around them", ErrSetup)
		}
	}

	var provider outbound.Provider
	if setup.Recording != nil {
		encoded, err := setup.Recording.JSON()
		if err != nil {
			return nil, ErrRecording
		}
		recording, err := replay.Parse([]byte(encoded))
		if err != nil || recording.Task != recordingTask || len(recording.Steps) > MaxAttempts || recording.Log != "" || recording.Triage != nil {
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
		session.config.Attempts = len(recording.Steps)
	} else {
		resolved, err := taskrun.ResolveProvider(ctx, config.Provider, setup)
		if err != nil {
			return nil, err
		}
		session.recorder = replay.NewRecorder(resolved.Provider, recordingTask, resolved.Model, "")
		provider = session.recorder
	}
	root := config.Provider.Target
	if root == "" {
		root = config.Sources[0]
	}
	if session.sender, err = outbound.New(provider, root); err != nil {
		return nil, ErrSetup
	}

	return session, nil
}

// Preview is the first request as it would be sent, after the guard. It sends nothing and writes nothing.
func (session *Session) Preview() (outbound.Request, error) {
	return session.sender.Preview(session.request)
}

func (session *Session) ConsentText() string {
	if session.label != "" {
		return session.label + ": recorded answers are checked against the current logs. Nothing is sent to a provider."
	}

	return session.sender.ConsentText() + fmt.Sprintf(" The example events and up to %d other events of the logs are included after the filter for secrets; no tools are available to the AI. Up to %d requests are made.",
		maxContrast, session.config.Attempts)
}

func (session *Session) Label() string { return session.label }

func (session *Session) Confirm() {
	session.mutex.Lock()
	defer session.mutex.Unlock()
	if !session.started {
		session.confirmed = true
	}
}

// Run asks for a rule, checks the answer, and asks again with the fixed reasons while attempts are left.
// The report is written whether or not a rule was accepted. rule.yml is written only for an accepted rule.
func (session *Session) Run(ctx context.Context, progress func(string)) (Result, error) {
	session.mutex.Lock()
	if session.started {
		session.mutex.Unlock()
		return Result{}, ErrAlreadyRun
	}
	if !session.confirmed && session.label == "" {
		session.mutex.Unlock()
		return Result{}, ErrNotConfirmed
	}
	session.started = true
	session.sender.Authorize()
	session.mutex.Unlock()
	if progress == nil {
		progress = func(string) {}
	}

	result := Result{Version: 1, Mode: session.mode, Attempts: []Verdict{}, Reason: "no answer was received"}
	writer, err := reportwriter.NewRun(session.config.Sources, session.directory)
	if err != nil {
		return result, err
	}
	result.SavedTo = session.directory

	request := session.request
	request.Messages = append([]outbound.Message(nil), request.Messages...)
	for attempt := 1; attempt <= session.config.Attempts; attempt++ {
		if ctx.Err() != nil {
			result.Reason = "cancelled"
			break
		}
		progress(fmt.Sprintf("asking for a rule (answer %d of up to %d)", attempt, session.config.Attempts))
		response, err := session.sender.Send(ctx, request)
		result.Requests = session.sender.Attempts()
		result.Tokens += max(0, response.TokensUsed)
		if err != nil {
			result.Reason = "the provider failed, or the recording does not fit these logs and this goal"
			if ctx.Err() != nil {
				result.Reason = "cancelled"
			}
			break
		}
		if len(response.ToolCalls) != 0 {
			result.Reason = "the AI asked for tools; a rule draft permits no tools"
			break
		}
		if limit := session.config.Provider.Limits.MaxTokens; limit > 0 && result.Tokens > limit {
			result.Reason = "the reported token usage exceeded the limit"
			break
		}
		progress("checking the rule against the examples, the logs and days without an attack")
		text := CleanAnswer(response.Text)
		verdict := session.prepared.Check(text)
		result.Attempts = append(result.Attempts, verdict)
		if verdict.Accepted {
			result.Accepted, result.Reason = true, fmt.Sprintf("the rule was accepted on answer %d", attempt)
			break
		}
		result.Reason = fmt.Sprintf("no rule was accepted in %d answers", attempt)
		// The next request holds the refused answer and the fixed reasons. The sender filters both again.
		request.Messages = append(request.Messages, outbound.Message{Role: "assistant", Text: text}, outbound.Message{Role: "user", Text: Feedback(verdict)})
	}

	if err := session.save(writer, &result); err != nil {
		return result, err
	}
	progress(result.Reason)

	return result, nil
}

func (session *Session) save(writer *reportwriter.Writer, result *Result) error {
	report := session.markdown(*result)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return ErrOutput
	}
	files := []struct{ name, content string }{{"report.md", report}, {"report.html", htmlreport.Render(report)}, {"draft.json", string(data) + "\n"}}
	if result.Accepted {
		files = append(files, struct{ name, content string }{"rule.yml", result.Attempts[len(result.Attempts)-1].Rule})
		result.RuleFile = filepath.Join(session.directory, "rule.yml")
	}
	if session.recorder != nil {
		if recording := session.recorder.Recording(); len(recording.Steps) > 0 {
			if text, err := recording.JSON(); err == nil {
				files = append(files, struct{ name, content string }{"recording.json", text})
			}
		}
	}
	for _, file := range files {
		if err := writer.Write(file.name, file.content); err != nil {
			return ErrOutput
		}
	}

	return nil
}

// markdown is the report of a draft. It is made of fixed words, numbers, references of events and the
// accepted rule. A refused answer of the AI is not shown: only the reasons for the refusal are.
func (session *Session) markdown(result Result) string {
	var out strings.Builder
	input := session.prepared.input
	if session.label != "" {
		out.WriteString("**" + session.label + ": recorded answers were checked. Nothing was sent to a provider.**\n\n")
	}
	out.WriteString("# Omamori rule draft\n\n")
	state := "No rule was accepted. No rule file was written."
	if result.Accepted {
		state = "A rule was accepted and saved as rule.yml."
	}
	fmt.Fprintf(&out, "- %s\n- Goal given by the user: %s\n- Examples: %d events. Answers of the AI: %d. Requests: %d.\n", state, input.Goal, len(session.prepared.examples), len(result.Attempts), result.Requests)
	out.WriteString("- The AI wrote the log source, the detection and tests. The title, the level and the description come from the user and from Omamori.\n\n")

	out.WriteString("## Checks\n\n| Answer | Result | Examples matched | Matches in the logs | Matches on built-in days without an attack | Matches in logs given as clean |\n|---|---|---|---|---|---|\n")
	for number, verdict := range result.Attempts {
		outcome := "refused"
		if verdict.Accepted {
			outcome = "accepted"
		}
		fmt.Fprintf(&out, "| %d | %s | %d of %d | %d of %d | %d of %d | %d of %d |\n", number+1, outcome, verdict.ExamplesMatched, verdict.Examples,
			verdict.LogMatches, verdict.LogEvents, verdict.BuiltinMatches, verdict.BuiltinEvents, verdict.BenignMatches, verdict.BenignEvents)
	}
	out.WriteString("\n")
	for number, verdict := range result.Attempts {
		if len(verdict.Reasons) == 0 {
			continue
		}
		fmt.Fprintf(&out, "Answer %d was refused:\n\n", number+1)
		for _, reason := range verdict.Reasons {
			out.WriteString("- " + oneLine(reason, 300) + "\n")
		}
		out.WriteString("\n")
	}

	if result.Accepted {
		accepted := result.Attempts[len(result.Attempts)-1]
		out.WriteString("## What the rule matches in the logs\n\n")
		fmt.Fprintf(&out, "%d events. Read them before you use the rule: the examples are among them, and the others are what the rule finds beyond the examples.\n\n", accepted.LogMatches)
		for _, ref := range accepted.MatchedRefs {
			out.WriteString("- " + oneLine(ref, 100) + "\n")
		}
		if accepted.LogMatches > len(accepted.MatchedRefs) {
			fmt.Fprintf(&out, "- and %d more\n", accepted.LogMatches-len(accepted.MatchedRefs))
		}
		out.WriteString("\n## The rule\n\n")
		for _, line := range strings.Split(strings.TrimRight(accepted.Rule, "\n"), "\n") {
			out.WriteString("    " + line + "\n")
		}
		out.WriteString("\nTo use it, put rule.yml into a folder of rules and give that folder with --rules.\n\n")
	}

	out.WriteString("## Limits\n\n")
	out.WriteString("- Accepted means: it loads, its tests pass, it matches every example, it is silent on the built-in synthetic days without an attack, and it is not too broad on the given logs. It does not mean that the rule is right for your network.\n")
	out.WriteString("- The built-in days are made up and small. A rule can be silent on them and still be noisy on real logs. Give logs that you know to be clean with --benign.\n")
	out.WriteString("- A rule that matches the examples can miss the next variant of the same attack. Read the detection.\n")
	out.WriteString("- Only one detection rule is drafted. Counting and sequences (correlations) are written by hand.\n")

	return out.String()
}
