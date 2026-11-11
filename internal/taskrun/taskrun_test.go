package taskrun

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/agent"
	"github.com/kenzietann/omamori/internal/outbound"
)

const (
	fixtureDirectory = "../../testdata/fixtures/exposure"
	testKey          = "sk-ant-api03-FAKEKEYFAKEKEYFAKEKEYFAKEKEY"
)

var plantedValues = []string{
	"AKIAIOSFODNN7EXAMPLE",
	"ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1",
	"123123123128",
	"090-1234-5678",
	"080-9876-5432",
}

type reply struct {
	response outbound.Response
	err      error
}

type scriptedProvider struct {
	replies  []reply
	recorded []outbound.Request
	onSend   func(index int)
}

func (provider *scriptedProvider) Name() string { return "FakeAI" }

func (provider *scriptedProvider) Send(ctx context.Context, safe outbound.SafeRequest) (outbound.Response, error) {
	index := len(provider.recorded)
	provider.recorded = append(provider.recorded, safe.Request())
	if provider.onSend != nil {
		provider.onSend(index)
	}
	if index >= len(provider.replies) {
		return outbound.Response{Text: "done"}, nil
	}

	return provider.replies[index].response, provider.replies[index].err
}

func scanAll() reply {
	return reply{response: outbound.Response{ToolCalls: []outbound.ToolCall{{ID: "call_1", Name: "run_detectors", Arguments: map[string]string{"path": "."}}}, TokensUsed: 50}}
}

func answerText(text string) reply {
	return reply{response: outbound.Response{Text: text, TokensUsed: 20}}
}

type factoryCall struct {
	id, key, model, reasoning string
}

type testSetup struct {
	config   Config
	provider *scriptedProvider
	calls    *[]factoryCall
	project  string
	output   string
}

func fixtureProject(t testing.TB) string {
	t.Helper()

	project, err := filepath.Abs(filepath.Join(fixtureDirectory, "project"))
	if err != nil {
		t.Fatal(err)
	}

	return project
}

func newSetup(t testing.TB, replies ...reply) testSetup {
	t.Helper()

	provider := &scriptedProvider{replies: replies}
	calls := &[]factoryCall{}
	project := fixtureProject(t)
	output := filepath.Join(t.TempDir(), "out")

	environment := map[string]string{}
	return testSetup{
		config: Config{
			Target:     project,
			OutputBase: output,
			Limits:     agent.Limits{MaxSteps: 10, MaxTokens: 100000},
			LookupEnv:  func(name string) string { return environment[name] },
			Now:        func() time.Time { return time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC) },
			NewProvider: func(id, key, model, reasoning string) (outbound.Provider, error) {
				*calls = append(*calls, factoryCall{id, key, model, reasoning})
				return provider, nil
			},
		},
		provider: provider, calls: calls, project: project, output: output,
	}
}

func (setup testSetup) session(t testing.TB) *Session {
	t.Helper()

	session, err := Prepare(setup.config, Setup{ProviderID: "anthropic", Key: testKey})
	if err != nil {
		t.Fatal(err)
	}

	return session
}

func hashTree(t testing.TB, root string) map[string][32]byte {
	t.Helper()

	hashes := make(map[string][32]byte)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			hashes[path+"/"] = [32]byte{}
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hashes[path] = sha256.Sum256(content)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return hashes
}

func outputFiles(t testing.TB, root string) map[string]string {
	t.Helper()

	files := make(map[string]string)
	filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		relative, _ := filepath.Rel(root, path)
		files[relative] = string(content)

		return nil
	})

	return files
}

func assertNoSecrets(t testing.TB, where string, text string, project string) {
	t.Helper()

	for _, secret := range append(slices.Clone(plantedValues), project, testKey) {
		if strings.Contains(text, secret) {
			t.Errorf("%s contains %q", where, secret)
		}
	}
}

func TestProvidersTellWhichKeysAreInTheEnvironment(t *testing.T) {
	setup := newSetup(t)
	setup.config.LookupEnv = func(name string) string {
		return map[string]string{"OPENAI_API_KEY": "sk-x", "MISTRAL_API_KEY": ""}[name]
	}

	byID := map[string]Choice{}
	for _, choice := range setup.config.Providers() {
		byID[choice.ID] = choice
	}

	if len(byID) != len(outbound.Providers()) {
		t.Fatalf("%d providers, want %d", len(byID), len(outbound.Providers()))
	}
	if !byID["openai"].KeyFound || byID["mistral"].KeyFound || byID["anthropic"].KeyFound {
		t.Errorf("key status is wrong: %+v", byID)
	}
	if byID["ollama"].KeyFound || !byID["ollama"].Local || byID["anthropic"].DefaultModel != "claude-opus-5-5" || byID["openai"].DefaultModel != "" {
		t.Errorf("provider details are wrong: %+v", byID)
	}
}

func TestPrepareChecksTheSetup(t *testing.T) {
	testCases := []struct {
		name      string
		setup     Setup
		env       map[string]string
		target    string
		factory   func(id, key, model, reasoning string) (outbound.Provider, error)
		wantErr   error
		wantCall  factoryCall
		wantCalls int
	}{
		{"a key that is typed", Setup{ProviderID: "anthropic", Key: testKey}, nil, "", nil, nil, factoryCall{"anthropic", testKey, "claude-opus-5-5", ""}, 1},
		{"a key from the environment", Setup{ProviderID: "anthropic"}, map[string]string{"ANTHROPIC_API_KEY": testKey}, "", nil, nil, factoryCall{"anthropic", testKey, "claude-opus-5-5", ""}, 1},
		{"a typed key beats the environment", Setup{ProviderID: "anthropic", Key: testKey}, map[string]string{"ANTHROPIC_API_KEY": "sk-other"}, "", nil, nil, factoryCall{"anthropic", testKey, "claude-opus-5-5", ""}, 1},
		{"white space around the key is removed", Setup{ProviderID: "anthropic", Key: "  " + testKey + "\n"}, nil, "", nil, nil, factoryCall{"anthropic", testKey, "claude-opus-5-5", ""}, 1},
		{"a chosen model beats the default", Setup{ProviderID: "anthropic", Key: testKey, Model: " claude-sonnet-5-5 "}, nil, "", nil, nil, factoryCall{"anthropic", testKey, "claude-sonnet-5-5", ""}, 1},
		{"no key", Setup{ProviderID: "anthropic"}, nil, "", nil, ErrNeedsKey, factoryCall{}, 0},
		{"a key of only spaces", Setup{ProviderID: "anthropic", Key: "   "}, nil, "", nil, ErrNeedsKey, factoryCall{}, 0},
		{"a provider without a default model", Setup{ProviderID: "openai", Key: testKey}, nil, "", nil, ErrNeedsModel, factoryCall{}, 0},
		{"a provider with a model", Setup{ProviderID: "openai", Key: testKey, Model: "a-model"}, nil, "", nil, nil, factoryCall{"openai", testKey, "a-model", ""}, 1},
		{"a local provider needs no key and ignores one", Setup{ProviderID: "ollama", Model: "llama", Key: testKey}, nil, "", nil, nil, factoryCall{"ollama", "", "llama", ""}, 1},
		{"a local provider still needs a model", Setup{ProviderID: "ollama"}, nil, "", nil, ErrNeedsModel, factoryCall{}, 0},
		{"an unknown provider", Setup{ProviderID: "nope", Key: testKey, Model: "m"}, nil, "", nil, ErrUnknownProvider, factoryCall{}, 0},
		{"no provider", Setup{Key: testKey, Model: "m"}, nil, "", nil, ErrUnknownProvider, factoryCall{}, 0},
		{"a folder that is not there", Setup{ProviderID: "anthropic", Key: testKey}, nil, "/no/such/folder/anywhere", nil, ErrTarget, factoryCall{}, 0},
		{"a provider that cannot be built", Setup{ProviderID: "anthropic", Key: testKey}, nil, "",
			func(id, key, model, reasoning string) (outbound.Provider, error) {
				return nil, errors.New("boom " + key)
			}, ErrSetup, factoryCall{}, 0},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			setup := newSetup(t)
			environment := testCase.env
			setup.config.LookupEnv = func(name string) string { return environment[name] }
			if testCase.target != "" {
				setup.config.Target = testCase.target
			}
			if testCase.factory != nil {
				setup.config.NewProvider = testCase.factory
			}

			session, err := Prepare(setup.config, testCase.setup)

			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("err = %v, want %v", err, testCase.wantErr)
			}
			if err != nil {
				if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), "boom") {
					t.Errorf("the error shows more than its fixed text: %v", err)
				}
			} else if session == nil {
				t.Error("no session")
			}
			if len(*setup.calls) != testCase.wantCalls || (testCase.wantCalls == 1 && (*setup.calls)[0] != testCase.wantCall) {
				t.Errorf("factory calls = %+v, want %d call %+v", *setup.calls, testCase.wantCalls, testCase.wantCall)
			}
		})
	}
}

func TestPrepareAndPreviewSendNothingAndCreateNothing(t *testing.T) {
	setup := newSetup(t)
	before := hashTree(t, setup.project)

	session := setup.session(t)
	preview, err := session.Preview()
	if err != nil {
		t.Fatal(err)
	}

	if len(setup.provider.recorded) != 0 {
		t.Errorf("the provider received %d requests", len(setup.provider.recorded))
	}
	if _, err := os.Stat(setup.output); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the output folder exists before the user confirmed: %v", err)
	}
	if !slices.Equal(hashKeys(before), hashKeys(hashTree(t, setup.project))) {
		t.Error("the project changed")
	}

	if want := "Omamori will send sanitized content to FakeAI during this run."; session.ConsentText() != want {
		t.Errorf("ConsentText() = %q, want %q", session.ConsentText(), want)
	}
	for _, want := range []string{"first request", "up to 10 requests and 100000 tokens", "System prompt:", "Message (user):", "Check this project for exposed secrets", "read_file", "list_dir", "run_detectors", "search_text", "all read-only"} {
		if !strings.Contains(preview, want) {
			t.Errorf("the preview has no %q:\n%s", want, preview)
		}
	}
	assertNoSecrets(t, "the preview", preview, setup.project)
}

func hashKeys(hashes map[string][32]byte) []string {
	keys := make([]string, 0, len(hashes))
	for key := range hashes {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	return keys
}

func TestThePreviewShowsWhatWouldBeSentNotWhatTheUserTyped(t *testing.T) {
	setup := newSetup(t)
	session := setup.session(t)
	session.Confirm()

	preview, err := session.Preview()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Run(context.Background(), func(string) {}); err != nil {
		t.Fatal(err)
	}

	first := setup.provider.recorded[0]
	if !strings.Contains(preview, first.System) || !strings.Contains(preview, first.Messages[0].Text) {
		t.Errorf("the dry run is not the first request:\n%s", preview)
	}
	for _, spec := range first.Tools {
		if !strings.Contains(preview, "- "+spec.Name+": "+spec.Description) {
			t.Errorf("the dry run does not show the tool %s", spec.Name)
		}
	}
}

func TestNothingRunsWithoutConfirmation(t *testing.T) {
	setup := newSetup(t, scanAll())
	session := setup.session(t)

	_, err := session.Run(context.Background(), func(string) {})

	if !errors.Is(err, ErrNotConfirmed) || len(setup.provider.recorded) != 0 {
		t.Errorf("err = %v, provider calls = %d, want ErrNotConfirmed and nothing sent", err, len(setup.provider.recorded))
	}
	if _, statErr := os.Stat(setup.output); !errors.Is(statErr, fs.ErrNotExist) {
		t.Error("an output folder was created without confirmation")
	}
}

func TestAFullRunWritesTheReportAndTheLogAndNothingElse(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("I found 5 problems."))
	before := hashTree(t, setup.project)
	session := setup.session(t)
	session.Confirm()

	var steps []string
	result, err := session.Run(context.Background(), func(text string) { steps = append(steps, text) })
	if err != nil {
		t.Fatal(err)
	}

	wantDirectory := filepath.Join(setup.output, "run-20261112-093000")
	if !result.Complete || result.SavedTo != wantDirectory {
		t.Errorf("result = complete %v, saved to %q, want complete and %q", result.Complete, result.SavedTo, wantDirectory)
	}

	files := outputFiles(t, setup.output)
	page := files[filepath.Join("run-20261112-093000", "report.html")]
	if !strings.HasPrefix(page, "<!doctype html>") || !strings.Contains(page, "[SECRET:aws-access-key:001]") || strings.Contains(page, "<script") {
		t.Errorf("report.html is wrong:\n%s", page)
	}
	if len(files) != 4 || files[filepath.Join("run-20261112-093000", "report.md")] != result.Report || files[filepath.Join("run-20261112-093000", "events.jsonl")] == "" || files[filepath.Join("run-20261112-093000", "recording.json")] == "" {
		t.Fatalf("the output files are %v, want exactly report.md (the same as the result), report.html, events.jsonl and recording.json", slices.Sorted(mapKeys(files)))
	}

	expected, err := os.ReadFile(filepath.Join(fixtureDirectory, "expected_findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wantFindings []struct {
		File        string `json:"file"`
		Line        int    `json:"line"`
		Placeholder string `json:"placeholder"`
	}
	if err := json.Unmarshal(expected, &wantFindings); err != nil {
		t.Fatal(err)
	}
	for _, finding := range wantFindings {
		if want := fmt.Sprintf("%s:%d %s", finding.File, finding.Line, finding.Placeholder); !strings.Contains(result.Report, want) {
			t.Errorf("the report has no %q", want)
		}
	}
	if !strings.Contains(result.Report, "Status: complete") {
		t.Error("the report does not say complete")
	}

	for name, content := range files {
		assertNoSecrets(t, name, content, setup.project)
	}
	for index, request := range setup.provider.recorded {
		encoded, _ := json.Marshal(request)
		assertNoSecrets(t, fmt.Sprintf("request %d", index), string(encoded), setup.project)
	}
	for _, step := range steps {
		assertNoSecrets(t, "a step", step, setup.project)
	}
	if !slices.Equal(hashKeys(before), hashKeys(hashTree(t, setup.project))) {
		t.Error("the project changed")
	}
	if after := hashTree(t, setup.project); !equalHashes(before, after) {
		t.Error("a file in the project changed")
	}

	for _, want := range []string{"run started", "sending request 1 to FakeAI", "tool run_detectors: ok", "sending request 2 to FakeAI", "answer received", "run finished: finished", "report saved"} {
		if !slices.ContainsFunc(steps, func(step string) bool { return strings.Contains(step, want) }) {
			t.Errorf("no step says %q, steps: %v", want, steps)
		}
	}
}

func mapKeys[V any](items map[string]V) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		for key := range items {
			if !yield(key) {
				return
			}
		}
	}
}

func equalHashes(first, second map[string][32]byte) bool {
	if len(first) != len(second) {
		return false
	}
	for key, value := range first {
		if second[key] != value {
			return false
		}
	}

	return true
}

func TestEveryRequestIsInTheEventLog(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("done"))
	session := setup.session(t)
	session.Confirm()

	result, err := session.Run(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(filepath.Join(result.SavedTo, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var kinds []string
	var requestNotes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry struct {
			Kind string `json:"kind"`
			Note string `json:"note"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("a log line is not JSON: %v", err)
		}
		kinds = append(kinds, entry.Kind)
		if entry.Kind == "provider_request" {
			requestNotes = append(requestNotes, entry.Note)
		}
	}

	want := []string{"run_start", "provider_request", "provider_response", "tool_call", "provider_request", "provider_response", "run_end"}
	if !slices.Equal(kinds, want) {
		t.Errorf("log kinds = %v, want %v", kinds, want)
	}
	if len(requestNotes) != len(setup.provider.recorded) || len(requestNotes) != 2 {
		t.Fatalf("%d requests are logged and the provider received %d, want 2 and 2", len(requestNotes), len(setup.provider.recorded))
	}
	if !strings.Contains(requestNotes[0], "request 1: 1 messages, 4 tools") || !strings.Contains(requestNotes[0], "[user] Check this project") {
		t.Errorf("the first request is not described well: %s", requestNotes[0])
	}
	if strings.Contains(requestNotes[1], "[user]") {
		t.Errorf("the second request repeats the first message instead of showing only the newest turn: %s", requestNotes[1])
	}
	if !strings.Contains(requestNotes[1], "request 2") || !strings.Contains(requestNotes[1], "(calls run_detectors)") || !strings.Contains(requestNotes[1], "[tool] tool_result run_detectors") || !strings.Contains(requestNotes[1], "[SECRET:aws-access-key:") {
		t.Errorf("the second request does not show the newest turn: %s", requestNotes[1])
	}
}

func TestEveryRunHasItsOwnFolderAndNothingIsOverwritten(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("first"))
	first := setup.session(t)
	first.Confirm()
	firstResult, err := first.Run(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	reportBefore := outputFiles(t, setup.output)

	// The same second: the folder name is the same, so the writer must refuse and keep the first run.
	second := setup.session(t)
	second.Confirm()
	if _, err := second.Run(context.Background(), func(string) {}); !errors.Is(err, ErrOutput) {
		t.Errorf("a second run in the same folder: err = %v, want ErrOutput", err)
	}
	if after := outputFiles(t, setup.output); fmt.Sprint(after) != fmt.Sprint(reportBefore) {
		t.Error("the first run's files were changed")
	}

	later := newSetup(t)
	later.config.OutputBase = setup.output
	later.config.Now = func() time.Time { return time.Date(2026, 11, 12, 9, 30, 1, 0, time.UTC) }
	third := later.session(t)
	third.Confirm()
	thirdResult, err := third.Run(context.Background(), func(string) {})
	if err != nil || thirdResult.SavedTo == firstResult.SavedTo {
		t.Errorf("a later run: err = %v, saved to %q, want a different folder than %q", err, thirdResult.SavedTo, firstResult.SavedTo)
	}
}

func copyTree(t testing.TB, from, to string) {
	t.Helper()

	err := filepath.WalkDir(from, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, _ := filepath.Rel(from, path)
		target := filepath.Join(to, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(target, content, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAnOutputFolderInsideTheProjectIsRefused(t *testing.T) {
	setup := newSetup(t, scanAll())
	parent := t.TempDir()
	project := filepath.Join(parent, "project")
	copyTree(t, fixtureProject(t), project)
	setup.config.Target = project
	before := hashTree(t, project)

	testCases := []struct {
		name    string
		output  string
		wantErr error
	}{
		{"inside the project", filepath.Join(project, "reports"), ErrOutput},
		{"the project itself", project, ErrOutput},
		{"inside the project through dots", filepath.Join(project, "app", "..", "reports"), ErrOutput},
		{"inside a folder of the project", filepath.Join(project, "app"), ErrOutput},
		{"next to the project", filepath.Join(parent, "reports"), nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			setup.config.OutputBase = testCase.output
			session := setup.session(t)
			session.Confirm()

			_, err := session.Run(context.Background(), func(string) {})

			if !errors.Is(err, testCase.wantErr) {
				t.Errorf("err = %v, want %v", err, testCase.wantErr)
			}
			if !equalHashes(before, hashTree(t, project)) {
				t.Error("the run changed the project folder")
			}
		})
	}
}

func TestACancelledRunKeepsAnIncompleteReport(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("never"))
	ctx, cancel := context.WithCancel(context.Background())
	setup.provider.onSend = func(index int) {
		if index == 0 {
			cancel()
		}
	}
	session := setup.session(t)
	session.Confirm()

	result, err := session.Run(ctx, func(string) {})

	if err != nil || result.Complete || !strings.Contains(result.Report, "Status: incomplete (cancelled)") {
		t.Fatalf("err = %v, complete = %v, report:\n%s", err, result.Complete, result.Report)
	}
	if saved := outputFiles(t, setup.output)[filepath.Join("run-20261112-093000", "report.md")]; saved != result.Report {
		t.Error("the incomplete report was not saved")
	}
	if len(setup.provider.recorded) != 1 {
		t.Errorf("%d requests were sent, want 1", len(setup.provider.recorded))
	}
}

func TestProviderProblemsGiveAnIncompleteReportWithAReason(t *testing.T) {
	testCases := []struct {
		name        string
		providerErr error
		wantReason  string
	}{
		{"a bad key", outbound.ErrAuth, "key rejected"},
		{"a refusal", outbound.ErrRefused, "provider declined"},
		{"another error", errors.New("boom " + testKey), "provider failed"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			setup := newSetup(t, reply{err: testCase.providerErr})
			session := setup.session(t)
			session.Confirm()

			result, err := session.Run(context.Background(), func(string) {})

			if err != nil || result.Complete || !strings.Contains(result.Report, "Status: incomplete ("+testCase.wantReason+")") {
				t.Fatalf("err = %v, complete = %v, report:\n%s", err, result.Complete, result.Report)
			}
			for name, content := range outputFiles(t, setup.output) {
				assertNoSecrets(t, name, content, setup.project)
			}
		})
	}
}

func TestTheKeyIsNeverWrittenOrShown(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("done"))
	session := setup.session(t)
	session.Confirm()
	preview, _ := session.Preview()

	var steps []string
	result, err := session.Run(context.Background(), func(text string) { steps = append(steps, text) })
	if err != nil {
		t.Fatal(err)
	}

	for name, text := range map[string]string{
		"the preview": preview, "the consent text": session.ConsentText(), "the report": result.Report, "the steps": strings.Join(steps, "\n"),
		"the saved folder name": result.SavedTo, "the session": fmt.Sprintf("%+v %#v", session.providerName, session.config.OutputBase),
	} {
		if strings.Contains(text, testKey) || strings.Contains(text, "FAKEKEY") {
			t.Errorf("%s shows the key", name)
		}
	}
	for name, content := range outputFiles(t, setup.output) {
		if strings.Contains(content, testKey) || strings.Contains(content, "FAKEKEY") {
			t.Errorf("the file %s has the key", name)
		}
	}
}

func TestARunThatCannotLogDoesNotSend(t *testing.T) {
	setup := newSetup(t, scanAll())
	session := setup.session(t)
	session.Confirm()

	// The log file is opened for writing in a folder that is then made read-only: the first
	// write fails, and a request that cannot be logged must not be sent.
	blocked := filepath.Join(setup.output, "run-20261112-093000")
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "events.jsonl"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := session.Run(context.Background(), func(string) {})

	if !errors.Is(err, ErrOutput) || len(setup.provider.recorded) != 0 {
		t.Errorf("err = %v, provider calls = %d, want ErrOutput and nothing sent", err, len(setup.provider.recorded))
	}
	if content, _ := os.ReadFile(filepath.Join(blocked, "events.jsonl")); string(content) != "existing" {
		t.Error("an existing log file was changed")
	}
}

func TestTheTruncationOfLoggedText(t *testing.T) {
	long := strings.Repeat("a", 5000)
	note := describeRequest(outbound.Request{Messages: []outbound.Message{{Role: "user", Text: long}}}, 1)

	if len([]rune(note)) > 6200 || !strings.Contains(note, "…") {
		t.Errorf("the note is %d characters, want it cut near %d", len([]rune(note)), maxLoggedRunes)
	}
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate changed a short text: %q", got)
	}
	if got := truncate("日本語のテキスト", 3); got != "日本語…" {
		t.Errorf("truncate = %q, want it cut by characters", got)
	}
}

func TestRefusedToolCallsAreShownAndLogged(t *testing.T) {
	forbidden := reply{response: outbound.Response{ToolCalls: []outbound.ToolCall{
		{ID: "c1", Name: "send_email", Arguments: map[string]string{"to": "attacker"}},
		{ID: "c2", Name: "read_file", Arguments: map[string]string{"path": "../../etc/passwd"}},
	}}}
	setup := newSetup(t, forbidden, answerText("done"))
	session := setup.session(t)
	session.Confirm()

	var steps []string
	result, err := session.Run(context.Background(), func(text string) { steps = append(steps, text) })
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"a tool call was refused (unknown tool)", "tool read_file: refused (path not allowed)"} {
		if !slices.Contains(steps, want) {
			t.Errorf("no step says %q, steps: %v", want, steps)
		}
	}
	log := outputFiles(t, setup.output)[filepath.Join("run-20261112-093000", "events.jsonl")]
	if strings.Count(log, `"allowed":false`) != 2 || !strings.Contains(log, `"reason":"unknown tool"`) || !strings.Contains(log, `"reason":"path not allowed"`) {
		t.Errorf("the refusals are not in the log:\n%s", log)
	}
	if !result.Complete {
		t.Error("the run should still finish after refused calls")
	}
}

func TestModelsUsesTheKeyTheUserTypedOrTheEnvironment(t *testing.T) {
	testCases := []struct {
		name        string
		providerID  string
		typedKey    string
		environment map[string]string
		wantKey     string
		wantErr     error
		wantAsked   bool
		listerErr   error
	}{
		{"the typed key", "anthropic", "  typed-key ", nil, "typed-key", nil, true, nil},
		{"the environment key", "anthropic", "", map[string]string{"ANTHROPIC_API_KEY": "env-key"}, "env-key", nil, true, nil},
		{"the typed key wins", "anthropic", "typed-key", map[string]string{"ANTHROPIC_API_KEY": "env-key"}, "typed-key", nil, true, nil},
		{"no key", "anthropic", " ", nil, "", ErrNeedsKey, false, nil},
		{"a local provider needs no key", "ollama", "", nil, "", nil, true, nil},
		{"an unknown provider", "nope", "k", nil, "", ErrUnknownProvider, false, nil},
		{"the provider fails", "anthropic", "typed-key", nil, "typed-key", ErrModelList, true, errors.New("secret detail typed-key")},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var gotID, gotKey string
			asked := false
			config := Config{
				LookupEnv: func(name string) string { return testCase.environment[name] },
				ListModels: func(ctx context.Context, id, key string) ([]string, error) {
					asked, gotID, gotKey = true, id, key
					return []string{"model-a"}, testCase.listerErr
				},
			}

			models, err := config.Models(context.Background(), testCase.providerID, testCase.typedKey)

			if !errors.Is(err, testCase.wantErr) || asked != testCase.wantAsked {
				t.Fatalf("err = %v, asked = %v", err, asked)
			}
			if asked && (gotID != testCase.providerID || gotKey != testCase.wantKey) {
				t.Errorf("asked %q with key %q", gotID, gotKey)
			}
			if err == nil && !slices.Equal(models, []string{"model-a"}) {
				t.Errorf("models = %q", models)
			}
			if err != nil && strings.Contains(err.Error(), "typed-key") {
				t.Error("the error holds the key")
			}
		})
	}
}

func TestModelsKeepsACancel(t *testing.T) {
	config := Config{ListModels: func(ctx context.Context, id, key string) ([]string, error) { return nil, context.Canceled }}

	if _, err := config.Models(context.Background(), "ollama", ""); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestARejectedRequestShowsItsSafeDetailInTheTimelineAndTheLog(t *testing.T) {
	setup := newSetup(t, reply{err: &outbound.ProviderError{Detail: "status 404, code model_not_found"}})
	session := setup.session(t)
	session.Confirm()

	var steps []string
	result, err := session.Run(context.Background(), func(text string) { steps = append(steps, text) })
	if err != nil {
		t.Fatal(err)
	}

	if result.Complete || !slices.Contains(steps, "run finished: provider failed (status 404, code model_not_found)") {
		t.Errorf("complete = %v, steps = %q", result.Complete, steps)
	}
	log, err := os.ReadFile(filepath.Join(result.SavedTo, "events.jsonl"))
	if err != nil || !strings.Contains(string(log), `"reason":"provider failed","note":"status 404, code model_not_found"`) {
		t.Errorf("the event log does not hold the detail (err %v):\n%s", err, log)
	}
}

func TestAProviderFailureWithoutDetailStaysPlain(t *testing.T) {
	setup := newSetup(t, reply{err: outbound.ErrProviderFailed})
	session := setup.session(t)
	session.Confirm()

	var steps []string
	if _, err := session.Run(context.Background(), func(text string) { steps = append(steps, text) }); err != nil {
		t.Fatal(err)
	}

	if !slices.Contains(steps, "run finished: provider failed") {
		t.Errorf("steps = %q", steps)
	}
}

func TestPrepareChecksTheReasoningLevel(t *testing.T) {
	testCases := []struct {
		name        string
		setup       Setup
		wantErr     error
		wantFactory int
		wantLevel   string
	}{
		{"a documented level", Setup{ProviderID: "anthropic", Key: testKey, Reasoning: "max"}, nil, 1, "max"},
		{"the default", Setup{ProviderID: "anthropic", Key: testKey}, nil, 1, ""},
		{"a level the model does not have", Setup{ProviderID: "anthropic", Key: testKey, Model: "claude-sonnet-4-6", Reasoning: "xhigh"}, ErrReasoning, 0, ""},
		{"a level for a provider without any", Setup{ProviderID: "openai", Key: testKey, Model: "gpt-5.5", Reasoning: "high"}, ErrReasoning, 0, ""},
		{"a made-up level", Setup{ProviderID: "anthropic", Key: testKey, Reasoning: "x\", \"model\": \"y"}, ErrReasoning, 0, ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			setup := newSetup(t)

			_, err := Prepare(setup.config, testCase.setup)

			if !errors.Is(err, testCase.wantErr) || len(*setup.calls) != testCase.wantFactory {
				t.Fatalf("err = %v, factory calls = %d", err, len(*setup.calls))
			}
			if testCase.wantFactory == 1 && (*setup.calls)[0].reasoning != testCase.wantLevel {
				t.Errorf("the provider got %q, want %q", (*setup.calls)[0].reasoning, testCase.wantLevel)
			}
			if err != nil && err != ErrReasoning {
				t.Errorf("the error is not the fixed one: %v", err)
			}
		})
	}
}

func TestThePreviewNamesAChosenReasoningLevelOnly(t *testing.T) {
	setup := newSetup(t)

	chosen, err := Prepare(setup.config, Setup{ProviderID: "anthropic", Key: testKey, Reasoning: "high"})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Prepare(setup.config, Setup{ProviderID: "anthropic", Key: testKey})
	if err != nil {
		t.Fatal(err)
	}

	withLevel, _ := chosen.Preview()
	without, _ := plain.Preview()

	if !strings.Contains(withLevel, "Reasoning level: high\n") || strings.Contains(without, "Reasoning level") {
		t.Errorf("with:\n%s\nwithout:\n%s", withLevel, without)
	}
}

func TestReasoningChoicesStartWithTheDefault(t *testing.T) {
	choices := ReasoningChoices("anthropic", " claude-opus-5-5 ")

	if len(choices) < 2 || choices[0].Value != "" || choices[0].Label == "" {
		t.Errorf("choices = %+v", choices)
	}
	if got := ReasoningChoices("openai", "gpt-5.5"); len(got) != 0 {
		t.Errorf("openai: %+v", got)
	}
}

type fakeKeys struct {
	saved     map[string]string
	available bool
	failSet   bool
	failDel   bool
	getCalls  []string
}

func newFakeKeys(saved map[string]string) *fakeKeys {
	return &fakeKeys{saved: saved, available: true}
}

func (keys *fakeKeys) Available() bool { return keys.available }

func (keys *fakeKeys) Get(ctx context.Context, providerID string) (string, error) {
	keys.getCalls = append(keys.getCalls, providerID)
	if key, found := keys.saved[providerID]; found {
		return key, nil
	}

	return "", errors.New("no saved key")
}

func (keys *fakeKeys) Set(ctx context.Context, providerID, key string) error {
	if keys.failSet {
		return errors.New("boom " + key)
	}
	keys.saved[providerID] = key

	return nil
}

func (keys *fakeKeys) Delete(ctx context.Context, providerID string) error {
	if keys.failDel {
		return errors.New("boom")
	}
	delete(keys.saved, providerID)

	return nil
}

func TestTheKeyComesFromTheUserThenTheEnvironmentThenTheSavedKey(t *testing.T) {
	testCases := []struct {
		name    string
		typed   string
		env     map[string]string
		saved   map[string]string
		wantKey string
		wantErr error
	}{
		{"typed wins", "typed-key", map[string]string{"ANTHROPIC_API_KEY": "env-key"}, map[string]string{"anthropic": "saved-key"}, "typed-key", nil},
		{"the environment beats the saved key", "", map[string]string{"ANTHROPIC_API_KEY": "env-key"}, map[string]string{"anthropic": "saved-key"}, "env-key", nil},
		{"the saved key is the last choice", "  ", nil, map[string]string{"anthropic": "saved-key"}, "saved-key", nil},
		{"a saved key of another provider is not used", "", nil, map[string]string{"openai": "other-key"}, "", ErrNeedsKey},
		{"nothing at all", "", nil, nil, "", ErrNeedsKey},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			setup := newSetup(t)
			environment := testCase.env
			setup.config.LookupEnv = func(name string) string { return environment[name] }
			setup.config.Keys = newFakeKeys(testCase.saved)

			_, err := Prepare(setup.config, Setup{ProviderID: "anthropic", Key: testCase.typed})

			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("err = %v, want %v", err, testCase.wantErr)
			}
			if testCase.wantErr == nil && (*setup.calls)[0].key != testCase.wantKey {
				t.Errorf("the provider got the key %q, want %q", (*setup.calls)[0].key, testCase.wantKey)
			}
		})
	}
}

func TestModelsUsesTheSavedKey(t *testing.T) {
	var gotKey string
	config := Config{
		Keys: newFakeKeys(map[string]string{"openai": "saved-key"}),
		ListModels: func(ctx context.Context, id, key string) ([]string, error) {
			gotKey = key
			return []string{"m"}, nil
		},
	}

	if _, err := config.Models(context.Background(), "openai", ""); err != nil || gotKey != "saved-key" {
		t.Errorf("err = %v, key = %q", err, gotKey)
	}
}

func TestProvidersSayWhichKeysAreSavedAndAskOnlyWhenNeeded(t *testing.T) {
	keys := newFakeKeys(map[string]string{"anthropic": "saved-key", "openai": "saved-key-2", "ollama": "never-asked"})
	config := Config{Keys: keys, LookupEnv: func(name string) string {
		if name == "OPENAI_API_KEY" {
			return "env-key"
		}
		return ""
	}}

	byID := map[string]Choice{}
	for _, choice := range config.Providers() {
		byID[choice.ID] = choice
	}

	if !byID["anthropic"].KeySaved || byID["gemini"].KeySaved {
		t.Errorf("anthropic %+v, gemini %+v", byID["anthropic"], byID["gemini"])
	}
	if !byID["openai"].KeyFound || byID["openai"].KeySaved {
		t.Errorf("openai %+v: a key in the environment makes asking the store unnecessary", byID["openai"])
	}
	if byID["ollama"].KeySaved {
		t.Error("a local provider has a saved key")
	}
	for _, asked := range keys.getCalls {
		if asked == "openai" || asked == "ollama" {
			t.Errorf("the store was asked about %s", asked)
		}
	}
}

func TestSaveKeyAndForgetKey(t *testing.T) {
	keys := newFakeKeys(map[string]string{})
	config := Config{Keys: keys}
	ctx := context.Background()

	if err := config.SaveKey(ctx, "openai", "  new-key \n"); err != nil || keys.saved["openai"] != "new-key" {
		t.Fatalf("err = %v, saved = %v", err, keys.saved)
	}
	if err := config.ForgetKey(ctx, "openai"); err != nil || len(keys.saved) != 0 {
		t.Fatalf("err = %v, saved = %v", err, keys.saved)
	}
	if err := config.ForgetKey(ctx, "openai"); err != nil {
		t.Errorf("forgetting a key that is not there: %v", err)
	}
}

func TestSaveKeyAndForgetKeyRefuseWhatTheyShould(t *testing.T) {
	ctx := context.Background()
	unavailable := newFakeKeys(map[string]string{})
	unavailable.available = false
	failing := newFakeKeys(map[string]string{})
	failing.failSet, failing.failDel = true, true

	testCases := []struct {
		name    string
		config  Config
		action  func(Config) error
		wantErr error
	}{
		{"save for an unknown provider", Config{Keys: newFakeKeys(nil)}, func(c Config) error { return c.SaveKey(ctx, "nope", "k") }, ErrUnknownProvider},
		{"save for a local provider", Config{Keys: newFakeKeys(nil)}, func(c Config) error { return c.SaveKey(ctx, "ollama", "k") }, ErrUnknownProvider},
		{"save without a store", Config{}, func(c Config) error { return c.SaveKey(ctx, "openai", "k") }, ErrKeyStore},
		{"save where it is not available", Config{Keys: unavailable}, func(c Config) error { return c.SaveKey(ctx, "openai", "k") }, ErrKeyStore},
		{"save when the store fails", Config{Keys: failing}, func(c Config) error { return c.SaveKey(ctx, "openai", "secret-key") }, ErrKeyStore},
		{"forget an unknown provider", Config{Keys: newFakeKeys(nil)}, func(c Config) error { return c.ForgetKey(ctx, "nope") }, ErrUnknownProvider},
		{"forget without a store", Config{}, func(c Config) error { return c.ForgetKey(ctx, "openai") }, ErrKeyStore},
		{"forget when the store fails", Config{Keys: failing}, func(c Config) error { return c.ForgetKey(ctx, "openai") }, ErrKeyStore},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.action(testCase.config)

			if err != testCase.wantErr {
				t.Errorf("err = %v, want exactly %v", err, testCase.wantErr)
			}
		})
	}
	if (Config{}).KeysCanBeSaved() || !(Config{Keys: newFakeKeys(nil)}).KeysCanBeSaved() || (Config{Keys: unavailable}).KeysCanBeSaved() {
		t.Error("KeysCanBeSaved is wrong")
	}
}

func TestAWrongKeyIsReportedAsRejectedAndOtherFailuresAreNot(t *testing.T) {
	testCases := []struct {
		name      string
		listerErr error
		wantErr   error
	}{
		{"the provider rejects the key", outbound.ErrAuth, ErrKeyRejected},
		{"the provider is down", outbound.ErrTemporary, ErrModelList},
		{"another problem", errors.New("boom sk-secret"), ErrModelList},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := Config{ListModels: func(ctx context.Context, id, key string) ([]string, error) { return nil, testCase.listerErr }}

			_, err := config.Models(context.Background(), "ollama", "")

			if err != testCase.wantErr {
				t.Errorf("err = %v, want exactly %v", err, testCase.wantErr)
			}
		})
	}
}

func TestThePreviewNamesTheModel(t *testing.T) {
	setup := newSetup(t)
	session, err := Prepare(setup.config, Setup{ProviderID: "anthropic", Key: testKey, Model: " claude-sonnet-5-5 "})
	if err != nil {
		t.Fatal(err)
	}

	preview, _ := session.Preview()

	if !strings.Contains(preview, "\nModel: claude-sonnet-5-5\n") {
		t.Errorf("the preview does not name the model:\n%s", preview)
	}
}

func TestTheSummaryIsShortAndTheFullPreviewKeepsTheSystemPrompt(t *testing.T) {
	setup := newSetup(t)
	session, err := Prepare(setup.config, Setup{ProviderID: "anthropic", Key: testKey, Model: "claude-sonnet-5-5", Reasoning: "high"})
	if err != nil {
		t.Fatal(err)
	}

	summary, err := session.Summary()
	if err != nil {
		t.Fatal(err)
	}
	preview, _ := session.Preview()

	for _, want := range []string{"Provider: FakeAI\n", "Model: claude-sonnet-5-5\n", "Reasoning level: high\n", "Limits for this run: up to 10 requests and 100000 tokens.", "It holds no file content.", "Later requests also hold the files", "Instruction (user):\nCheck this project"} {
		if !strings.Contains(summary, want) {
			t.Errorf("the summary has no %q:\n%s", want, summary)
		}
	}
	for _, left := range []string{"System prompt:", "Tools the AI may call", "- read_file:"} {
		if strings.Contains(summary, left) || !strings.Contains(preview, left) {
			t.Errorf("%q must be in the full preview only", left)
		}
	}
	if strings.Count(summary, "\n") >= strings.Count(preview, "\n") {
		t.Errorf("the summary (%d lines) is not shorter than the preview (%d lines)", strings.Count(summary, "\n"), strings.Count(preview, "\n"))
	}
}

func TestTheSummaryNamesAReasoningLevelOnlyWhenChosen(t *testing.T) {
	setup := newSetup(t)
	plain, err := Prepare(setup.config, Setup{ProviderID: "anthropic", Key: testKey})
	if err != nil {
		t.Fatal(err)
	}

	summary, _ := plain.Summary()

	if strings.Contains(summary, "Reasoning level") {
		t.Errorf("a level is named although none was chosen:\n%s", summary)
	}
}

func TestTheSummaryNeverHoldsAKeyOrFileContent(t *testing.T) {
	setup := newSetup(t)
	session, err := Prepare(setup.config, Setup{ProviderID: "anthropic", Key: testKey})
	if err != nil {
		t.Fatal(err)
	}

	summary, _ := session.Summary()

	for _, planted := range append(plantedValues, testKey) {
		if strings.Contains(summary, planted) {
			t.Errorf("the summary holds %q", planted)
		}
	}
}

func TestMarkupInFileNamesFileContentsAndAINotesIsOnlyTextInTheHTMLReport(t *testing.T) {
	hostile := "<script>alert(document.domain)</script>"
	setup := newSetup(t, scanAll(), answerText("Note: "+hostile+" <img src=x onerror=alert(1)>"))
	project := filepath.Join(t.TempDir(), "project")
	copyTree(t, setup.project, project)
	setup.config.Target = project
	name := filepath.Join(project, "notes", "<svg onload=alert(1)>.txt")
	if err := os.WriteFile(name, []byte(hostile+"\ncall 090-1234-5678\n"), 0o600); err != nil {
		t.Skip("this file system does not allow this file name")
	}
	session := setup.session(t)
	session.Confirm()

	result, err := session.Run(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}

	page := outputFiles(t, setup.output)[filepath.Join("run-20261112-093000", "report.html")]
	body := page[strings.Index(page, "<body>"):]
	if strings.Contains(body, "<script") || strings.Contains(body, "<img") || strings.Contains(body, "<svg") || !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "notes/_svg onload=alert(1)_.txt") {
		t.Errorf("the markup is not shown as text:\n%s", body)
	}
	if strings.Contains(page, "090-1234-5678") || !strings.Contains(result.Report, "[PHONE:") {
		t.Error("the page or the report is wrong about the phone number")
	}
}

func TestNewSecretFormatsAreFoundWithTheRightLineAndNeverReachTheProviderOrAFile(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("Rotate them."))
	project := filepath.Join(t.TempDir(), "project")
	copyTree(t, setup.project, project)
	setup.config.Target = project
	block := "-----BEGIN PRIVATE KEY-----\nFAKEFAKEFAKEFAKEBODYLINE1\nFAKEFAKEFAKEFAKEBODYLINE2\n-----END PRIVATE KEY-----\n"
	files := map[string]string{
		"deploy/key.pem":  "# fake\n" + block,
		"app/settings.py": "x = 1\nAI = 'sk-" + "proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234'\nDB = 'postgres://admin:FakePass123@db.example.com/app'\n",
	}
	for name, content := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(project, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	session := setup.session(t)
	session.Confirm()

	result, err := session.Run(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"| deploy/key.pem | 2 |", "| app/settings.py | 2 |", "| app/settings.py | 3 |", "private-key", "ai-api-key", "url-credentials"} {
		if !strings.Contains(result.Report, want) {
			t.Errorf("the report has no %q:\n%s", want, result.Report)
		}
	}
	var sent strings.Builder
	for _, request := range setup.provider.recorded {
		for _, message := range request.Messages {
			sent.WriteString(message.Text)
		}
	}
	everything := sent.String() + result.Report
	for _, content := range outputFiles(t, setup.output) {
		everything += content
	}
	for _, planted := range []string{"BODYLINE1", "BODYLINE2", "sk-proj-FAKEFAKE", "FakePass123"} {
		if strings.Contains(everything, planted) {
			t.Errorf("%q reached a request, the report or a file", planted)
		}
	}
}

func TestOrdinaryCodeAndAssetsAreNotCountedButRealDataStillIs(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("Done."))
	project := filepath.Join(t.TempDir(), "project")
	copyTree(t, setup.project, project)
	setup.config.Target = project

	svg := "<svg><path d=\"M0.0643290124,12.5 L0.000428679482,175.6 C-0.0197873902 206.3\"/></svg>\n"
	files := map[string][]byte{
		".agents/skills/design/assets/icon.svg": []byte(svg),
		".agents/skills/design/assets/real.txt": []byte("call 03-5555-0100\n"),
		"third_party/lib/contact.txt":           []byte("call 03-5555-0101\n"),
		"web/shader.js":                         []byte("const k = [4.0767416621, -3.3077115913, 0.2309699292];\n"),
		"web/ids.go":                            []byte("const id = \"123e4567-e89b-12d3-a456-426614174000\"\nconst other = \"123e4567-e89b-12d3-a456-123123123128\"\n"),
		"docs/dump.txt":                         []byte("0024 ffff ffff 8000 0014 0000 0000 0000\n"),
		"web/digits.go":                         []byte("const digits = \"0123456789\"\n"),
		"docs/readme.md":                        []byte("connect with postgres://user:pass@localhost/db\n"),
		"app/db.py":                             []byte("URL = 'postgres://admin:k8Zq2vLp9Xw@db.example.com/app'\n"),
		"app/contacts.csv":                      []byte("name,phone\nSato,03-6666-0199\n"),
		"assets/logo.bmp":                       append([]byte("BM\x00\x00\x00"), []byte("09012345678 090-1234-5678 AKIAIOSFODNN7EXAMPLE")...),
	}
	for name, content := range files {
		path := filepath.Join(project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	session := setup.session(t)
	session.Confirm()

	result, err := session.Run(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}

	table := result.Report[strings.Index(result.Report, "## Findings"):]
	table = table[:strings.Index(table, "\n## ")]
	for _, want := range []string{"app/contacts.csv", "app/db.py"} {
		if !strings.Contains(table, want) {
			t.Errorf("the table has no %s:\n%s", want, table)
		}
	}
	for _, notWanted := range []string{"icon.svg", "shader.js", "ids.go", "dump.txt", "digits.go", "readme.md", "logo.bmp"} {
		if strings.Contains(table, notWanted) {
			t.Errorf("the table holds %s:\n%s", notWanted, table)
		}
	}
	if !strings.Contains(table, "[SECRET:url-credentials:001] | high | url-credentials | app/db.py") {
		t.Errorf("a real password in an address must be counted:\n%s", table)
	}

	for _, want := range []string{"## Library and generated files", "third_party/lib/contact.txt", "## Probably not real", "web/shader.js", "web/ids.go", "docs/dump.txt", "web/digits.go", "docs/readme.md", "[EXAMPLE:url-credentials:001]"} {
		if !strings.Contains(result.Report, want) {
			t.Errorf("the report has no %q:\n%s", want, result.Report)
		}
	}
	if strings.Contains(result.Report, ".agents/skills/design") {
		t.Error("the skills folder of an AI tool was scanned")
	}
	if strings.Contains(result.Report, "logo.bmp") {
		t.Error("a binary file was scanned")
	}
	for _, content := range outputFiles(t, setup.output) {
		if strings.Contains(content, "k8Zq2vLp9Xw") || strings.Contains(content, "0.0643290124") {
			t.Error("a value is in an output file")
		}
	}
}

func TestNoisyFoldersThatComeFirstNeverHideARealFindingInALaterFolder(t *testing.T) {
	setup := newSetup(t, scanAll(), answerText("Done."))
	project := filepath.Join(t.TempDir(), "project")
	copyTree(t, setup.project, project)
	setup.config.Target = project

	files := map[string]string{
		"backend/src/app.controller.ts": "return { openaiApiKey: '" + "sk-" + "proj-OMAMORITESTFAKEKEYOMAMORITESTFAKEKEY0001' };\n",
		"backend/.env":                  "AI_KEY=" + "sk-" + "proj-OMAMORITESTFAKEKEYOMAMORITESTFAKEKEY0002\n",
		"backend/.gitignore":            "dist\n",
	}
	for index := 0; index < 130; index++ {
		files[fmt.Sprintf("aaa-assets/icon%03d.svg", index)] = "<path d=\"M0.0643290124,12.5\"/>\n"
	}
	for name, content := range files {
		path := filepath.Join(project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	session := setup.session(t)
	session.Confirm()
	var steps []string

	result, err := session.Run(context.Background(), func(text string) { steps = append(steps, text) })
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"backend/src/app.controller.ts | 1 |",
		"| backend/.env | 1 |",
		"No .gitignore rule in the scanned folder keeps this file out of git",
	} {
		if !strings.Contains(result.Report, want) {
			t.Errorf("the report has no %q:\n%s", want, result.Report)
		}
	}
	if strings.Contains(result.Report, "stopped at a limit") && strings.Contains(result.Report, "WARNING") {
		t.Errorf("the scan was completed, so there must be no warning:\n%s", result.Report)
	}
	if !slices.Contains(steps, "tool full_scan: ok") {
		t.Errorf("the user must see that the scan was completed: %q", steps)
	}
	if strings.Contains(result.Report, "OMAMORITESTFAKEKEY") {
		t.Error("the key is in the report")
	}
}
