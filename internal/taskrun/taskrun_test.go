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
	id, key, model string
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
			NewProvider: func(id, key, model string) (outbound.Provider, error) {
				*calls = append(*calls, factoryCall{id, key, model})
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
		factory   func(id, key, model string) (outbound.Provider, error)
		wantErr   error
		wantCall  factoryCall
		wantCalls int
	}{
		{"a key that is typed", Setup{ProviderID: "anthropic", Key: testKey}, nil, "", nil, nil, factoryCall{"anthropic", testKey, "claude-opus-5-5"}, 1},
		{"a key from the environment", Setup{ProviderID: "anthropic"}, map[string]string{"ANTHROPIC_API_KEY": testKey}, "", nil, nil, factoryCall{"anthropic", testKey, "claude-opus-5-5"}, 1},
		{"a typed key beats the environment", Setup{ProviderID: "anthropic", Key: testKey}, map[string]string{"ANTHROPIC_API_KEY": "sk-other"}, "", nil, nil, factoryCall{"anthropic", testKey, "claude-opus-5-5"}, 1},
		{"white space around the key is removed", Setup{ProviderID: "anthropic", Key: "  " + testKey + "\n"}, nil, "", nil, nil, factoryCall{"anthropic", testKey, "claude-opus-5-5"}, 1},
		{"a chosen model beats the default", Setup{ProviderID: "anthropic", Key: testKey, Model: " claude-sonnet-5-5 "}, nil, "", nil, nil, factoryCall{"anthropic", testKey, "claude-sonnet-5-5"}, 1},
		{"no key", Setup{ProviderID: "anthropic"}, nil, "", nil, ErrNeedsKey, factoryCall{}, 0},
		{"a key of only spaces", Setup{ProviderID: "anthropic", Key: "   "}, nil, "", nil, ErrNeedsKey, factoryCall{}, 0},
		{"a provider without a default model", Setup{ProviderID: "openai", Key: testKey}, nil, "", nil, ErrNeedsModel, factoryCall{}, 0},
		{"a provider with a model", Setup{ProviderID: "openai", Key: testKey, Model: "a-model"}, nil, "", nil, nil, factoryCall{"openai", testKey, "a-model"}, 1},
		{"a local provider needs no key and ignores one", Setup{ProviderID: "ollama", Model: "llama", Key: testKey}, nil, "", nil, nil, factoryCall{"ollama", "", "llama"}, 1},
		{"a local provider still needs a model", Setup{ProviderID: "ollama"}, nil, "", nil, ErrNeedsModel, factoryCall{}, 0},
		{"an unknown provider", Setup{ProviderID: "nope", Key: testKey, Model: "m"}, nil, "", nil, ErrUnknownProvider, factoryCall{}, 0},
		{"no provider", Setup{Key: testKey, Model: "m"}, nil, "", nil, ErrUnknownProvider, factoryCall{}, 0},
		{"a folder that is not there", Setup{ProviderID: "anthropic", Key: testKey}, nil, "/no/such/folder/anywhere", nil, ErrTarget, factoryCall{}, 0},
		{"a provider that cannot be built", Setup{ProviderID: "anthropic", Key: testKey}, nil, "",
			func(id, key, model string) (outbound.Provider, error) { return nil, errors.New("boom " + key) }, ErrSetup, factoryCall{}, 0},
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
	if len(files) != 2 || files[filepath.Join("run-20261112-093000", "report.md")] != result.Report || files[filepath.Join("run-20261112-093000", "events.jsonl")] == "" {
		t.Fatalf("the output files are %v, want exactly report.md (the same as the result) and events.jsonl", slices.Sorted(mapKeys(files)))
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
