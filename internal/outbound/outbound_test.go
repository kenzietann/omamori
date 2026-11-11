package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/sanitizer"
)

const (
	fakeAWSKey      = "AKIAIOSFODNN7EXAMPLE"
	fakeGitHubToken = "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1"
	fakeMyNumber    = "123123123128"
	fakePhone       = "090-1234-5678"
)

var plantedValues = []string{fakeAWSKey, fakeGitHubToken, fakeMyNumber, fakePhone}

type fakeProvider struct {
	recorded  []Request
	scripted  []error
	onSend    func()
	callCount int
}

func (provider *fakeProvider) Name() string { return "FakeAI" }

func (provider *fakeProvider) Send(ctx context.Context, safe SafeRequest) (Response, error) {
	provider.recorded = append(provider.recorded, safe.Request())
	provider.callCount++
	if provider.onSend != nil {
		provider.onSend()
	}

	if len(provider.scripted) > 0 {
		scriptedError := provider.scripted[0]
		provider.scripted = provider.scripted[1:]
		if scriptedError != nil {
			return Response{}, scriptedError
		}
	}

	return Response{Text: "ok"}, nil
}

func newTestSender(t testing.TB, provider Provider) (*Sender, string) {
	t.Helper()

	projectDirectory := t.TempDir()
	sender, err := New(provider, projectDirectory)
	if err != nil {
		t.Fatal(err)
	}
	sender.Authorize()

	return sender, projectDirectory
}

func encodeForSearch(t testing.TB, value any) string {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return string(encoded) + fmt.Sprintf("%+v", value)
}

func plantedRequest(projectDirectory string) Request {
	return Request{
		System: "You help with " + fakeAWSKey + " checks in " + projectDirectory,
		Messages: []Message{
			{Role: "user", Text: "Scan " + filepath.Join(projectDirectory, "src", "app.go") + " for " + fakePhone},
			{Role: "assistant", ToolCalls: []ToolCall{{Name: "read_file", Arguments: map[string]string{
				"path": filepath.Join(projectDirectory, "config", fakeGitHubToken+".txt"),
			}}}},
			{Role: "tool", Text: "mynumber=" + fakeMyNumber + " token=" + fakeGitHubToken},
		},
	}
}

func TestMultiTurnRunWithRetryNeverLeaks(t *testing.T) {
	provider := &fakeProvider{scripted: []error{nil, ErrTemporary, nil, nil}}
	sender, projectDirectory := newTestSender(t, provider)
	request := plantedRequest(projectDirectory)

	for turn := 0; turn < 3; turn++ {
		if _, err := sender.Send(context.Background(), request); err != nil {
			t.Fatalf("turn %d: %v", turn, err)
		}
		request.Messages = append(request.Messages, Message{Role: "user", Text: "next " + fakeAWSKey})
	}

	if len(provider.recorded) != 4 {
		t.Fatalf("the provider saw %d requests, want 4 (3 turns and 1 retry)", len(provider.recorded))
	}
	if sender.Attempts() != 4 {
		t.Errorf("Attempts() = %d, want 4", sender.Attempts())
	}

	for index, recorded := range provider.recorded {
		searchText := encodeForSearch(t, recorded)
		for _, planted := range append(plantedValues, projectDirectory) {
			if strings.Contains(searchText, planted) {
				t.Errorf("request %d contains %q", index, planted)
			}
		}
		if !strings.Contains(searchText, "src/app.go") {
			t.Errorf("request %d lost the project-relative path", index)
		}
	}
}

func TestNotAuthorizedSendsNothing(t *testing.T) {
	provider := &fakeProvider{}
	sender, err := New(provider, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	_, err = sender.Send(context.Background(), Request{Messages: []Message{{Role: "user", Text: "hi"}}})

	if !errors.Is(err, ErrNotAuthorized) || provider.callCount != 0 {
		t.Errorf("err = %v, calls = %d, want ErrNotAuthorized and 0 calls", err, provider.callCount)
	}
}

func TestPreviewShowsTheRequestWithoutSending(t *testing.T) {
	provider := &fakeProvider{}
	sender, err := New(provider, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	gotRequest, err := sender.Preview(Request{Messages: []Message{{Role: "user", Text: "key " + fakeAWSKey}}})

	if err != nil || provider.callCount != 0 || sender.Attempts() != 0 {
		t.Fatalf("err = %v, calls = %d, attempts = %d, want no error and nothing sent", err, provider.callCount, sender.Attempts())
	}
	if gotRequest.Messages[0].Text != "key [SECRET:aws-access-key:001]" {
		t.Errorf("preview text = %q", gotRequest.Messages[0].Text)
	}
}

func TestConsentText(t *testing.T) {
	sender, err := New(&fakeProvider{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	want := "Omamori will send sanitized content to FakeAI during this run."
	if got := sender.ConsentText(); got != want {
		t.Errorf("ConsentText() = %q, want %q", got, want)
	}
}

func TestRetries(t *testing.T) {
	testCases := []struct {
		name         string
		scripted     []error
		wantErr      error
		wantAttempts int
	}{
		{"works at once", nil, nil, 1},
		{"one temporary problem", []error{ErrTemporary}, nil, 2},
		{"two temporary problems", []error{ErrTemporary, ErrTemporary}, nil, 3},
		{"three temporary problems stop at the limit", []error{ErrTemporary, ErrTemporary, ErrTemporary}, ErrProviderFailed, 3},
		{"a wrapped temporary problem is retried", []error{fmt.Errorf("busy: %w", ErrTemporary)}, nil, 2},
		{"another error is not retried", []error{errors.New("bad key")}, ErrProviderFailed, 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			provider := &fakeProvider{scripted: testCase.scripted}
			sender, _ := newTestSender(t, provider)

			_, err := sender.Send(context.Background(), Request{Messages: []Message{{Role: "user", Text: "hi"}}})

			if !errors.Is(err, testCase.wantErr) || provider.callCount != testCase.wantAttempts {
				t.Errorf("err = %v, attempts = %d, want %v and %d", err, provider.callCount, testCase.wantErr, testCase.wantAttempts)
			}
		})
	}
}

func TestErrorsNeverHoldContent(t *testing.T) {
	provider := &fakeProvider{scripted: []error{errors.New("echo " + fakeAWSKey)}}
	sender, _ := newTestSender(t, provider)

	_, err := sender.Send(context.Background(), Request{Messages: []Message{{Role: "user", Text: "hi"}}})

	if err == nil || strings.Contains(err.Error(), fakeAWSKey) {
		t.Errorf("err = %v, want an error without the provider's text", err)
	}
}

func TestCancelStopsNewCalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	provider := &fakeProvider{scripted: []error{ErrTemporary, ErrTemporary}, onSend: cancel}
	sender, _ := newTestSender(t, provider)

	_, err := sender.Send(ctx, Request{Messages: []Message{{Role: "user", Text: "hi"}}})

	if !errors.Is(err, ErrCancelled) || provider.callCount != 1 {
		t.Errorf("err = %v, calls = %d, want ErrCancelled and 1 call", err, provider.callCount)
	}

	_, err = sender.Send(ctx, Request{Messages: []Message{{Role: "user", Text: "hi"}}})
	if !errors.Is(err, ErrCancelled) || provider.callCount != 1 {
		t.Errorf("after cancel: err = %v, calls = %d, want ErrCancelled and still 1 call", err, provider.callCount)
	}
}

func TestInvalidRequests(t *testing.T) {
	testCases := []struct {
		name    string
		request Request
	}{
		{"no messages", Request{System: "hi"}},
		{"unknown role", Request{Messages: []Message{{Role: "system", Text: "hi"}}}},
		{"a secret as the role", Request{Messages: []Message{{Role: fakeAWSKey, Text: "hi"}}}},
		{"a secret as the tool name", Request{Messages: []Message{{Role: "assistant", ToolCalls: []ToolCall{{Name: fakeAWSKey}}}}}},
		{"a secret as an argument name", Request{Messages: []Message{{Role: "assistant", ToolCalls: []ToolCall{{Name: "read_file", Arguments: map[string]string{fakeAWSKey: "x"}}}}}}},
		{"empty tool name", Request{Messages: []Message{{Role: "assistant", ToolCalls: []ToolCall{{Name: ""}}}}}},
		{"tool name with a space", Request{Messages: []Message{{Role: "assistant", ToolCalls: []ToolCall{{Name: "read file"}}}}}},
		{"a result ID on a user message", Request{Messages: []Message{{Role: "user", Text: "hi", ToolCallID: "toolu_1"}}}},
		{"a result ID with a space", Request{Messages: []Message{{Role: "tool", Text: "x", ToolCallID: "bad id"}}}},
		{"a secret-shaped result ID with brackets", Request{Messages: []Message{{Role: "tool", Text: "x", ToolCallID: "[SECRET:aws:001]"}}}},
		{"a call ID that is too long", Request{Messages: []Message{{Role: "assistant", ToolCalls: []ToolCall{{ID: strings.Repeat("a", 65), Name: "read_file"}}}}}},
		{"a tool spec with a bad name", Request{Messages: []Message{{Role: "user", Text: "hi"}}, Tools: []ToolSpec{{Name: "Read File"}}}},
		{"a tool spec with a bad parameter name", Request{Messages: []Message{{Role: "user", Text: "hi"}}, Tools: []ToolSpec{{Name: "read_file", Parameters: []ToolParameter{{Name: fakeAWSKey}}}}}},
		{"too many tool specs", Request{Messages: []Message{{Role: "user", Text: "hi"}}, Tools: manyToolSpecs(17)}},
		{"too many parameters", Request{Messages: []Message{{Role: "user", Text: "hi"}}, Tools: []ToolSpec{{Name: "read_file", Parameters: manyParameters(9)}}}},
		{"a long tool description", Request{Messages: []Message{{Role: "user", Text: "hi"}}, Tools: []ToolSpec{{Name: "read_file", Description: strings.Repeat("a", 1001)}}}},
		{"a long parameter description", Request{Messages: []Message{{Role: "user", Text: "hi"}}, Tools: []ToolSpec{{Name: "read_file", Parameters: []ToolParameter{{Name: "path", Description: strings.Repeat("a", 1001)}}}}}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			provider := &fakeProvider{}
			sender, _ := newTestSender(t, provider)

			_, err := sender.Send(context.Background(), testCase.request)

			if !errors.Is(err, ErrInvalidRequest) || provider.callCount != 0 {
				t.Errorf("err = %v, calls = %d, want ErrInvalidRequest and 0 calls", err, provider.callCount)
			}
			if strings.Contains(err.Error(), fakeAWSKey) {
				t.Errorf("the error holds the input: %v", err)
			}
		})
	}
}

func TestEscapingCannotCreateAFinding(t *testing.T) {
	provider := &fakeProvider{}
	sender, _ := newTestSender(t, provider)

	_, err := sender.Send(context.Background(), Request{Messages: []Message{{Role: "user", Text: "\x00" + "00000000A"}}})

	if !errors.Is(err, ErrUnsafeRequest) || provider.callCount != 0 {
		t.Errorf("err = %v, calls = %d, want ErrUnsafeRequest and 0 calls", err, provider.callCount)
	}
}

func TestPlaceholdersAreTheSameForTheSameHistory(t *testing.T) {
	provider := &fakeProvider{}
	sender, _ := newTestSender(t, provider)
	request := Request{Messages: []Message{{Role: "user", Text: fakeAWSKey}}}

	sender.Send(context.Background(), request)
	request.Messages = append(request.Messages, Message{Role: "user", Text: "again"})
	sender.Send(context.Background(), request)

	firstText := provider.recorded[0].Messages[0].Text
	secondText := provider.recorded[1].Messages[0].Text
	if firstText != secondText {
		t.Errorf("the first message changed between turns: %q then %q", firstText, secondText)
	}
}

func TestShortenPath(t *testing.T) {
	testCases := []struct {
		name      string
		inputText string
		want      string
	}{
		{"file inside", "read /work/proj/src/a.go now", "read src/a.go now"},
		{"the folder itself", "scan /work/proj", "scan ."},
		{"the folder at the end of a sentence", "scan /work/proj.", "scan .."},
		{"a folder with a dot in its name", "see /work/proj.bak/a.go", "see /work/proj.bak/a.go"},
		{"a folder with a longer name", "see /work/project2/a.go", "see /work/project2/a.go"},
		{"two paths", "/work/proj/a /work/proj/b", "a b"},
		{"quoted", `"/work/proj/a.go"`, `"a.go"`},
		{"other folder is kept", "/etc/passwd", "/etc/passwd"},
		{"no path", "hello", "hello"},
		{"empty", "", ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := shortenPath(testCase.inputText, "/work/proj"); got != testCase.want {
				t.Errorf("shortenPath(%q) = %q, want %q", testCase.inputText, got, testCase.want)
			}
		})
	}
}

func TestNewRejectsBadSetup(t *testing.T) {
	if _, err := New(nil, t.TempDir()); !errors.Is(err, ErrInvalidSetup) {
		t.Errorf("nil provider: err = %v", err)
	}
	if _, err := New(&fakeProvider{}, ""); !errors.Is(err, ErrInvalidSetup) {
		t.Errorf("empty directory: err = %v", err)
	}
	if _, err := New(&fakeProvider{}, "/"); !errors.Is(err, ErrInvalidSetup) {
		t.Errorf("root directory: err = %v", err)
	}
}

func FuzzSend(f *testing.F) {
	f.Add("hello", "world")
	f.Add("key "+fakeAWSKey, fakePhone)
	f.Add("\x00"+"00000000A", "")
	f.Add("/tmp/x/a.go", "mynumber "+fakeMyNumber)

	f.Fuzz(func(t *testing.T, systemText, messageText string) {
		provider := &fakeProvider{}
		sender, _ := newTestSender(t, provider)
		request := Request{System: systemText, Messages: []Message{{Role: "user", Text: messageText}}}

		_, err := sender.Send(context.Background(), request)
		if err != nil {
			if provider.callCount != 0 {
				t.Fatalf("an error was returned after a send: %v", err)
			}
			return
		}

		for _, recorded := range provider.recorded {
			if _, findings := (&sanitizer.Sanitizer{}).Sanitize(encodeForSearch(t, recorded)); len(findings) > 0 {
				t.Fatalf("a recorded request still has a finding: %v", findings)
			}
		}
	})
}

func manyToolSpecs(count int) []ToolSpec {
	specs := make([]ToolSpec, count)
	for index := range specs {
		specs[index] = ToolSpec{Name: fmt.Sprintf("tool_%d", index)}
	}

	return specs
}

func manyParameters(count int) []ToolParameter {
	parameters := make([]ToolParameter, count)
	for index := range parameters {
		parameters[index] = ToolParameter{Name: fmt.Sprintf("parameter_%d", index)}
	}

	return parameters
}

func TestValidToolSpecsAndIDsAreAccepted(t *testing.T) {
	provider := &fakeProvider{}
	sender, _ := newTestSender(t, provider)
	request := Request{
		Messages: []Message{
			{Role: "user", Text: "hi"},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "toolu_01A-b_c", Name: "read_file", Arguments: map[string]string{"path": "a.go"}}}},
			{Role: "tool", Text: "result", ToolCallID: "toolu_01A-b_c"},
		},
		Tools: append(manyToolSpecs(15), ToolSpec{Name: "read_file", Description: "Read a file.", Parameters: manyParameters(8)}),
	}

	if _, err := sender.Send(context.Background(), request); err != nil {
		t.Fatalf("a valid request was refused: %v", err)
	}

	got := provider.recorded[0]
	if len(got.Tools) != 16 || got.Messages[2].ToolCallID != "toolu_01A-b_c" || got.Messages[1].ToolCalls[0].ID != "toolu_01A-b_c" {
		t.Errorf("the IDs or the tools were lost: %+v", got)
	}
}

func TestTheObserverSeesEveryCleanedRequestBeforeItIsSent(t *testing.T) {
	provider := &fakeProvider{scripted: []error{ErrTemporary, nil}}
	sender, projectDirectory := newTestSender(t, provider)

	var seen []Request
	var providerCallsWhenSeen []int
	sender.Observe(func(request Request) error {
		seen = append(seen, request)
		providerCallsWhenSeen = append(providerCallsWhenSeen, provider.callCount)

		return nil
	})

	if _, err := sender.Send(context.Background(), plantedRequest(projectDirectory)); err != nil {
		t.Fatal(err)
	}

	if len(seen) != 2 || !slices.Equal(providerCallsWhenSeen, []int{0, 1}) {
		t.Fatalf("the observer saw %d requests, provider calls at those moments = %v, want 2 and [0 1]", len(seen), providerCallsWhenSeen)
	}
	for index, request := range seen {
		searchText := encodeForSearch(t, request)
		for _, planted := range append(plantedValues, projectDirectory) {
			if strings.Contains(searchText, planted) {
				t.Errorf("the observer saw %q in request %d", planted, index)
			}
		}
	}
	if !reflect.DeepEqual(seen[0], provider.recorded[0]) {
		t.Error("the observer saw a different request than the provider")
	}
}

func TestARequestWithoutALogEntryIsNotSent(t *testing.T) {
	provider := &fakeProvider{}
	sender, _ := newTestSender(t, provider)
	sender.Observe(func(Request) error { return errors.New("disk full " + fakeAWSKey) })

	_, err := sender.Send(context.Background(), Request{Messages: []Message{{Role: "user", Text: "hi"}}})

	if !errors.Is(err, ErrLogFailed) || provider.callCount != 0 || sender.Attempts() != 0 || strings.Contains(err.Error(), fakeAWSKey) {
		t.Errorf("err = %v, provider calls = %d, attempts = %d, want ErrLogFailed and nothing sent", err, provider.callCount, sender.Attempts())
	}
}

func TestPreviewDoesNotCallTheObserver(t *testing.T) {
	sender, _ := newTestSender(t, &fakeProvider{})
	called := 0
	sender.Observe(func(Request) error { called++; return nil })

	if _, err := sender.Preview(Request{Messages: []Message{{Role: "user", Text: "hi"}}}); err != nil || called != 0 {
		t.Errorf("err = %v, observer calls = %d, want none", err, called)
	}
}
