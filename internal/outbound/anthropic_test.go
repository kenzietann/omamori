package outbound

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const apiTestKey = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"

type apiServer struct {
	*httptest.Server
	mutex  sync.Mutex
	bodies []string
	calls  int
}

func (server *apiServer) requestBodies() []string {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	return append([]string(nil), server.bodies...)
}

func newAPIServer(t testing.TB, handlers ...http.HandlerFunc) *apiServer {
	t.Helper()

	server := &apiServer{}
	server.Server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)

		server.mutex.Lock()
		server.bodies = append(server.bodies, string(body))
		index := min(server.calls, len(handlers)-1)
		server.calls++
		server.mutex.Unlock()

		handlers[index](writer, request)
	}))
	t.Cleanup(server.Close)

	return server
}

func okAnswer(content, stopReason string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5","content":[%s],"stop_reason":%q,"stop_sequence":null,"usage":{"input_tokens":100,"output_tokens":20,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}`, content, stopReason)
	}
}

func statusAnswer(status int) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		io.WriteString(writer, `{"type":"error","error":{"type":"x","message":"no"}}`)
	}
}

func newAPISender(t testing.TB, server *apiServer) (*Sender, string) {
	t.Helper()

	provider, err := newAnthropicAt(apiTestKey, "", server.URL)
	if err != nil {
		t.Fatal(err)
	}

	return newTestSender(t, provider)
}

func TestTheProviderOnlyReceivesCleanText(t *testing.T) {
	server := newAPIServer(t,
		statusAnswer(529),
		okAnswer(`{"type":"tool_use","id":"toolu_01ABC","name":"read_file","input":{"path":"src/app.go"}}`, "tool_use"),
		okAnswer(`{"type":"text","text":"Done."}`, "end_turn"),
	)
	sender, projectDirectory := newAPISender(t, server)

	request := plantedRequest(projectDirectory)
	request.Tools = []ToolSpec{{
		Name:        "read_file",
		Description: "Read a file. Example key " + fakeAWSKey + " in " + projectDirectory,
		Parameters:  []ToolParameter{{Name: "path", Description: "call " + fakePhone, Required: true}},
	}}
	request.Messages[1].ToolCalls[0].ID = "toolu_01ABC"
	request.Messages[2].ToolCallID = "toolu_01ABC"

	first, err := sender.Send(context.Background(), request)
	if err != nil || len(first.ToolCalls) != 1 || first.ToolCalls[0].ID != "toolu_01ABC" || first.TokensUsed != 120 {
		t.Fatalf("first answer = %+v, err = %v", first, err)
	}
	request.Messages = append(request.Messages,
		Message{Role: "assistant", ToolCalls: first.ToolCalls},
		Message{Role: "tool", ToolCallID: first.ToolCalls[0].ID, Text: "mynumber=" + fakeMyNumber},
	)
	if _, err := sender.Send(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	bodies := server.requestBodies()
	if len(bodies) != 3 || sender.Attempts() != 3 {
		t.Fatalf("the server saw %d requests and the sender made %d attempts, want 3 and 3 (1 retry and 2 turns)", len(bodies), sender.Attempts())
	}
	for index, body := range bodies {
		for _, planted := range append(plantedValues, projectDirectory, apiTestKey) {
			if strings.Contains(body, planted) {
				t.Errorf("request %d contains %q", index, planted)
			}
		}
		for _, want := range []string{"[SECRET:aws-access-key:", "src/app.go", `"strict":true`, `"id":"toolu_01ABC"`, `"tool_use_id":"toolu_01ABC"`} {
			if !strings.Contains(body, want) {
				t.Errorf("request %d has no %q", index, want)
			}
		}
	}
	if bodies[0] != bodies[1] {
		t.Error("the retry did not send the same cleaned request as the first attempt")
	}
}

func TestProviderProblemsStopOrRetryAsTheyShould(t *testing.T) {
	testCases := []struct {
		name         string
		handlers     []http.HandlerFunc
		wantErr      error
		wantRequests int
	}{
		{"a bad key stops at once", []http.HandlerFunc{statusAnswer(401)}, ErrAuth, 1},
		{"forbidden also means the key", []http.HandlerFunc{statusAnswer(403)}, ErrAuth, 1},
		{"a refusal stops at once", []http.HandlerFunc{okAnswer(`{"type":"text","text":"no"}`, "refusal")}, ErrRefused, 1},
		{"a rejected request is not retried", []http.HandlerFunc{statusAnswer(400)}, ErrProviderFailed, 1},
		{"overload is retried until the limit", []http.HandlerFunc{statusAnswer(529)}, ErrProviderFailed, 3},
		{"rate limiting is retried", []http.HandlerFunc{statusAnswer(429), okAnswer(`{"type":"text","text":"ok"}`, "end_turn")}, nil, 2},
		{"a cut-off tool call is not used", []http.HandlerFunc{okAnswer(`{"type":"tool_use","id":"toolu_1","name":"list_dir","input":{}}`, "max_tokens")}, ErrProviderFailed, 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			server := newAPIServer(t, testCase.handlers...)
			sender, _ := newAPISender(t, server)

			_, err := sender.Send(context.Background(), Request{Messages: []Message{{Role: "user", Text: "hi"}}})

			if !errors.Is(err, testCase.wantErr) || len(server.requestBodies()) != testCase.wantRequests {
				t.Errorf("err = %v, requests = %d, want %v and %d", err, len(server.requestBodies()), testCase.wantErr, testCase.wantRequests)
			}
		})
	}
}

func TestCancelStopsARequestThatIsWaiting(t *testing.T) {
	server := newAPIServer(t, func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	sender, _ := newAPISender(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := sender.Send(ctx, Request{Messages: []Message{{Role: "user", Text: "hi"}}})

	if !errors.Is(err, ErrCancelled) || time.Since(started) > 3*time.Second || len(server.requestBodies()) != 1 {
		t.Errorf("err = %v after %v with %d requests, want ErrCancelled, quickly, and no new request", err, time.Since(started), len(server.requestBodies()))
	}
}

func TestNewAnthropicNeedsAKey(t *testing.T) {
	if _, err := NewAnthropic("", ""); !errors.Is(err, ErrInvalidSetup) {
		t.Errorf("err = %v, want ErrInvalidSetup", err)
	}
	if _, err := newAnthropicAt(apiTestKey, "", "http://evil.example.com"); !errors.Is(err, ErrInvalidSetup) {
		t.Errorf("a plain http address to another host: err = %v, want ErrInvalidSetup", err)
	}

	provider, err := NewAnthropic(apiTestKey, "")
	if err != nil || provider.Name() != "Anthropic" {
		t.Fatalf("provider = %v, err = %v", provider, err)
	}
	for _, shown := range []string{fmt.Sprintf("%v", provider), fmt.Sprintf("%+v", provider), fmt.Sprintf("%#v", provider)} {
		if strings.Contains(shown, "api03") || strings.Contains(shown, "FAKE") {
			t.Errorf("formatting the provider shows the key: %q", shown)
		}
	}
}

func TestOnlyTheClientPackageImportsTheSDK(t *testing.T) {
	const sdkPrefix = "github.com/anthropics/anthropic-sdk-go"
	clientDirectory := filepath.ToSlash(filepath.Join("internal", "outbound", "internal", "anthropicclient"))
	moduleRoot := filepath.Join("..", "..")

	importers := 0
	err := filepath.WalkDir(moduleRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "testdata") {
			return fs.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		relative, err := filepath.Rel(moduleRoot, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)

		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range parsed.Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)

			inClient := strings.HasPrefix(relative, clientDirectory+"/")
			if strings.HasPrefix(importPath, sdkPrefix) {
				if !inClient {
					t.Errorf("%s imports the provider SDK, but only the client package may", relative)
				}
				importers++
			}
			if strings.Contains(importPath, "outbound/internal/anthropicclient") && !strings.HasPrefix(relative, "internal/outbound/") {
				t.Errorf("%s imports the client package, but only outbound may", relative)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if importers == 0 {
		t.Error("no file imports the SDK, so the check looked in the wrong place")
	}
}
