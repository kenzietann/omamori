package openaicompat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/outbound/internal/wire"
)

const fakeKey = "sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"

type capturedRequest struct {
	method string
	path   string
	header http.Header
	body   []byte
}

type fakeServer struct {
	*httptest.Server
	mutex    sync.Mutex
	captured []capturedRequest
}

func (server *fakeServer) requests() []capturedRequest {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	return append([]capturedRequest(nil), server.captured...)
}

func newFakeServer(t testing.TB, reply http.HandlerFunc) *fakeServer {
	t.Helper()

	server := &fakeServer{}
	server.Server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		server.mutex.Lock()
		server.captured = append(server.captured, capturedRequest{request.Method, request.URL.Path, request.Header.Clone(), body})
		server.mutex.Unlock()

		reply(writer, request)
	}))
	t.Cleanup(server.Close)

	return server
}

func answer(body string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		io.WriteString(writer, body)
	}
}

func chatAnswer(message, finishReason string, promptTokens, completionTokens int) http.HandlerFunc {
	return answer(fmt.Sprintf(`{"id":"c1","choices":[{"index":0,"message":%s,"finish_reason":%q}],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}}`,
		message, finishReason, promptTokens, completionTokens, promptTokens+completionTokens))
}

func failWith(status int, body string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		io.WriteString(writer, body)
	}
}

func newTestClient(t testing.TB, server *fakeServer, field string) *Client {
	t.Helper()

	client, err := New(Config{BaseURL: server.URL + "/v1", APIKey: fakeKey, Model: "test-model", MaxTokensField: field})
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func simpleRequest() wire.Request {
	return wire.Request{Messages: []wire.Message{{Role: "user", Text: "hello"}}}
}

func decode(t testing.TB, body []byte) map[string]any {
	t.Helper()

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the request body is not JSON: %v\n%s", err, body)
	}

	return decoded
}

func TestTheRequestHasTheRightShape(t *testing.T) {
	server := newFakeServer(t, chatAnswer(`{"role":"assistant","content":"ok"}`, "stop", 1, 1))
	client := newTestClient(t, server, "")

	request := wire.Request{
		System: "You help.",
		Tools: []wire.Tool{
			{Name: "read_file", Description: "Read a file.", Parameters: []wire.Parameter{{Name: "path", Description: "The path.", Required: true}}},
			{Name: "list_dir", Description: "List.", Parameters: []wire.Parameter{{Name: "path", Description: "Where."}}},
		},
		Messages: []wire.Message{
			{Role: "user", Text: "Scan it"},
			{Role: "assistant", Text: "Looking.", ToolCalls: []wire.ToolCall{{ID: "call_1", Name: "read_file", Arguments: map[string]string{"path": "a.go"}}}},
			{Role: "tool", ToolCallID: "call_1", Text: "tool_result read_file: first"},
		},
	}
	if _, err := client.Send(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	sent := server.requests()
	if len(sent) != 1 || sent[0].method != "POST" || sent[0].path != "/v1/chat/completions" {
		t.Fatalf("requests = %+v, want one POST to /v1/chat/completions", sent)
	}
	if sent[0].header.Get("Authorization") != "Bearer "+fakeKey || sent[0].header.Get("Content-Type") != "application/json" {
		t.Errorf("headers are wrong: %v", sent[0].header)
	}

	body := decode(t, sent[0].body)
	if body["model"] != "test-model" || body["max_tokens"] != float64(16000) {
		t.Errorf("model = %v, max_tokens = %v", body["model"], body["max_tokens"])
	}
	for _, forbidden := range []string{"stream", "temperature", "tool_choice", "max_completion_tokens"} {
		if _, present := body[forbidden]; present {
			t.Errorf("the request must not set %q", forbidden)
		}
	}

	messages := body["messages"].([]any)
	roles := []string{}
	for _, message := range messages {
		roles = append(roles, message.(map[string]any)["role"].(string))
	}
	if fmt.Sprint(roles) != "[system user assistant tool]" {
		t.Errorf("roles = %v", roles)
	}
	assistant := messages[2].(map[string]any)
	call := assistant["tool_calls"].([]any)[0].(map[string]any)
	function := call["function"].(map[string]any)
	if assistant["content"] != "Looking." || call["id"] != "call_1" || call["type"] != "function" || function["name"] != "read_file" || function["arguments"] != `{"path":"a.go"}` {
		t.Errorf("assistant message = %v", assistant)
	}
	if result := messages[3].(map[string]any); result["tool_call_id"] != "call_1" || result["content"] != "tool_result read_file: first" {
		t.Errorf("tool message = %v", result)
	}

	tools := body["tools"].([]any)
	first := tools[0].(map[string]any)["function"].(map[string]any)
	schema := first["parameters"].(map[string]any)
	if tools[0].(map[string]any)["type"] != "function" || first["name"] != "read_file" || first["description"] != "Read a file." {
		t.Errorf("tool = %v", tools[0])
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false || fmt.Sprint(schema["required"]) != "[path]" {
		t.Errorf("schema = %v", schema)
	}
	second := tools[1].(map[string]any)["function"].(map[string]any)["parameters"].(map[string]any)
	if fmt.Sprint(second["required"]) != "[]" {
		t.Errorf("a tool without required parameters must send an empty list: %v", second["required"])
	}
}

func TestTheOutputLimitHasTheNameThatTheProviderWants(t *testing.T) {
	for _, field := range []string{"max_tokens", "max_completion_tokens"} {
		server := newFakeServer(t, chatAnswer(`{"role":"assistant","content":"ok"}`, "stop", 1, 1))
		client := newTestClient(t, server, field)

		if _, err := client.Send(context.Background(), simpleRequest()); err != nil {
			t.Fatal(err)
		}

		body := decode(t, server.requests()[0].body)
		other := map[string]string{"max_tokens": "max_completion_tokens", "max_completion_tokens": "max_tokens"}[field]
		if body[field] != float64(16000) {
			t.Errorf("%s = %v, want 16000", field, body[field])
		}
		if _, present := body[other]; present {
			t.Errorf("the request also has %s", other)
		}
	}
}

func TestResultsOfOneTurnStayTogetherAndNotesComeAfterThem(t *testing.T) {
	request := wire.Request{Messages: []wire.Message{
		{Role: "user", Text: "go"},
		{Role: "assistant", ToolCalls: []wire.ToolCall{{ID: "a", Name: "x"}, {ID: "b", Name: "x"}, {ID: "c", Name: "x"}}},
		{Role: "tool", ToolCallID: "a", Text: "result a"},
		{Role: "tool", Text: "a note about a dropped call"},
		{Role: "tool", ToolCallID: "b", Text: "result b"},
		{Role: "tool", ToolCallID: "c", Text: "result c"},
		{Role: "user", Text: "next"},
	}}

	built, err := buildMessages(request)
	if err != nil {
		t.Fatal(err)
	}

	var order []string
	for _, message := range built {
		order = append(order, message.Role+":"+message.ToolCallID+message.Content)
	}
	want := "[user:go assistant: tool:aresult a tool:bresult b tool:cresult c user:a note about a dropped call user:next]"
	if got := fmt.Sprint(order); got != want {
		t.Errorf("order = %s\nwant    %s", got, want)
	}
}

func TestMessageConversionEdgeCases(t *testing.T) {
	testCases := []struct {
		name         string
		messages     []wire.Message
		wantMessages int
		wantErr      error
	}{
		{"an empty assistant message is skipped", []wire.Message{{Role: "user", Text: "a"}, {Role: "assistant"}, {Role: "user", Text: "b"}}, 2, nil},
		{"empty user text is replaced", []wire.Message{{Role: "user"}}, 1, nil},
		{"a tool call without an ID", []wire.Message{{Role: "assistant", ToolCalls: []wire.ToolCall{{Name: "x"}}}}, 0, wire.ErrBadRequest},
		{"an unknown role", []wire.Message{{Role: "system", Text: "x"}}, 0, wire.ErrBadRequest},
		{"only a note", []wire.Message{{Role: "tool", Text: "note"}}, 1, nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			built, err := buildMessages(wire.Request{Messages: testCase.messages})

			if !errors.Is(err, testCase.wantErr) || len(built) != testCase.wantMessages {
				t.Errorf("messages = %d, err = %v, want %d and %v", len(built), err, testCase.wantMessages, testCase.wantErr)
			}
		})
	}

	built, _ := buildMessages(wire.Request{Messages: []wire.Message{{Role: "user"}, {Role: "assistant", ToolCalls: []wire.ToolCall{{ID: "t", Name: "x"}}}, {Role: "tool", ToolCallID: "t"}}})
	encoded, _ := json.Marshal(built)
	if !strings.Contains(string(encoded), `"(empty)"`) {
		t.Errorf("an empty text must be replaced: %s", encoded)
	}
}

func TestResponsesAreParsed(t *testing.T) {
	testCases := []struct {
		name       string
		message    string
		finish     string
		wantText   string
		wantCalls  []wire.ToolCall
		wantTokens int
		wantErr    error
	}{
		{"text", `{"role":"assistant","content":"Hello"}`, "stop", "Hello", nil, 30, nil},
		{"null content with a tool call", `{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a.go\"}"}}]}`, "tool_calls",
			"", []wire.ToolCall{{ID: "call_1", Name: "read_file", Arguments: map[string]string{"path": "a.go"}}}, 30, nil},
		{"two tool calls", `{"role":"assistant","content":"Reading","tool_calls":[{"id":"c1","type":"function","function":{"name":"a","arguments":"{}"}},{"id":"c2","type":"function","function":{"name":"b","arguments":"{\"q\":\"x\"}"}}]}`, "tool_calls",
			"Reading", []wire.ToolCall{{ID: "c1", Name: "a", Arguments: map[string]string{}}, {ID: "c2", Name: "b", Arguments: map[string]string{"q": "x"}}}, 30, nil},
		{"arguments of other types are kept as JSON text", `{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"a","arguments":"{\"n\":5,\"f\":true}"}}]}`, "tool_calls",
			"", []wire.ToolCall{{ID: "c1", Name: "a", Arguments: map[string]string{"n": "5", "f": "true"}}}, 30, nil},
		{"unreadable arguments become none", `{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"a","arguments":"not json"}}]}`, "tool_calls",
			"", []wire.ToolCall{{ID: "c1", Name: "a", Arguments: map[string]string{}}}, 30, nil},
		{"a cut-off text answer is kept", `{"role":"assistant","content":"Part"}`, "length", "Part", nil, 30, nil},
		{"a cut-off tool call is refused", `{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"a","arguments":"{\"pa"}}]}`, "length", "", nil, 0, wire.ErrBadResponse},
		{"a content filter is a refusal", `{"role":"assistant","content":""}`, "content_filter", "", nil, 0, wire.ErrRefused},
		{"a refusal message", `{"role":"assistant","content":null,"refusal":"I cannot help"}`, "stop", "", nil, 0, wire.ErrRefused},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newTestClient(t, newFakeServer(t, chatAnswer(testCase.message, testCase.finish, 10, 20)), "")

			got, err := client.Send(context.Background(), simpleRequest())

			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("err = %v, want %v", err, testCase.wantErr)
			}
			if err != nil {
				return
			}
			if got.Text != testCase.wantText || got.TokensUsed != testCase.wantTokens {
				t.Errorf("text = %q, tokens = %d, want %q and %d", got.Text, got.TokensUsed, testCase.wantText, testCase.wantTokens)
			}
			if len(got.ToolCalls) != len(testCase.wantCalls) {
				t.Fatalf("tool calls = %+v, want %+v", got.ToolCalls, testCase.wantCalls)
			}
			for index, want := range testCase.wantCalls {
				if got.ToolCalls[index].ID != want.ID || got.ToolCalls[index].Name != want.Name || fmt.Sprint(got.ToolCalls[index].Arguments) != fmt.Sprint(want.Arguments) {
					t.Errorf("tool call %d = %+v, want %+v", index, got.ToolCalls[index], want)
				}
			}
		})
	}
}

func TestAnswersThatAreNotChatAnswersAreRefused(t *testing.T) {
	bodies := map[string]string{
		"no choices":      `{"choices":[]}`,
		"an empty object": `{}`,
		"a web page":      `<html><body>Sign in</body></html>`,
		"empty":           ``,
		"a list":          `[1,2,3]`,
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, newFakeServer(t, answer(body)), "")

			if _, err := client.Send(context.Background(), simpleRequest()); !errors.Is(err, wire.ErrBadResponse) {
				t.Errorf("err = %v, want ErrBadResponse", err)
			}
		})
	}
}

func TestAnAnswerThatIsTooBigIsRefused(t *testing.T) {
	// The start is a good answer. Without the size limit it would be accepted, because
	// white space after a JSON value does no harm. So only the limit can refuse it.
	big := func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		io.WriteString(writer, `{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
		chunk := strings.Repeat(" ", 1<<20)
		for written := 0; written <= wire.MaxResponseBytes; written += len(chunk) {
			io.WriteString(writer, chunk)
		}
	}
	client := newTestClient(t, newFakeServer(t, big), "")

	if _, err := client.Send(context.Background(), simpleRequest()); !errors.Is(err, wire.ErrBadResponse) {
		t.Errorf("err = %v, want ErrBadResponse", err)
	}

	small := newTestClient(t, newFakeServer(t, chatAnswer(`{"role":"assistant","content":"ok"}`, "stop", 1, 1)), "")
	if _, err := small.Send(context.Background(), simpleRequest()); err != nil {
		t.Errorf("a normal answer was refused: %v", err)
	}
}

func TestErrorsAreMappedAndNeverCarryTheServerText(t *testing.T) {
	testCases := []struct {
		status  int
		wantErr error
	}{
		{400, wire.ErrRejected}, {401, wire.ErrAuth}, {403, wire.ErrAuth}, {404, wire.ErrRejected}, {422, wire.ErrRejected},
		{408, wire.ErrRetryable}, {409, wire.ErrRetryable}, {429, wire.ErrRetryable}, {500, wire.ErrRetryable}, {503, wire.ErrRetryable}, {529, wire.ErrRetryable},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprint(testCase.status), func(t *testing.T) {
			secret := "AKIAIOSFODNN7EXAMPLE and 090-1234-5678"
			client := newTestClient(t, newFakeServer(t, failWith(testCase.status, fmt.Sprintf(`{"error":{"message":%q}}`, "echo: "+secret))), "")

			_, err := client.Send(context.Background(), simpleRequest())

			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("err = %v, want %v", err, testCase.wantErr)
			}
			if strings.Contains(err.Error(), "AKIA") || strings.Contains(err.Error(), "090-") || strings.Contains(err.Error(), "echo") {
				t.Errorf("the error carries the server text: %v", err)
			}
		})
	}
}

func TestNothingIsRetriedInsideTheClient(t *testing.T) {
	server := newFakeServer(t, failWith(503, `{}`))
	client := newTestClient(t, server, "")

	_, err := client.Send(context.Background(), simpleRequest())

	if !errors.Is(err, wire.ErrRetryable) || len(server.requests()) != 1 {
		t.Errorf("err = %v, requests = %d, want one request: the sender owns the retries", err, len(server.requests()))
	}
}

func TestBrokenConnectionsAndTimeoutsAreRetryable(t *testing.T) {
	closed := newFakeServer(t, chatAnswer(`{"role":"assistant","content":"x"}`, "stop", 1, 1))
	closed.Close()
	client, err := New(Config{BaseURL: closed.URL, APIKey: fakeKey, Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(context.Background(), simpleRequest()); !errors.Is(err, wire.ErrRetryable) {
		t.Errorf("connection refused: err = %v, want ErrRetryable", err)
	}

	slow := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) { time.Sleep(400 * time.Millisecond) })
	quick, err := New(Config{BaseURL: slow.URL, APIKey: fakeKey, Model: "m", Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := quick.Send(context.Background(), simpleRequest()); !errors.Is(err, wire.ErrRetryable) {
		t.Errorf("timeout: err = %v, want ErrRetryable", err)
	}
}

func TestACancelledContextIsNotAProviderProblem(t *testing.T) {
	client := newTestClient(t, newFakeServer(t, chatAnswer(`{"role":"assistant","content":"x"}`, "stop", 1, 1)), "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.Send(ctx, simpleRequest())

	if !errors.Is(err, context.Canceled) || errors.Is(err, wire.ErrRetryable) {
		t.Errorf("err = %v, want context.Canceled and not a retryable error", err)
	}
}

func TestTheKeyIsOnlyInTheAuthorizationHeader(t *testing.T) {
	server := newFakeServer(t, chatAnswer(`{"role":"assistant","content":"x"}`, "stop", 1, 1))
	client := newTestClient(t, server, "")

	if _, err := client.Send(context.Background(), wire.Request{System: "s", Messages: []wire.Message{{Role: "user", Text: "hello"}}}); err != nil {
		t.Fatal(err)
	}

	sent := server.requests()[0]
	if strings.Contains(string(sent.body), fakeKey) || strings.Contains(sent.path, fakeKey) {
		t.Error("the key is in the body or in the path")
	}
	for name, values := range sent.header {
		if name != "Authorization" && strings.Contains(strings.Join(values, ","), fakeKey) {
			t.Errorf("the key is in the header %s", name)
		}
	}
	for _, shown := range []string{fmt.Sprintf("%v", client), fmt.Sprintf("%+v", client), fmt.Sprintf("%#v", client), fmt.Sprintf("%s", client)} {
		if strings.Contains(shown, "FAKE") || strings.Contains(shown, "sk-") {
			t.Errorf("formatting the client shows the key: %q", shown)
		}
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	elsewhere := newFakeServer(t, chatAnswer(`{"role":"assistant","content":"x"}`, "stop", 1, 1))
	redirecting := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, elsewhere.URL+"/v1/chat/completions", http.StatusTemporaryRedirect)
	})
	client := newTestClient(t, redirecting, "")

	_, err := client.Send(context.Background(), simpleRequest())

	if err == nil || len(elsewhere.requests()) != 0 {
		t.Errorf("err = %v, requests that reached the other host = %d, want an error and none", err, len(elsewhere.requests()))
	}
}

func TestTheEnvironmentDoesNotChangeTheRequest(t *testing.T) {
	elsewhere := newFakeServer(t, chatAnswer(`{"role":"assistant","content":"x"}`, "stop", 1, 1))
	intended := newFakeServer(t, chatAnswer(`{"role":"assistant","content":"x"}`, "stop", 1, 1))
	for _, name := range []string{"OPENAI_BASE_URL", "OPENAI_API_BASE", "OPENROUTER_BASE_URL", "OLLAMA_HOST"} {
		t.Setenv(name, elsewhere.URL)
	}
	t.Setenv("OPENAI_API_KEY", "sk-ENVIRONMENT-KEY")
	t.Setenv("OPENAI_ORGANIZATION", "org-evil")

	client := newTestClient(t, intended, "")
	if _, err := client.Send(context.Background(), simpleRequest()); err != nil {
		t.Fatal(err)
	}

	header := intended.requests()[0].header
	if len(elsewhere.requests()) != 0 || header.Get("Authorization") != "Bearer "+fakeKey || header.Get("OpenAI-Organization") != "" {
		t.Errorf("the environment changed the request: elsewhere = %d, headers = %v", len(elsewhere.requests()), header)
	}
}

func TestAProviderOnThisComputerNeedsNoKey(t *testing.T) {
	server := newFakeServer(t, chatAnswer(`{"role":"assistant","content":"x"}`, "stop", 1, 1))
	client, err := New(Config{BaseURL: server.URL + "/v1", Model: "llama"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Send(context.Background(), simpleRequest()); err != nil {
		t.Fatal(err)
	}

	if header := server.requests()[0].header; header.Get("Authorization") != "" {
		t.Errorf("an Authorization header was sent without a key: %v", header)
	}
}

func TestNewChecksItsSettings(t *testing.T) {
	testCases := []struct {
		name    string
		config  Config
		wantErr error
	}{
		{"a good setting", Config{BaseURL: "https://api.example.com/v1", APIKey: fakeKey, Model: "m"}, nil},
		{"no model", Config{BaseURL: "https://api.example.com/v1", APIKey: fakeKey}, wire.ErrBadConfig},
		{"no key for a remote provider", Config{BaseURL: "https://api.example.com/v1", Model: "m"}, wire.ErrNoKey},
		{"no key for this computer", Config{BaseURL: "http://127.0.0.1:11434/v1", Model: "m"}, nil},
		{"plain http to another host", Config{BaseURL: "http://api.example.com/v1", APIKey: fakeKey, Model: "m"}, wire.ErrBadConfig},
		{"a user name in the address", Config{BaseURL: "https://u:p@api.example.com", APIKey: fakeKey, Model: "m"}, wire.ErrBadConfig},
		{"a name that starts like localhost", Config{BaseURL: "http://localhost.evil.example", APIKey: fakeKey, Model: "m"}, wire.ErrBadConfig},
		{"no address", Config{APIKey: fakeKey, Model: "m"}, wire.ErrBadConfig},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := New(testCase.config); !errors.Is(err, testCase.wantErr) {
				t.Errorf("err = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

func TestABadRequestIsNotSent(t *testing.T) {
	server := newFakeServer(t, chatAnswer(`{"role":"assistant","content":"x"}`, "stop", 1, 1))
	client := newTestClient(t, server, "")

	_, err := client.Send(context.Background(), wire.Request{Messages: []wire.Message{{Role: "system", Text: "x"}}})

	if !errors.Is(err, wire.ErrBadRequest) || len(server.requests()) != 0 {
		t.Errorf("err = %v, requests = %d, want ErrBadRequest and nothing sent", err, len(server.requests()))
	}
}

func FuzzBuildMessages(f *testing.F) {
	f.Add("user", "hello", "", "")
	f.Add("assistant", "", "call_1", "read_file")
	f.Add("tool", "result", "call_1", "")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, role, text, callID, name string) {
		built, err := buildMessages(wire.Request{System: text, Messages: []wire.Message{
			{Role: "user", Text: "start"},
			{Role: role, Text: text, ToolCallID: callID, ToolCalls: []wire.ToolCall{{ID: callID, Name: name, Arguments: map[string]string{"path": text}}}},
			{Role: "tool", Text: text, ToolCallID: callID},
		}})
		if err != nil {
			if !errors.Is(err, wire.ErrBadRequest) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}

		for _, message := range built {
			if (message.Role == "user" || message.Role == "tool") && message.Content == "" {
				t.Fatalf("an empty %s message would be sent", message.Role)
			}
		}
		if _, err := json.Marshal(built); err != nil {
			t.Fatalf("the messages cannot be encoded: %v", err)
		}
	})
}

func FuzzParseResponse(f *testing.F) {
	f.Add(`{"choices":[{"message":{"content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1}}`)
	f.Add(`{"choices":[{"message":{"tool_calls":[{"id":"a","function":{"name":"n","arguments":"{}"}}]},"finish_reason":"length"}]}`)
	f.Add(`not json`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, raw string) {
		if _, err := parseResponse([]byte(raw)); err != nil && !errors.Is(err, wire.ErrBadResponse) && !errors.Is(err, wire.ErrRefused) {
			t.Fatalf("unexpected error kind: %v", err)
		}
	})
}

func TestListModels(t *testing.T) {
	server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, `{"data":[{"id":"zeta"},{"id":"text-embedding-x"},{"id":"alpha"},{"id":"alpha"}]}`)
	})

	gotIDs, err := ListModels(context.Background(), server.URL+"/v1", fakeKey, time.Second)

	if err != nil || !slices.Equal(gotIDs, []string{"alpha", "zeta"}) {
		t.Fatalf("got %q, err %v", gotIDs, err)
	}
	sent := server.requests()
	if len(sent) != 1 || sent[0].method != http.MethodGet || sent[0].path != "/v1/models" || sent[0].header.Get("Authorization") != "Bearer "+fakeKey || len(sent[0].body) != 0 {
		t.Errorf("the request is wrong: %+v", sent)
	}
}

func TestListModelsErrors(t *testing.T) {
	testCases := []struct {
		name    string
		baseURL string
		key     string
		reply   http.HandlerFunc
		wantErr error
	}{
		{"a key is wrong", "ok", fakeKey, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }, wire.ErrAuth},
		{"the server is down", "ok", fakeKey, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }, wire.ErrRetryable},
		{"the answer is not JSON", "ok", fakeKey, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<html>") }, wire.ErrBadResponse},
		{"a redirect is not followed", "ok", fakeKey, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://127.0.0.1:1/x", 302) }, wire.ErrRejected},
		{"a remote address over plain http", "http://example.com/v1", fakeKey, nil, wire.ErrBadConfig},
		{"no key for a remote address", "https://example.com/v1", "", nil, wire.ErrNoKey},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			baseURL := testCase.baseURL
			if baseURL == "ok" {
				baseURL = newFakeServer(t, testCase.reply).URL
			}

			_, err := ListModels(context.Background(), baseURL, testCase.key, time.Second)

			if !errors.Is(err, testCase.wantErr) {
				t.Errorf("err = %v, want %v", err, testCase.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), fakeKey) {
				t.Error("the error holds the key")
			}
		})
	}
}

func TestListModelsWorksWithoutAKeyOnThisComputer(t *testing.T) {
	server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, `{"data":[{"id":"local-model"}]}`)
		if request.Header.Get("Authorization") != "" {
			t.Error("a header was sent without a key")
		}
	})

	gotIDs, err := ListModels(context.Background(), server.URL, "", time.Second)

	if err != nil || !slices.Equal(gotIDs, []string{"local-model"}) {
		t.Errorf("got %q, err %v", gotIDs, err)
	}
}

func TestARejectedRequestReportsTheStatusAndCodeOnly(t *testing.T) {
	server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(404)
		fmt.Fprint(writer, `{"error":{"message":"The model `+"`secret-model-name`"+` does not exist","type":"invalid_request_error","code":"model_not_found"}}`)
	})
	client := newTestClient(t, server, "")

	_, err := client.Send(context.Background(), wire.Request{Messages: []wire.Message{{Role: "user", Text: "hello"}}})

	var rejection *wire.Rejection
	if !errors.Is(err, wire.ErrRejected) || !errors.As(err, &rejection) || rejection.Detail() != "status 404, code model_not_found" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "secret-model-name") {
		t.Error("the message of the provider is shown")
	}
}

func TestListModelsDropsModelsThatCannotChatOrCallTools(t *testing.T) {
	server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, `{"data":[
			{"id":"good","capabilities":{"completion_chat":true,"function_calling":true}},
			{"id":"no-tools","capabilities":{"completion_chat":true,"function_calling":false}},
			{"id":"no-chat","capabilities":{"completion_chat":false,"function_calling":true}},
			{"id":"unknown-abilities"},
			{"id":"partial","capabilities":{"vision":true}}]}`)
	})

	gotIDs, err := ListModels(context.Background(), server.URL+"/v1", fakeKey, time.Second)

	if err != nil || !slices.Equal(gotIDs, []string{"good", "partial", "unknown-abilities"}) {
		t.Errorf("got %q, err %v", gotIDs, err)
	}
}

func rejectReasoning(writer http.ResponseWriter) {
	writer.WriteHeader(400)
	fmt.Fprint(writer, `{"error":{"message":"Function tools with reasoning_effort are not supported","type":"invalid_request_error","param":"reasoning_effort","code":null}}`)
}

func clientWithFallback(t testing.TB, server *fakeServer, fallback string) *Client {
	t.Helper()

	client, err := New(Config{BaseURL: server.URL + "/v1", APIKey: fakeKey, Model: "test-model", ReasoningFallback: fallback})
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func sentEffort(t testing.TB, body []byte) (string, bool) {
	t.Helper()

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	effort, present := decoded["reasoning_effort"].(string)

	return effort, present
}

func TestReasoningFallbackRetriesOnceAndIsRemembered(t *testing.T) {
	var server *fakeServer
	server = newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) {
		captured := server.requests()
		if _, present := sentEffort(t, captured[len(captured)-1].body); !present {
			rejectReasoning(writer)
			return
		}
		fmt.Fprint(writer, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	})
	client := clientWithFallback(t, server, "none")
	request := wire.Request{Messages: []wire.Message{{Role: "user", Text: "hello"}}}

	for attempt := range 2 {
		if response, err := client.Send(context.Background(), request); err != nil || response.Text != "ok" {
			t.Fatalf("send %d: %+v, %v", attempt, response, err)
		}
	}

	sent := server.requests()
	if len(sent) != 3 {
		t.Fatalf("%d requests, want 3: one rejected, one retried, one that already has the setting", len(sent))
	}
	if _, present := sentEffort(t, sent[0].body); present {
		t.Error("the first request already had the setting")
	}
	for _, later := range sent[1:] {
		if effort, _ := sentEffort(t, later.body); effort != "none" {
			t.Errorf("effort = %q, want none", effort)
		}
	}
}

func TestReasoningFallbackDoesNotLoopOrApplyToOtherProblems(t *testing.T) {
	testCases := []struct {
		name         string
		fallback     string
		reply        func(http.ResponseWriter)
		wantRequests int
	}{
		{"no fallback is set", "", rejectReasoning, 1},
		{"the retry fails too", "none", rejectReasoning, 2},
		{"another field is the cause", "none", func(writer http.ResponseWriter) {
			writer.WriteHeader(400)
			fmt.Fprint(writer, `{"error":{"param":"tools","type":"invalid_request_error"}}`)
		}, 1},
		{"a server error", "none", func(writer http.ResponseWriter) { writer.WriteHeader(500) }, 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) { testCase.reply(writer) })
			client := clientWithFallback(t, server, testCase.fallback)

			_, err := client.Send(context.Background(), wire.Request{Messages: []wire.Message{{Role: "user", Text: "hello"}}})

			if err == nil || len(server.requests()) != testCase.wantRequests {
				t.Errorf("err = %v, requests = %d, want %d", err, len(server.requests()), testCase.wantRequests)
			}
		})
	}
}

func TestAChosenReasoningLevelIsSentOnEveryRequestAndNeverReplacedByTheFallback(t *testing.T) {
	server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`)
	})
	client, err := New(Config{BaseURL: server.URL + "/v1", APIKey: fakeKey, Model: "m", Reasoning: "high", ReasoningFallback: "none"})
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if _, err := client.Send(context.Background(), wire.Request{Messages: []wire.Message{{Role: "user", Text: "hi"}}}); err != nil {
			t.Fatal(err)
		}
	}

	for _, sent := range server.requests() {
		if effort, _ := sentEffort(t, sent.body); effort != "high" {
			t.Errorf("effort = %q, want high", effort)
		}
	}
}

func TestAChosenReasoningLevelThatTheProviderRejectsIsNotRetried(t *testing.T) {
	server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) { rejectReasoning(writer) })
	client, err := New(Config{BaseURL: server.URL + "/v1", APIKey: fakeKey, Model: "m", Reasoning: "high", ReasoningFallback: "none"})
	if err != nil {
		t.Fatal(err)
	}

	_, sendErr := client.Send(context.Background(), wire.Request{Messages: []wire.Message{{Role: "user", Text: "hi"}}})

	if !errors.Is(sendErr, wire.ErrRejected) || len(server.requests()) != 1 {
		t.Errorf("err = %v, requests = %d: the user's choice must not be changed silently", sendErr, len(server.requests()))
	}
}

func TestAReasoningLevelWithOddCharactersIsRefused(t *testing.T) {
	for _, level := range []string{"HIGH", "high\n", "a b", "x", "toolongvalue1", `high","model":"x`, "none;"} {
		if _, err := New(Config{BaseURL: "https://example.com/v1", APIKey: fakeKey, Model: "m", Reasoning: level}); !errors.Is(err, wire.ErrBadConfig) {
			t.Errorf("%q: err = %v", level, err)
		}
	}
}
