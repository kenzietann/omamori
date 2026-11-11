package anthropicclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const fakeKey = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"

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

func answer(content, stopReason string, input, output, cacheWrite, cacheRead int) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5","content":[%s],"stop_reason":%q,"stop_sequence":null,"usage":{"input_tokens":%d,"output_tokens":%d,"cache_creation_input_tokens":%d,"cache_read_input_tokens":%d}}`,
			content, stopReason, input, output, cacheWrite, cacheRead)
	}
}

func failWith(status int, body string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		io.WriteString(writer, body)
	}
}

func newTestClient(t testing.TB, server *fakeServer) *Client {
	t.Helper()

	client, err := New(fakeKey, "", server.URL)
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func decode(t testing.TB, body []byte) map[string]any {
	t.Helper()

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the request body is not JSON: %v\n%s", err, body)
	}

	return decoded
}

func simpleRequest() Request {
	return Request{Messages: []Message{{Role: "user", Text: "hello"}}}
}

func TestTheRequestHasTheRightShape(t *testing.T) {
	server := newFakeServer(t, answer(`{"type":"text","text":"ok"}`, "end_turn", 1, 1, 0, 0))
	client := newTestClient(t, server)

	request := Request{
		System: "You help.",
		Tools: []Tool{{Name: "read_file", Description: "Read a file.", Parameters: []Parameter{
			{Name: "path", Description: "The path.", Required: true},
			{Name: "limit", Description: "A limit."},
		}}},
		Messages: []Message{
			{Role: "user", Text: "Scan it"},
			{Role: "assistant", Text: "Looking.", ToolCalls: []ToolCall{
				{ID: "toolu_one", Name: "read_file", Arguments: map[string]string{"path": "a.go"}},
				{ID: "toolu_two", Name: "read_file", Arguments: map[string]string{"path": "b.go"}},
			}},
			{Role: "tool", ToolCallID: "toolu_one", Text: "tool_result read_file: first"},
			{Role: "tool", Text: "a note without an ID"},
			{Role: "tool", ToolCallID: "toolu_two", Text: "tool_result read_file: second"},
		},
	}
	if _, err := client.Send(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	sent := server.requests()
	if len(sent) != 1 || sent[0].method != "POST" || sent[0].path != "/v1/messages" {
		t.Fatalf("requests = %+v, want one POST to /v1/messages", sent)
	}
	if sent[0].header.Get("Authorization") != "Bearer "+fakeKey || sent[0].header.Get("Anthropic-Version") == "" || sent[0].header.Get("X-Api-Key") != "" {
		t.Errorf("headers are wrong: %v", sent[0].header)
	}

	body := decode(t, sent[0].body)
	if body["model"] != "claude-opus-5-5" || body["max_tokens"] != float64(16000) {
		t.Errorf("model = %v, max_tokens = %v", body["model"], body["max_tokens"])
	}
	if effort := body["output_config"].(map[string]any)["effort"]; effort != "medium" {
		t.Errorf("effort = %v, want medium", effort)
	}
	if cache, _ := body["cache_control"].(map[string]any); cache["type"] != "ephemeral" {
		t.Errorf("cache_control = %v", body["cache_control"])
	}
	for _, forbidden := range []string{"thinking", "temperature", "top_p", "top_k", "tool_choice", "stream"} {
		if _, present := body[forbidden]; present {
			t.Errorf("the request must not set %q on this model", forbidden)
		}
	}
	if system := body["system"].([]any)[0].(map[string]any); system["text"] != "You help." {
		t.Errorf("system = %v", body["system"])
	}

	tool := body["tools"].([]any)[0].(map[string]any)
	schema := tool["input_schema"].(map[string]any)
	if tool["name"] != "read_file" || tool["description"] != "Read a file." || tool["strict"] != true {
		t.Errorf("tool = %v", tool)
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false || fmt.Sprint(schema["required"]) != "[path]" {
		t.Errorf("schema = %v", schema)
	}
	if property := schema["properties"].(map[string]any)["path"].(map[string]any); property["type"] != "string" || property["description"] != "The path." {
		t.Errorf("path property = %v", property)
	}

	messages := body["messages"].([]any)
	if len(messages) != 3 {
		t.Fatalf("%d messages were sent, want 3 (the three tool messages are one user turn)", len(messages))
	}
	assistant := messages[1].(map[string]any)["content"].([]any)
	if len(assistant) != 3 || assistant[0].(map[string]any)["type"] != "text" || assistant[1].(map[string]any)["id"] != "toolu_one" || assistant[2].(map[string]any)["id"] != "toolu_two" {
		t.Errorf("assistant blocks = %v", assistant)
	}
	if input := assistant[1].(map[string]any)["input"].(map[string]any); input["path"] != "a.go" {
		t.Errorf("tool_use input = %v", input)
	}
	results := messages[2].(map[string]any)["content"].([]any)
	types := []string{}
	for _, block := range results {
		types = append(types, block.(map[string]any)["type"].(string))
	}
	if fmt.Sprint(types) != "[tool_result tool_result text]" {
		t.Errorf("result blocks are %v, want the results first and the note last", types)
	}
	if results[0].(map[string]any)["tool_use_id"] != "toolu_one" || results[1].(map[string]any)["tool_use_id"] != "toolu_two" {
		t.Errorf("results are linked wrongly: %v", results)
	}
}

func TestMessageConversionEdgeCases(t *testing.T) {
	testCases := []struct {
		name         string
		messages     []Message
		wantMessages int
		wantErr      error
	}{
		{"empty assistant message is skipped", []Message{{Role: "user", Text: "a"}, {Role: "assistant"}, {Role: "user", Text: "b"}}, 2, nil},
		{"empty user text is replaced", []Message{{Role: "user"}}, 1, nil},
		{"a tool call without an ID", []Message{{Role: "user", Text: "a"}, {Role: "assistant", ToolCalls: []ToolCall{{Name: "read_file"}}}}, 0, ErrBadRequest},
		{"unknown role", []Message{{Role: "system", Text: "x"}}, 0, ErrBadRequest},
		{"two separate groups of tool results", []Message{
			{Role: "user", Text: "a"},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "t1", Name: "x"}}},
			{Role: "tool", ToolCallID: "t1", Text: "r1"},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "t2", Name: "x"}}},
			{Role: "tool", ToolCallID: "t2", Text: "r2"},
		}, 5, nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := buildMessages(testCase.messages)

			if !errors.Is(err, testCase.wantErr) || len(got) != testCase.wantMessages {
				t.Errorf("messages = %d, err = %v, want %d and %v", len(got), err, testCase.wantMessages, testCase.wantErr)
			}
		})
	}

	body, err := json.Marshal(mustBuild(t, []Message{{Role: "user"}, {Role: "assistant", ToolCalls: []ToolCall{{ID: "t1", Name: "x"}}}, {Role: "tool", ToolCallID: "t1"}}))
	if err != nil || !strings.Contains(string(body), `"(empty)"`) || strings.Contains(string(body), `"text":""`) {
		t.Errorf("empty texts must not be sent: %s (%v)", body, err)
	}
}

func mustBuild(t testing.TB, messages []Message) any {
	t.Helper()

	built, err := buildMessages(messages)
	if err != nil {
		t.Fatal(err)
	}

	return built
}

func TestResponsesAreParsed(t *testing.T) {
	testCases := []struct {
		name       string
		content    string
		stop       string
		wantText   string
		wantCalls  []ToolCall
		wantTokens int
		wantErr    error
	}{
		{
			"text only", `{"type":"text","text":"Hello"}`, "end_turn", "Hello", nil, 17, nil,
		},
		{
			"two text blocks are joined", `{"type":"text","text":"One"},{"type":"text","text":"Two"}`, "end_turn", "One\n\nTwo", nil, 17, nil,
		},
		{
			"a thinking block is dropped", `{"type":"thinking","thinking":"","signature":"abc"},{"type":"text","text":"Done"}`, "end_turn", "Done", nil, 17, nil,
		},
		{
			"a tool call with text arguments", `{"type":"text","text":"Reading"},{"type":"tool_use","id":"toolu_1","name":"read_file","input":{"path":"a.go"}}`, "tool_use",
			"Reading", []ToolCall{{ID: "toolu_1", Name: "read_file", Arguments: map[string]string{"path": "a.go"}}}, 17, nil,
		},
		{
			"arguments of other types are kept as JSON text", `{"type":"tool_use","id":"toolu_2","name":"search_text","input":{"query":"a","path":5,"deep":true}}`, "tool_use",
			"", []ToolCall{{ID: "toolu_2", Name: "search_text", Arguments: map[string]string{"query": "a", "path": "5", "deep": "true"}}}, 17, nil,
		},
		{
			"a cut-off answer with text is kept", `{"type":"text","text":"Part"}`, "max_tokens", "Part", nil, 17, nil,
		},
		{
			"a cut-off answer with a tool call is refused", `{"type":"tool_use","id":"toolu_3","name":"read_file","input":{"pa`, "max_tokens", "", nil, 0, ErrBadResponse,
		},
		{
			"a refusal", `{"type":"text","text":"I cannot"}`, "refusal", "", nil, 0, ErrRefused,
		},
		{
			"the context window is full", `{"type":"text","text":"x"}`, "model_context_window_exceeded", "", nil, 0, ErrRejected,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := answer(testCase.content, testCase.stop, 10, 5, 1, 1)
			if testCase.wantErr == ErrBadResponse {
				handler = answer(`{"type":"tool_use","id":"toolu_3","name":"read_file","input":{"path":"a"}}`, testCase.stop, 10, 5, 1, 1)
			}
			client := newTestClient(t, newFakeServer(t, handler))

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

func TestAnUnreadableToolInputBecomesNoArguments(t *testing.T) {
	handler := func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		io.WriteString(writer, `{"id":"m","type":"message","role":"assistant","model":"x","content":[{"type":"tool_use","id":"toolu_9","name":"list_dir","input":"not an object"}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`)
	}
	client := newTestClient(t, newFakeServer(t, handler))

	got, err := client.Send(context.Background(), simpleRequest())

	if err != nil || len(got.ToolCalls) != 1 || len(got.ToolCalls[0].Arguments) != 0 {
		t.Errorf("got %+v, err %v, want one call with no arguments", got, err)
	}
}

func TestErrorsAreMappedAndNeverCarryTheServerText(t *testing.T) {
	testCases := []struct {
		status  int
		wantErr error
	}{
		{400, ErrRejected},
		{401, ErrAuth},
		{403, ErrAuth},
		{404, ErrRejected},
		{413, ErrRejected},
		{422, ErrRejected},
		{408, ErrRetryable},
		{409, ErrRetryable},
		{429, ErrRetryable},
		{500, ErrRetryable},
		{503, ErrRetryable},
		{529, ErrRetryable},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprint(testCase.status), func(t *testing.T) {
			secret := "AKIAIOSFODNN7EXAMPLE and 090-1234-5678"
			body := fmt.Sprintf(`{"type":"error","error":{"type":"invalid_request_error","message":%q}}`, "echo: "+secret)
			client := newTestClient(t, newFakeServer(t, failWith(testCase.status, body)))

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
	server := newFakeServer(t, failWith(529, `{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`))
	client := newTestClient(t, server)

	_, err := client.Send(context.Background(), simpleRequest())

	if !errors.Is(err, ErrRetryable) || len(server.requests()) != 1 {
		t.Errorf("err = %v, requests = %d, want one request: the sender owns the retries", err, len(server.requests()))
	}
}

func TestBrokenConnectionsAndTimeoutsAreRetryable(t *testing.T) {
	closed := newFakeServer(t, answer(`{"type":"text","text":"x"}`, "end_turn", 1, 1, 0, 0))
	closed.Close()
	client, err := New(fakeKey, "", closed.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(context.Background(), simpleRequest()); !errors.Is(err, ErrRetryable) {
		t.Errorf("connection refused: err = %v, want ErrRetryable", err)
	}

	slow := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) {
		time.Sleep(400 * time.Millisecond)
	})
	quick, err := newClient(fakeKey, "", slow.URL, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := quick.Send(context.Background(), simpleRequest()); !errors.Is(err, ErrRetryable) {
		t.Errorf("timeout: err = %v, want ErrRetryable", err)
	}
}

func TestACancelledContextIsNotAProviderProblem(t *testing.T) {
	client := newTestClient(t, newFakeServer(t, answer(`{"type":"text","text":"x"}`, "end_turn", 1, 1, 0, 0)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.Send(ctx, simpleRequest())

	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrRetryable) {
		t.Errorf("err = %v, want context.Canceled and not a retryable error", err)
	}
}

func TestTheKeyIsOnlyInTheHeader(t *testing.T) {
	server := newFakeServer(t, answer(`{"type":"text","text":"x"}`, "end_turn", 1, 1, 0, 0))
	client := newTestClient(t, server)

	if _, err := client.Send(context.Background(), Request{System: "s", Messages: []Message{{Role: "user", Text: "hello"}}}); err != nil {
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

	for _, shown := range []string{fmt.Sprintf("%v", client), fmt.Sprintf("%+v", client), fmt.Sprintf("%#v", client), fmt.Sprintf("%s", client), client.String()} {
		if strings.Contains(shown, fakeKey) || strings.Contains(shown, "api03") {
			t.Errorf("formatting the client shows the key: %q", shown)
		}
	}
}

func TestTheEnvironmentCannotChangeWhereTheRequestGoes(t *testing.T) {
	elsewhere := newFakeServer(t, answer(`{"type":"text","text":"x"}`, "end_turn", 1, 1, 0, 0))
	intended := newFakeServer(t, answer(`{"type":"text","text":"x"}`, "end_turn", 1, 1, 0, 0))

	t.Setenv("ANTHROPIC_BASE_URL", elsewhere.URL)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-ENVIRONMENT-KEY")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "environment-token")
	t.Setenv("ANTHROPIC_CUSTOM_HEADERS", "X-Evil: 1\nX-Other: 2")
	t.Setenv("ANTHROPIC_PROFILE", "someone-else")

	client := newTestClient(t, intended)
	if _, err := client.Send(context.Background(), simpleRequest()); err != nil {
		t.Fatal(err)
	}

	if len(elsewhere.requests()) != 0 || len(intended.requests()) != 1 {
		t.Fatalf("elsewhere got %d requests, the intended server got %d", len(elsewhere.requests()), len(intended.requests()))
	}
	header := intended.requests()[0].header
	if header.Get("Authorization") != "Bearer "+fakeKey || strings.Contains(strings.Join(header.Values("Authorization"), ","), "environment") || header.Get("X-Evil") != "" || header.Get("X-Other") != "" {
		t.Errorf("the environment changed the headers: %v", header)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	elsewhere := newFakeServer(t, answer(`{"type":"text","text":"x"}`, "end_turn", 1, 1, 0, 0))
	redirecting := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, elsewhere.URL+"/v1/messages", http.StatusTemporaryRedirect)
	})
	client := newTestClient(t, redirecting)

	_, err := client.Send(context.Background(), simpleRequest())

	if err == nil || len(elsewhere.requests()) != 0 {
		t.Errorf("err = %v, requests that reached the other host = %d, want an error and none", err, len(elsewhere.requests()))
	}
}

func TestNewChecksItsSettings(t *testing.T) {
	testCases := []struct {
		name    string
		apiKey  string
		baseURL string
		wantErr error
	}{
		{"no key", "", "", ErrNoKey},
		{"the default address", fakeKey, "", nil},
		{"https", fakeKey, "https://api.example.com", nil},
		{"plain http to another host", fakeKey, "http://api.example.com", ErrBadConfig},
		{"plain http to the same machine", fakeKey, "http://127.0.0.1:8080", nil},
		{"plain http to localhost", fakeKey, "http://localhost:8080", nil},
		{"a name that only starts like localhost", fakeKey, "http://localhost.evil.example", ErrBadConfig},
		{"a user name in the address", fakeKey, "https://user:pass@api.example.com", ErrBadConfig},
		{"no host", fakeKey, "https://", ErrBadConfig},
		{"another scheme", fakeKey, "ftp://api.example.com", ErrBadConfig},
		{"not a URL", fakeKey, "::::", ErrBadConfig},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := New(testCase.apiKey, "", testCase.baseURL); !errors.Is(err, testCase.wantErr) {
				t.Errorf("err = %v, want %v", err, testCase.wantErr)
			}
		})
	}

	client, err := New(fakeKey, "", "")
	if err != nil || client.model != DefaultModel {
		t.Errorf("the default model is %q (err %v), want %q", client.model, err, DefaultModel)
	}
}

func TestTheModelCanBeChosen(t *testing.T) {
	server := newFakeServer(t, answer(`{"type":"text","text":"x"}`, "end_turn", 1, 1, 0, 0))
	client, err := New(fakeKey, "claude-sonnet-5-5", server.URL)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Send(context.Background(), simpleRequest()); err != nil {
		t.Fatal(err)
	}

	if model := decode(t, server.requests()[0].body)["model"]; model != "claude-sonnet-5-5" {
		t.Errorf("model = %v", model)
	}
}

func TestABadRequestIsNotSent(t *testing.T) {
	server := newFakeServer(t, answer(`{"type":"text","text":"x"}`, "end_turn", 1, 1, 0, 0))
	client := newTestClient(t, server)

	_, err := client.Send(context.Background(), Request{Messages: []Message{{Role: "system", Text: "x"}}})

	if !errors.Is(err, ErrBadRequest) || len(server.requests()) != 0 {
		t.Errorf("err = %v, requests = %d, want ErrBadRequest and nothing sent", err, len(server.requests()))
	}
}

func FuzzBuildMessages(f *testing.F) {
	f.Add("user", "hello", "", "")
	f.Add("assistant", "", "toolu_1", "read_file")
	f.Add("tool", "result", "toolu_1", "")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, role, text, callID, name string) {
		messages := []Message{
			{Role: "user", Text: "start"},
			{Role: role, Text: text, ToolCallID: callID, ToolCalls: []ToolCall{{ID: callID, Name: name, Arguments: map[string]string{"path": text}}}},
			{Role: "tool", Text: text, ToolCallID: callID},
		}

		built, err := buildMessages(messages)
		if err != nil {
			if !errors.Is(err, ErrBadRequest) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}

		encoded, err := json.Marshal(built)
		if err != nil {
			t.Fatalf("the messages cannot be encoded: %v", err)
		}
		if strings.Contains(string(encoded), `"text":""`) {
			t.Fatalf("an empty text block would be sent: %s", encoded)
		}
	})
}

func FuzzParseArguments(f *testing.F) {
	f.Add(`{"path":"a.go"}`)
	f.Add(`{"a":5,"b":true,"c":null,"d":[1],"e":{"x":1}}`)
	f.Add(`not json`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, raw string) {
		arguments := parseArguments(raw)

		if arguments == nil {
			t.Fatal("the result must never be nil")
		}
	})
}
