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
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/outbound/internal/wire"
)

// This table pins every address that data can be sent to. A change here is a change of
// where data may go, so it must be a deliberate edit that a reviewer sees.
var pinnedProviders = []struct {
	id             string
	name           string
	baseURL        string
	keyEnv         string
	defaultModel   string
	maxTokensField string
	local          bool
}{
	{"anthropic", "Anthropic", "https://api.anthropic.com", "ANTHROPIC_API_KEY", "claude-opus-5-5", "", false},
	{"openai", "OpenAI", "https://api.openai.com/v1", "OPENAI_API_KEY", "", "max_completion_tokens", false},
	{"gemini", "Google Gemini", "https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY", "", "", false},
	{"mistral", "Mistral", "https://api.mistral.ai/v1", "MISTRAL_API_KEY", "", "", false},
	{"groq", "Groq", "https://api.groq.com/openai/v1", "GROQ_API_KEY", "", "", false},
	{"together", "Together AI", "https://api.together.xyz/v1", "TOGETHER_API_KEY", "", "", false},
	{"deepseek", "DeepSeek", "https://api.deepseek.com", "DEEPSEEK_API_KEY", "", "", false},
	{"xai", "xAI", "https://api.x.ai/v1", "XAI_API_KEY", "", "", false},
	{"openrouter", "OpenRouter", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", "", "", false},
	{"ollama", "Ollama (on this computer)", "http://127.0.0.1:11434/v1", "", "", "", true},
	{"lmstudio", "LM Studio (on this computer)", "http://127.0.0.1:1234/v1", "", "", "", true},
}

func TestEveryAddressIsPinned(t *testing.T) {
	if len(descriptors) != len(pinnedProviders) {
		t.Fatalf("there are %d providers and %d pinned ones", len(descriptors), len(pinnedProviders))
	}

	for index, pinned := range pinnedProviders {
		got := descriptors[index]
		if got.id != pinned.id || got.name != pinned.name || got.baseURL != pinned.baseURL || got.keyEnv != pinned.keyEnv ||
			got.defaultModel != pinned.defaultModel || got.maxTokensField != pinned.maxTokensField || got.local != pinned.local {
			t.Errorf("provider %d changed:\n got  %+v\n want %+v", index, got, pinned)
		}
	}
}

func TestTheProviderListIsConsistent(t *testing.T) {
	ids, names, keyNames := map[string]bool{}, map[string]bool{}, map[string]bool{}

	for _, current := range descriptors {
		if ids[current.id] || names[current.name] {
			t.Errorf("%s: the ID or the name is used twice", current.id)
		}
		ids[current.id], names[current.name] = true, true

		parsed, err := url.Parse(current.baseURL)
		if err != nil || !wire.SafeBaseURL(current.baseURL) {
			t.Errorf("%s: the address %q is not safe", current.id, current.baseURL)
			continue
		}
		if current.id != strings.ToLower(current.id) || strings.ContainsAny(current.id, " /:") {
			t.Errorf("%s: the ID is not plain lower case", current.id)
		}

		if current.local {
			if parsed.Scheme != "http" || !wire.IsLoopback(parsed) || current.keyEnv != "" {
				t.Errorf("%s: a local provider must be on this computer and need no key", current.id)
			}
			continue
		}

		if parsed.Scheme != "https" || current.keyEnv == "" || keyNames[current.keyEnv] || !strings.HasSuffix(current.keyEnv, "_API_KEY") {
			t.Errorf("%s: a remote provider needs https and its own key variable, got %q", current.id, current.keyEnv)
		}
		keyNames[current.keyEnv] = true
	}
}

func TestProvidersDescribesEveryProviderInOrder(t *testing.T) {
	infos := Providers()

	if len(infos) != len(pinnedProviders) {
		t.Fatalf("%d providers listed, want %d", len(infos), len(pinnedProviders))
	}
	for index, pinned := range pinnedProviders {
		want := Info{ID: pinned.id, Name: pinned.name, Local: pinned.local, KeyEnv: pinned.keyEnv, DefaultModel: pinned.defaultModel}
		if infos[index] != want {
			t.Errorf("info %d = %+v, want %+v", index, infos[index], want)
		}
	}

	infos[0].Name = "changed"
	if Providers()[0].Name != "Anthropic" {
		t.Error("changing the list changed the real providers")
	}
}

func chatOK(text string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"id":"c","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`, text)
	}
}

func chatToolCall(id, name, arguments string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"id":"c","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":%q,"type":"function","function":{"name":%q,"arguments":%q}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`, id, name, arguments)
	}
}

func TestEveryChatProviderOnlyReceivesCleanText(t *testing.T) {
	for _, current := range descriptors {
		if current.kind != kindChatCompletions {
			continue
		}

		t.Run(current.id, func(t *testing.T) {
			server := newAPIServer(t, statusAnswer(503), chatToolCall("call_abc", "read_file", `{"path":"src/app.go"}`), chatOK("Done."))
			provider, err := newAt(current.id, apiTestKey, "any-model", server.URL)
			if err != nil {
				t.Fatal(err)
			}
			sender, projectDirectory := newTestSender(t, provider)

			request := plantedRequest(projectDirectory)
			request.Tools = []ToolSpec{{Name: "read_file", Description: "Read " + fakeAWSKey, Parameters: []ToolParameter{{Name: "path", Description: "call " + fakePhone, Required: true}}}}
			request.Messages[1].ToolCalls[0].ID = "call_abc"
			request.Messages[2].ToolCallID = "call_abc"

			first, err := sender.Send(context.Background(), request)
			if err != nil || len(first.ToolCalls) != 1 || first.ToolCalls[0].ID != "call_abc" || first.TokensUsed != 10 {
				t.Fatalf("first answer = %+v, err = %v", first, err)
			}
			request.Messages = append(request.Messages, Message{Role: "assistant", ToolCalls: first.ToolCalls}, Message{Role: "tool", ToolCallID: "call_abc", Text: "mynumber=" + fakeMyNumber})
			if _, err := sender.Send(context.Background(), request); err != nil {
				t.Fatal(err)
			}

			bodies := server.requestBodies()
			if len(bodies) != 3 || sender.Attempts() != 3 {
				t.Fatalf("the server saw %d requests and the sender made %d attempts, want 3 and 3", len(bodies), sender.Attempts())
			}
			for index, body := range bodies {
				for _, planted := range append(plantedValues, projectDirectory, apiTestKey) {
					if strings.Contains(body, planted) {
						t.Errorf("request %d contains %q", index, planted)
					}
				}
				for _, want := range []string{"[SECRET:aws-access-key:", "src/app.go", `"model":"any-model"`, `"tool_call_id":"call_abc"`} {
					if !strings.Contains(body, want) {
						t.Errorf("request %d has no %q", index, want)
					}
				}
			}
			if bodies[0] != bodies[1] {
				t.Error("the retry did not send the same cleaned request as the first attempt")
			}
			if current.maxTokensField != "" && !strings.Contains(bodies[0], `"`+current.maxTokensField+`"`) {
				t.Errorf("the request has no %s", current.maxTokensField)
			}
		})
	}
}

func TestSetupIsCheckedForEveryProvider(t *testing.T) {
	testCases := []struct {
		name    string
		id      string
		key     string
		model   string
		baseURL string
		wantErr error
	}{
		{"an unknown provider", "nope", apiTestKey, "m", "", ErrInvalidSetup},
		{"an empty provider", "", apiTestKey, "m", "", ErrInvalidSetup},
		{"anthropic needs a key", "anthropic", "", "", "", ErrInvalidSetup},
		{"anthropic has a default model", "anthropic", apiTestKey, "", "", nil},
		{"openai needs a model", "openai", apiTestKey, "", "", ErrInvalidSetup},
		{"openai needs a key", "openai", "", "m", "", ErrInvalidSetup},
		{"openai with both", "openai", apiTestKey, "m", "", nil},
		{"a local provider needs no key", "ollama", "", "llama", "", nil},
		{"a local provider still needs a model", "ollama", "", "", "", ErrInvalidSetup},
		{"a remote address that is not https", "openai", apiTestKey, "m", "http://evil.example.com", ErrInvalidSetup},
		{"a name with the wrong case", "OpenAI", apiTestKey, "m", "", ErrInvalidSetup},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			provider, err := newAt(testCase.id, testCase.key, testCase.model, testCase.baseURL)

			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("err = %v, want %v", err, testCase.wantErr)
			}
			if err == nil && provider.Name() == "" {
				t.Error("the provider has no name")
			}
		})
	}
}

func TestEveryProviderNameIsTheNameOnTheConsentScreen(t *testing.T) {
	for _, current := range descriptors {
		provider, err := NewProvider(current.id, "any-key", "any-model")
		if err != nil {
			t.Fatalf("%s: %v", current.id, err)
		}
		sender, err := New(provider, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}

		want := "Omamori will send sanitized content to " + current.name + " during this run."
		if got := sender.ConsentText(); got != want {
			t.Errorf("%s: ConsentText() = %q, want %q", current.id, got, want)
		}
	}
}

func TestNoProviderShowsItsKey(t *testing.T) {
	for _, current := range descriptors {
		provider, err := NewProvider(current.id, apiTestKey, "any-model")
		if err != nil {
			t.Fatalf("%s: %v", current.id, err)
		}

		for _, shown := range []string{fmt.Sprintf("%v", provider), fmt.Sprintf("%+v", provider), fmt.Sprintf("%#v", provider), fmt.Sprintf("%s", provider)} {
			if strings.Contains(shown, "api03") || strings.Contains(shown, "FAKE") {
				t.Errorf("%s: formatting the provider shows the key: %q", current.id, shown)
			}
		}
	}
}

func TestProviderProblemsMeanTheSameForEveryChatProvider(t *testing.T) {
	testCases := []struct {
		name         string
		handlers     []http.HandlerFunc
		wantErr      error
		wantRequests int
	}{
		{"a bad key stops at once", []http.HandlerFunc{statusAnswer(401)}, ErrAuth, 1},
		{"a content filter stops at once", []http.HandlerFunc{func(writer http.ResponseWriter, request *http.Request) {
			io.WriteString(writer, `{"choices":[{"message":{"role":"assistant","content":""},"finish_reason":"content_filter"}]}`)
		}}, ErrRefused, 1},
		{"a rejected request is not retried", []http.HandlerFunc{statusAnswer(400)}, ErrProviderFailed, 1},
		{"overload is retried until the limit", []http.HandlerFunc{statusAnswer(503)}, ErrProviderFailed, 3},
		{"rate limiting is retried", []http.HandlerFunc{statusAnswer(429), chatOK("ok")}, nil, 2},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			server := newAPIServer(t, testCase.handlers...)
			provider, err := newAt("openai", apiTestKey, "m", server.URL)
			if err != nil {
				t.Fatal(err)
			}
			sender, _ := newTestSender(t, provider)

			_, err = sender.Send(context.Background(), Request{Messages: []Message{{Role: "user", Text: "hi"}}})

			if !errors.Is(err, testCase.wantErr) || len(server.requestBodies()) != testCase.wantRequests {
				t.Errorf("err = %v, requests = %d, want %v and %d", err, len(server.requestBodies()), testCase.wantErr, testCase.wantRequests)
			}
		})
	}
}

func TestProviderClientsAreOnlyImportedByOutbound(t *testing.T) {
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
			if strings.Contains(importPath, "internal/outbound/internal/") {
				importers++
				if !strings.HasPrefix(relative, "internal/outbound/") {
					t.Errorf("%s imports a provider client, but only outbound may", relative)
				}
			}
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if importers < 3 {
		t.Errorf("only %d imports of the client packages were found, the check looked in the wrong place", importers)
	}
}

func TestTheChatClientUsesOnlyTheStandardLibrary(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("internal", "openaicompat", "*.go"))
	if err != nil || len(files) < 2 {
		t.Fatalf("files = %v, err = %v", files, err)
	}

	for _, path := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range parsed.Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			firstSegment, _, _ := strings.Cut(importPath, "/")

			isStandard := !strings.Contains(firstSegment, ".")
			isOurs := importPath == "github.com/kenzietann/omamori/internal/outbound/internal/wire"
			if !isStandard && !isOurs {
				t.Errorf("%s imports %s, the chat client must not add a dependency", path, importPath)
			}
		}
	}
}

func TestPinnedAddressesAreSortedLikeTheList(t *testing.T) {
	ids := make([]string, 0, len(descriptors))
	for _, current := range descriptors {
		ids = append(ids, current.id)
	}
	if !slices.Contains(ids, "anthropic") || ids[0] != "anthropic" {
		t.Errorf("anthropic must stay the first provider, the list is %v", ids)
	}
}
