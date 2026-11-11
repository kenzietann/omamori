package wire

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestStatusError(t *testing.T) {
	testCases := []struct {
		status  int
		wantErr error
	}{
		{400, ErrRejected}, {401, ErrAuth}, {403, ErrAuth}, {404, ErrRejected}, {413, ErrRejected}, {422, ErrRejected},
		{301, ErrRejected}, {307, ErrRejected},
		{408, ErrRetryable}, {409, ErrRetryable}, {429, ErrRetryable}, {500, ErrRetryable}, {502, ErrRetryable}, {503, ErrRetryable}, {529, ErrRetryable},
	}

	for _, testCase := range testCases {
		if got := StatusError(testCase.status); !errors.Is(got, testCase.wantErr) {
			t.Errorf("StatusError(%d) = %v, want %v", testCase.status, got, testCase.wantErr)
		}
	}
}

func TestSafeBaseURL(t *testing.T) {
	testCases := []struct {
		raw  string
		want bool
	}{
		{"https://api.example.com", true},
		{"https://api.example.com/v1", true},
		{"http://127.0.0.1:8080", true},
		{"http://localhost:11434/v1", true},
		{"http://[::1]:8080", true},
		{"http://api.example.com", false},
		{"http://localhost.evil.example", false},
		{"http://127.0.0.1.evil.example", false},
		{"https://user:pass@api.example.com", false},
		{"https://", false},
		{"ftp://api.example.com", false},
		{"::::", false},
		{"", false},
	}

	for _, testCase := range testCases {
		if got := SafeBaseURL(testCase.raw); got != testCase.want {
			t.Errorf("SafeBaseURL(%q) = %v, want %v", testCase.raw, got, testCase.want)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://127.0.0.1:1": true, "http://localhost": true, "http://[::1]:5": true,
		"https://api.example.com": false, "http://10.0.0.1": false, "http://0.0.0.0:1": false,
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := IsLoopback(parsed); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestNewHTTPClientDoesNotFollowRedirects(t *testing.T) {
	reached := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ }))
	defer target.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	response, err := NewHTTPClient(time.Second).Get(redirecting.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	if response.StatusCode != http.StatusTemporaryRedirect || reached != 0 {
		t.Errorf("status = %d, requests that reached the target = %d, want 307 and none", response.StatusCode, reached)
	}
}

func TestParseArguments(t *testing.T) {
	testCases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{"text", `{"path":"a.go"}`, map[string]string{"path": "a.go"}},
		{"other types (null means no value)", `{"n":5,"f":true,"z":null,"l":[1],"o":{"x":1}}`, map[string]string{"n": "5", "f": "true", "z": "", "l": "[1]", "o": `{"x":1}`}},
		{"an empty object", `{}`, map[string]string{}},
		{"not an object", `"text"`, map[string]string{}},
		{"not JSON", `nope`, map[string]string{}},
		{"empty", ``, map[string]string{}},
	}

	for _, testCase := range testCases {
		if got := ParseArguments(testCase.raw); !reflect.DeepEqual(got, testCase.want) {
			t.Errorf("%s: ParseArguments(%q) = %v, want %v", testCase.name, testCase.raw, got, testCase.want)
		}
	}
}

func TestNonEmpty(t *testing.T) {
	if NonEmpty("") != "(empty)" || NonEmpty("x") != "x" {
		t.Error("NonEmpty is wrong")
	}
}

func TestErrorKindsAreDifferent(t *testing.T) {
	kinds := []error{ErrNoKey, ErrBadConfig, ErrBadRequest, ErrRetryable, ErrAuth, ErrRejected, ErrRefused, ErrBadResponse}
	for first := range kinds {
		for second := range kinds {
			if first != second && errors.Is(kinds[first], kinds[second]) {
				t.Errorf("%v and %v are the same kind", kinds[first], kinds[second])
			}
		}
	}
	if fmt.Sprint(ErrAuth) == "" {
		t.Error("an error has no text")
	}
}

func TestCleanModelIDs(t *testing.T) {
	testCases := []struct {
		name        string
		providerIDs []string
		wantIDs     []string
	}{
		{"sorted and without doubles", []string{"b-model", "a-model", "b-model"}, []string{"a-model", "b-model"}},
		{"the models/ prefix is removed", []string{"models/gemini-x", "gemini-x"}, []string{"gemini-x"}},
		{"a doubled prefix is dropped", []string{"models/models/x", "models/"}, nil},
		{"empty and spaced names are dropped", []string{"", "a b", "ok"}, []string{"ok"}},
		{"control and non-ASCII names are dropped", []string{"a\x1b[2J", "a‮b", "モデル", "fine"}, []string{"fine"}},
		{"too long names are dropped", []string{strings.Repeat("m", 101), strings.Repeat("m", 100)}, []string{strings.Repeat("m", 100)}},
		{"models that cannot chat are dropped", []string{"text-embedding-3", "whisper-large", "gpt-4o-mini-tts", "DALL-E-3", "omni-moderation", "llama-guard", "gpt-image-1", "chat-model"}, []string{"chat-model"}},
		{"nothing in, nothing out", nil, nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotIDs := CleanModelIDs(testCase.providerIDs)

			if !slices.Equal(gotIDs, testCase.wantIDs) {
				t.Errorf("got %q, want %q", gotIDs, testCase.wantIDs)
			}
		})
	}
}

func TestCleanModelIDsStopsAtTheLimit(t *testing.T) {
	var providerIDs []string
	for number := range 250 {
		providerIDs = append(providerIDs, fmt.Sprintf("model-%03d", number))
	}

	gotIDs := CleanModelIDs(providerIDs)

	if len(gotIDs) != MaxModelChoices || gotIDs[0] != "model-000" {
		t.Errorf("got %d names, first %q", len(gotIDs), gotIDs[0])
	}
}

func FuzzCleanModelIDs(f *testing.F) {
	f.Add("gpt-x", "models/y")
	f.Add("\x00\xff", "a b")

	f.Fuzz(func(t *testing.T, first, second string) {
		for _, id := range CleanModelIDs([]string{first, second}) {
			if !usableModelID(id) || strings.HasPrefix(id, "models/") {
				t.Fatalf("unsafe name %q", id)
			}
		}
	})
}

func TestStatusErrorWithBody(t *testing.T) {
	testCases := []struct {
		name       string
		status     int
		body       string
		wantDetail string
		wantKind   error
	}{
		{"a code from the provider", 404, `{"error":{"message":"The model gpt-x does not exist","type":"invalid_request_error","code":"model_not_found"}}`, "status 404, code model_not_found", ErrRejected},
		{"a null code falls back to the type", 400, `{"error":{"message":"m","type":"invalid_request_error","code":null}}`, "status 400, code invalid_request_error", ErrRejected},
		{"a status text is used when there is nothing else", 400, `{"error":{"code":400,"message":"m","status":"INVALID_ARGUMENT"}}`, "status 400, code INVALID_ARGUMENT", ErrRejected},
		{"the field is added", 400, `{"error":{"message":"m","type":"invalid_request_error","param":"tools","code":null}}`, "status 400, code invalid_request_error, field tools", ErrRejected},
		{"a nested field name is shown", 400, `{"error":{"code":"unsupported_parameter","param":"tools[0].function.name"}}`, "status 400, code unsupported_parameter, field tools[0].function.name", ErrRejected},
		{"a field with odd characters is not shown", 400, `{"error":{"code":"x","param":"a b\u001b sk-SECRET"}}`, "status 400, code x", ErrRejected},
		{"a code with odd characters is not shown", 400, `{"error":{"code":"bad code \u001b[2J sk-SECRET","type":"x y"}}`, "status 400", ErrRejected},
		{"a code that is too long is not shown", 400, `{"error":{"code":"` + strings.Repeat("a", 65) + `"}}`, "status 400", ErrRejected},
		{"a body that is not JSON", 422, `<html>sk-SECRET</html>`, "status 422", ErrRejected},
		{"an empty body", 400, ``, "status 400", ErrRejected},
		{"a wrong key keeps its own kind", 401, `{"error":{"code":"invalid_api_key"}}`, "", ErrAuth},
		{"a busy server keeps its own kind", 429, `{"error":{"code":"rate_limit"}}`, "", ErrRetryable},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := StatusErrorWithBody(testCase.status, []byte(testCase.body))

			if !errors.Is(err, testCase.wantKind) {
				t.Fatalf("err = %v, want kind %v", err, testCase.wantKind)
			}
			var rejection *Rejection
			if errors.As(err, &rejection) != (testCase.wantDetail != "") || rejection != nil && rejection.Detail() != testCase.wantDetail {
				t.Errorf("err = %v, want detail %q", err, testCase.wantDetail)
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "does not exist") {
				t.Errorf("the error shows text of the provider: %v", err)
			}
		})
	}
}
