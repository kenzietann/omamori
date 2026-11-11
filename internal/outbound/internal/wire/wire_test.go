package wire

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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
