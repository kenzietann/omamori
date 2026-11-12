package keystore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

const fakeKey = "sk-FAKE-keystore-Key_123.abc"

type call struct {
	stdin string
	args  []string
}

type fakeTool struct {
	calls  []call
	stdout string
	status int
	err    error
}

func (tool *fakeTool) run(ctx context.Context, stdin string, args ...string) (string, int, error) {
	tool.calls = append(tool.calls, call{stdin, args})

	return tool.stdout, tool.status, tool.err
}

func darwinStore(t testing.TB, tool *fakeTool) *Store {
	t.Helper()

	store, err := newStore("omamori-test", tool.run, "darwin")
	if err != nil {
		t.Fatal(err)
	}

	return store
}

func TestSetSendsTheKeyOnlyThroughStandardInputAsHex(t *testing.T) {
	tool := &fakeTool{}

	if err := darwinStore(t, tool).Set(context.Background(), "openai", fakeKey); err != nil {
		t.Fatal(err)
	}

	if len(tool.calls) != 1 {
		t.Fatalf("%d calls", len(tool.calls))
	}
	want := "add-generic-password -U -s omamori-test -a openai -X " + hex.EncodeToString([]byte(fakeKey)) + "\n"
	if tool.calls[0].stdin != want || len(tool.calls[0].args) != 1 || tool.calls[0].args[0] != "-i" {
		t.Errorf("stdin = %q, args = %q", tool.calls[0].stdin, tool.calls[0].args)
	}
	if strings.Contains(strings.Join(tool.calls[0].args, " "), "FAKE") || strings.Contains(tool.calls[0].stdin, fakeKey) {
		t.Error("the key is on the command line, or in stdin as plain text")
	}
}

func TestGetAndDeleteNeverPutTheKeyOnTheCommandLine(t *testing.T) {
	tool := &fakeTool{stdout: fakeKey + "\n"}
	store := darwinStore(t, tool)

	key, err := store.Get(context.Background(), "openai")
	if err != nil || key != fakeKey {
		t.Fatalf("key = %q, err = %v", key, err)
	}
	if err := store.Delete(context.Background(), "openai"); err != nil {
		t.Fatal(err)
	}

	wantFirst := []string{"find-generic-password", "-s", "omamori-test", "-a", "openai", "-w"}
	wantSecond := []string{"delete-generic-password", "-s", "omamori-test", "-a", "openai"}
	if fmt.Sprint(tool.calls[0].args) != fmt.Sprint(wantFirst) || fmt.Sprint(tool.calls[1].args) != fmt.Sprint(wantSecond) {
		t.Errorf("args = %q and %q", tool.calls[0].args, tool.calls[1].args)
	}
	if tool.calls[0].stdin != "" || tool.calls[1].stdin != "" {
		t.Error("something was sent on standard input")
	}
}

func TestOnlyUsableKeysAndProvidersAreSaved(t *testing.T) {
	longKey := strings.Repeat("k", maxKeyBytes+1)
	testCases := []struct {
		name       string
		providerID string
		key        string
	}{
		{"an empty key", "openai", ""},
		{"a key with a space", "openai", "sk abc"},
		{"a key with a newline that would add a command", "openai", "abc\nadd-generic-password -s x"},
		{"a key with a non-ASCII character", "openai", "abcé"},
		{"a key with a tab", "openai", "abc\tdef"},
		{"a key that is too long", "openai", longKey},
		{"an empty provider", "", fakeKey},
		{"a provider with an upper case letter", "OpenAI", fakeKey},
		{"a provider with a space and a flag", "openai -T /bin/sh", fakeKey},
		{"a provider with a newline", "openai\nx", fakeKey},
		{"a provider that is too long", strings.Repeat("a", 33), fakeKey},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tool := &fakeTool{}

			err := darwinStore(t, tool).Set(context.Background(), testCase.providerID, testCase.key)

			if !errors.Is(err, ErrBadValue) || len(tool.calls) != 0 {
				t.Errorf("err = %v, calls = %d: nothing may be run", err, len(tool.calls))
			}
		})
	}
}

func TestKeysWithQuotesAndSymbolsAreSafeBecauseOfHex(t *testing.T) {
	tool := &fakeTool{}
	key := `a'b"c;d$e` + "`" + `f\g&h|i#j`

	if err := darwinStore(t, tool).Set(context.Background(), "openai", key); err != nil {
		t.Fatal(err)
	}

	if strings.Count(tool.calls[0].stdin, "\n") != 1 || strings.ContainsAny(strings.TrimSuffix(tool.calls[0].stdin, "\n"), `'";$`+"`&|#\\") {
		t.Errorf("the command holds raw symbols: %q", tool.calls[0].stdin)
	}
}

func TestAProviderWithBadCharactersIsNeverLookedUp(t *testing.T) {
	tool := &fakeTool{}
	store := darwinStore(t, tool)

	if err := store.Set(context.Background(), "-a", fakeKey); !errors.Is(err, ErrBadValue) {
		t.Errorf("set: err = %v", err)
	}
	if _, err := store.Get(context.Background(), "-w"); !errors.Is(err, ErrBadValue) {
		t.Errorf("get: err = %v", err)
	}
	if err := store.Delete(context.Background(), "a b"); !errors.Is(err, ErrBadValue) {
		t.Errorf("delete: err = %v", err)
	}
	if len(tool.calls) != 0 {
		t.Error("the tool was run")
	}
}

func TestGetAnswers(t *testing.T) {
	testCases := []struct {
		name    string
		tool    *fakeTool
		wantKey string
		wantErr error
	}{
		{"a key without a newline", &fakeTool{stdout: fakeKey}, fakeKey, nil},
		{"not found", &fakeTool{status: 44}, "", ErrNotFound},
		{"another failure", &fakeTool{status: 1}, "", ErrFailed},
		{"the tool cannot start", &fakeTool{err: ErrFailed}, "", ErrFailed},
		{"an empty answer", &fakeTool{stdout: "\n"}, "", ErrFailed},
		{"an answer that is not a key", &fakeTool{stdout: "a b\n"}, "", ErrFailed},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			key, err := darwinStore(t, testCase.tool).Get(context.Background(), "openai")

			if key != testCase.wantKey || !errors.Is(err, testCase.wantErr) {
				t.Errorf("key = %q, err = %v", key, err)
			}
		})
	}
}

func TestSetAndDeleteFailuresAreFixedAndDoNotShowTheKey(t *testing.T) {
	for _, tool := range []*fakeTool{{status: 1}, {err: errors.New("boom " + fakeKey)}} {
		err := darwinStore(t, tool).Set(context.Background(), "openai", fakeKey)

		if !errors.Is(err, ErrFailed) || strings.Contains(err.Error(), fakeKey) {
			t.Errorf("set: err = %v", err)
		}
	}

	if err := darwinStore(t, &fakeTool{status: 44}).Delete(context.Background(), "openai"); err != nil {
		t.Errorf("deleting a key that is not there: %v", err)
	}
	if err := darwinStore(t, &fakeTool{status: 1}).Delete(context.Background(), "openai"); !errors.Is(err, ErrFailed) {
		t.Errorf("a failed delete: %v", err)
	}
}

func TestOtherSystemsSaveNothing(t *testing.T) {
	tool := &fakeTool{}
	store, err := newStore("omamori-test", tool.run, "linux")
	if err != nil {
		t.Fatal(err)
	}

	if store.Available() {
		t.Error("a linux store says it is available")
	}
	if err := store.Set(context.Background(), "openai", fakeKey); !errors.Is(err, ErrUnavailable) {
		t.Errorf("set: %v", err)
	}
	if _, err := store.Get(context.Background(), "openai"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("get: %v", err)
	}
	if err := store.Delete(context.Background(), "openai"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("delete: %v", err)
	}
	if len(tool.calls) != 0 {
		t.Error("the tool was run")
	}
}

func TestTheServiceNameIsChecked(t *testing.T) {
	for _, service := range []string{"", "a b", "x\ny", "-s", ".hidden", strings.Repeat("a", 65)} {
		if _, err := New(service); !errors.Is(err, ErrBadValue) {
			t.Errorf("%q: err = %v", service, err)
		}
	}
	if _, err := New(DefaultService); err != nil {
		t.Errorf("the default service was refused: %v", err)
	}
}

func TestTheRealKeychain(t *testing.T) {
	if os.Getenv("OMAMORI_KEYCHAIN_TEST") != "1" {
		t.Skip("set OMAMORI_KEYCHAIN_TEST=1 to use the real Keychain")
	}

	store, err := New(fmt.Sprintf("omamori-test-%d", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if !store.Available() {
		t.Skip("not macOS")
	}
	ctx := context.Background()
	t.Cleanup(func() { _ = store.Delete(ctx, "probe") })

	if _, err := store.Get(ctx, "probe"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before saving: %v", err)
	}
	if err := store.Set(ctx, "probe", fakeKey); err != nil {
		t.Fatal(err)
	}
	if key, err := store.Get(ctx, "probe"); err != nil || key != fakeKey {
		t.Fatalf("after saving: key %q, err %v", key, err)
	}
	if err := store.Set(ctx, "probe", fakeKey+"2"); err != nil {
		t.Fatal(err)
	}
	if key, _ := store.Get(ctx, "probe"); key != fakeKey+"2" {
		t.Errorf("the key was not replaced: %q", key)
	}
	if err := store.Delete(ctx, "probe"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "probe"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after deleting: %v", err)
	}
}
