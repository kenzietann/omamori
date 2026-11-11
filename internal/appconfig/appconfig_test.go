package appconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deep", "omamori", "settings.json")
	want := Settings{Provider: "anthropic", Model: "claude-opus-5-5", Reasoning: "high"}

	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)

	if err != nil || got != want {
		t.Errorf("got %+v, err %v", got, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the file mode is %v, want 0600", info.Mode().Perm())
	}
	folder, _ := os.Stat(filepath.Dir(path))
	if folder.Mode().Perm() != 0o700 {
		t.Errorf("the folder mode is %v, want 0700", folder.Mode().Perm())
	}
}

func TestSaveReplacesTheOldFileAndLeavesNoTemporaryFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "settings.json")

	for _, model := range []string{"first", "second"} {
		if err := Save(path, Settings{Provider: "openai", Model: model}); err != nil {
			t.Fatal(err)
		}
	}

	got, _ := Load(path)
	entries, _ := os.ReadDir(directory)
	if got.Model != "second" || len(entries) != 1 {
		t.Errorf("model = %q, files = %d", got.Model, len(entries))
	}
}

func TestAFileThatIsNotThereGivesEmptySettings(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "none.json"))

	if err != nil || got != (Settings{}) {
		t.Errorf("got %+v, err %v", got, err)
	}
}

func TestABrokenFileGivesEmptySettingsAndAnError(t *testing.T) {
	directory := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		return path
	}
	target := write("target.json", `{"provider":"openai"}`)
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"not JSON":      write("a.json", "hello"),
		"a list":        write("b.json", `["x"]`),
		"too big":       write("c.json", `{"model":"`+strings.Repeat("a", maxFileBytes)+`"}`),
		"a symlink":     link,
		"a folder":      directory,
		"an empty file": write("d.json", ""),
	} {
		got, err := Load(path)

		if !errors.Is(err, ErrCorrupt) || got != (Settings{}) {
			t.Errorf("%s: got %+v, err %v", name, got, err)
		}
	}
}

func TestOddFieldsInAFileAreDroppedNotTrusted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	content := `{"provider":"OpenAI; rm","model":"good\u001b[2Jmodel","reasoning":"HIGH","key":"sk-SECRET-should-be-ignored"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)

	if err != nil || got != (Settings{}) {
		t.Errorf("got %+v, err %v", got, err)
	}
}

func TestGoodFieldsSurviveWhenAnotherFieldIsBad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"provider":"mistral","model":"bad\u0007","reasoning":"low"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, _ := Load(path)

	if got != (Settings{Provider: "mistral", Reasoning: "low"}) {
		t.Errorf("got %+v", got)
	}
}

func TestSaveRefusesBadSettingsAndWritesNothing(t *testing.T) {
	testCases := []Settings{
		{Provider: "Open AI"},
		{Provider: "-x"},
		{Provider: strings.Repeat("a", 33)},
		{Model: "a\nb"},
		{Model: "a\x1b[2J"},
		{Model: "a\u202eb"},
		{Model: strings.Repeat("m", maxModelRunes+1)},
		{Model: "bad\xff"},
		{Reasoning: "HIGH"},
		{Reasoning: "high\n"},
		{Reasoning: "x"},
	}

	for _, settings := range testCases {
		directory := t.TempDir()
		path := filepath.Join(directory, "settings.json")

		if err := Save(path, settings); !errors.Is(err, ErrBadValue) {
			t.Errorf("%+v: err = %v", settings, err)
		}
		if entries, _ := os.ReadDir(directory); len(entries) != 0 {
			t.Errorf("%+v: a file was written", settings)
		}
	}
}

func TestTheFileHoldsNoKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := Save(path, Settings{Provider: "openai", Model: "m", Reasoning: "low"}); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)

	for _, field := range []string{"key", "token", "secret", "password"} {
		if strings.Contains(strings.ToLower(string(data)), field) {
			t.Errorf("the file mentions %q:\n%s", field, data)
		}
	}
}

func TestAnEmptySettingsFileIsSmall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := Save(path, Settings{}); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)

	if strings.TrimSpace(string(data)) != "{}" {
		t.Errorf("data = %q", data)
	}
}

func TestPathIsInsideTheSettingsFolder(t *testing.T) {
	path, err := Path()

	if err != nil || filepath.Base(path) != "settings.json" || filepath.Base(filepath.Dir(path)) != "omamori" {
		t.Errorf("path = %q, err = %v", path, err)
	}
}
