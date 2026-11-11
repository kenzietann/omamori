package peek

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/pathguard"
)

func project(t *testing.T, files map[string]string) *pathguard.Root {
	t.Helper()

	directory := t.TempDir()
	for name, content := range files {
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := pathguard.NewRoot(directory)
	if err != nil {
		t.Fatal(err)
	}

	return root
}

func TestTheReportIsReadWithRangesAndWithoutDoubles(t *testing.T) {
	report := "## Evidence locations\n\n- app/a.txt:2 [PHONE:001]\n- app/b.js:4 [SECRET:ai-api-key:001]\n\n## Library and generated files\n\n- web/dist/x.js:1 [PHONE:002]–[PHONE:004] (3 phone matches)\n- app/a.txt:2 [PHONE:001]\nnot a bullet app/z.txt:9 [PHONE:009]\n- bad line:0 [PHONE:001]\n"

	items, err := ReadReport(report)

	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, item := range items {
		got = append(got, item.Placeholder+"@"+item.File+":"+strings.Repeat("#", item.Line))
	}
	want := "[PHONE:001]@app/a.txt:##,[SECRET:ai-api-key:001]@app/b.js:####,[PHONE:002]@web/dist/x.js:#,[PHONE:003]@web/dist/x.js:#,[PHONE:004]@web/dist/x.js:#"
	if strings.Join(got, ",") != want {
		t.Errorf("items = %s\nwant    %s", strings.Join(got, ","), want)
	}
}

func TestAReportWithNoMatchesIsAnError(t *testing.T) {
	for _, report := range []string{"", "# Omamori report\n\nNo findings.\n", "- a:1 [PASSWORD:001]\n", "- a:1 [PHONE:002]–[PHONE:001]\n", "- a:1 [PHONE:001]–[PHONE:999999]\n"} {
		if _, err := ReadReport(report); err == nil {
			t.Errorf("report %q gave matches", report)
		}
	}
}

func TestAPhoneNumberIsMaskedWithItsContextUnlessTheUserAsksToSeeIt(t *testing.T) {
	root := project(t, map[string]string{"notes/a.txt": "first line\ncall the office at 03-1234-5678 for help\nlast line\n"})
	items, _ := ReadReport("- notes/a.txt:2 [PHONE:007]\n")

	masked := Show(root, items, false)
	revealed := Show(root, items, true)

	if masked[0].Problem != "" || masked[0].Value != "03-****-**78" || masked[0].Context != "call the office at 03-****-**78 for help" {
		t.Errorf("masked: %+v", masked[0])
	}
	if strings.Contains(masked[0].Value+masked[0].Context, "1234") {
		t.Error("the middle of the number is in the masked output")
	}
	if revealed[0].Value != "03-1234-5678" || revealed[0].Context != "call the office at 03-1234-5678 for help" {
		t.Errorf("revealed: %+v", revealed[0])
	}
}

func TestSeveralMatchesOnOneLineAreMatchedInOrderAndNeighboursStayMasked(t *testing.T) {
	root := project(t, map[string]string{"dist/x.js": "var a=1;\nt=['03-1111-2222','03-3333-4444','03-5555-6666'];\n"})
	items, _ := ReadReport("- dist/x.js:2 [PHONE:004]–[PHONE:006] (3 phone matches)\n")

	revealed := Show(root, items, true)

	for position, want := range []string{"03-1111-2222", "03-3333-4444", "03-5555-6666"} {
		if revealed[position].Value != want {
			t.Errorf("item %d: %q, want %q", position, revealed[position].Value, want)
		}
	}
	if !strings.Contains(revealed[1].Context, "03-3333-4444") || strings.Contains(revealed[1].Context, "1111") || strings.Contains(revealed[1].Context, "5555") {
		t.Errorf("only the chosen match is shown, the others stay masked: %q", revealed[1].Context)
	}
}

func TestAKeyIsMaskedAndAPrivateKeyIsNeverShown(t *testing.T) {
	key := "sk-" + "proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"
	block := "-----BEGIN PRIVATE KEY-----\nFAKEBODYLINE1\nFAKEBODYLINE2\n-----END PRIVATE KEY-----"
	root := project(t, map[string]string{"a.env": "# x\nAI=" + key + "\n", "k.pem": block + "\n"})
	items, _ := ReadReport("- a.env:2 [SECRET:ai-api-key:001]\n- k.pem:1 [SECRET:private-key:001]\n")

	for _, reveal := range []bool{false, true} {
		shown := Show(root, items, reveal)
		var byPlaceholder = map[string]Shown{}
		for _, one := range shown {
			byPlaceholder[one.Placeholder] = one
		}

		aiKey := byPlaceholder["[SECRET:ai-api-key:001]"]
		if !reveal && (strings.Contains(aiKey.Value+aiKey.Context, "FAKEFAKE") || !strings.HasPrefix(aiKey.Value, "sk-")) {
			t.Errorf("a masked key: %+v", aiKey)
		}
		if reveal && aiKey.Value != key {
			t.Errorf("a revealed key: %+v", aiKey)
		}
		pem := byPlaceholder["[SECRET:private-key:001]"]
		if strings.Contains(pem.Value+pem.Context, "BODYLINE") || !strings.Contains(pem.Value, "never shown") || !strings.Contains(pem.Value, "4 lines") {
			t.Errorf("a private key (reveal %v): %+v", reveal, pem)
		}
	}
}

func TestWhatCannotBeShownSaysWhyInAFixedSentence(t *testing.T) {
	root := project(t, map[string]string{"a.txt": "nothing here\n", "b.txt": "03-1234-5678\n"})
	items, _ := ReadReport("- missing.txt:1 [PHONE:001]\n- ../outside.txt:1 [PHONE:002]\n- notes/[SECRET:aws-access-key:002].txt:2 [PHONE:003]\n- a.txt:1 [PHONE:004]\n- b.txt:1 [PHONE:005]\n- b.txt:1 [PHONE:006]\n")

	shown := Show(root, items, false)

	want := map[string]string{
		"[PHONE:001]": "the file is not there",
		"[PHONE:002]": "the file is not there, or it is outside the project folder",
		"[PHONE:003]": "the file name holds a hidden value",
		"[PHONE:004]": "not found at this line",
		"[PHONE:006]": "not found at this line",
	}
	for _, one := range shown {
		if wantText, expected := want[one.Placeholder]; expected && !strings.Contains(one.Problem, wantText) {
			t.Errorf("%s: problem %q, want %q", one.Placeholder, one.Problem, wantText)
		}
		if one.Placeholder == "[PHONE:005]" && one.Problem != "" {
			t.Errorf("a match that exists: %+v", one)
		}
	}
}

func TestAMinifiedLineGivesOnlyTheTextNextToTheMatch(t *testing.T) {
	line := strings.Repeat("x", 5000) + " 03-1234-5678 " + strings.Repeat("y", 5000)
	root := project(t, map[string]string{"main.js": line + "\n"})
	items, _ := ReadReport("- main.js:1 [PHONE:001]\n")

	shown := Show(root, items, false)

	if utf8.RuneCountInString(shown[0].Context) > 130 || !strings.HasPrefix(shown[0].Context, "…") || !strings.HasSuffix(shown[0].Context, "…") || !strings.Contains(shown[0].Context, "03-****-**78") {
		t.Errorf("context of %d runes: %q", utf8.RuneCountInString(shown[0].Context), shown[0].Context)
	}
}

func TestControlCharactersInTheFileCannotMoveTheCursorOrHideText(t *testing.T) {
	root := project(t, map[string]string{"a.txt": "\x1b[2J\x1b[Hfake prompt \x07 03-1234-5678\ttab   end\n"})
	items, _ := ReadReport("- a.txt:1 [PHONE:001]\n")

	for _, reveal := range []bool{false, true} {
		shown := Show(root, items, reveal)

		for _, character := range shown[0].Context + shown[0].Value {
			if character < ' ' || character == 0x7f || character == ' ' {
				t.Errorf("a control character %q is in the output (reveal %v): %q", character, reveal, shown[0].Context)
			}
		}
	}
}

func TestMaskKeepsTheShapeAndHidesTheMiddle(t *testing.T) {
	for value, want := range map[string]string{
		"090-1234-5678":        "090-****-**78",
		"03-1234-5678":         "03-****-**78",
		"AKIAIOSFODNN7EXAMPLE": "AKI***************LE",
		"12345":                "*****",
		"123456":               "1****6",
		"":                     "",
		"日本語の電話番号です":           "日本語*****です",
	} {
		if got := Mask(value); got != want {
			t.Errorf("Mask(%q) = %q, want %q", value, got, want)
		}
	}
}

func FuzzMaskAndShowNeverPanicAndMaskedOutputHidesTheMiddle(f *testing.F) {
	for _, seed := range []string{"", "03-1234-5678", "\x00\x1b[", "日本語 090-1234-5678 \xff", strings.Repeat("a", 300)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		masked := Mask(text)
		if utf8.ValidString(text) && utf8.RuneCountInString(masked) != utf8.RuneCountInString(text) {
			t.Fatalf("Mask changed the length of %q", text)
		}

		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, "f.txt"), []byte(text+"\ntel 03-1234-5678\n"), 0o600); err != nil {
			t.Skip()
		}
		root, err := pathguard.NewRoot(directory)
		if err != nil {
			t.Skip()
		}
		items, readErr := ReadReport("- f.txt:2 [PHONE:001]\n- f.txt:1 [PHONE:002]\n")
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, one := range Show(root, items, false) {
			if strings.Contains(one.Value+one.Context, "1234") && one.Problem == "" && one.Placeholder == "[PHONE:001]" {
				t.Fatalf("the middle of the number is in the masked output: %+v", one)
			}
		}
	})
}
