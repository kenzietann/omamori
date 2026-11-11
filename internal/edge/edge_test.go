package edge

import "testing"

func TestEmbedded(t *testing.T) {
	testCases := []struct {
		name  string
		text  string
		match string
		want  bool
	}{
		{"alone", "03-1234-5678", "03-1234-5678", false},
		{"after a label", "Tel: 03-1234-5678", "03-1234-5678", false},
		{"at the end of a sentence", "Call 03-1234-5678.", "03-1234-5678", false},
		{"followed by a full stop and a word", "Call 03-1234-5678. Thanks", "03-1234-5678", false},
		{"in Japanese text", "電話03-1234-5678です", "03-1234-5678", false},
		{"after a full width colon", "電話：03-1234-5678", "03-1234-5678", false},
		{"in brackets", "(03-1234-5678)", "03-1234-5678", false},
		{"in quotes", `"03-1234-5678"`, "03-1234-5678", false},
		{"after a comma", "a,03-1234-5678,b", "03-1234-5678", false},
		{"the fraction of a decimal", "x = -0.0643290124;", "0643290124", true},
		{"a decimal in a list", "4.0767416621, -3.3077", "0767416621", true},
		{"a number with a decimal after it", "0312345678.5", "0312345678", true},
		{"after a letter", "id=abc0312345678", "0312345678", true},
		{"before a letter", "0312345678abc", "0312345678", true},
		{"after an underscore", "x_0312345678", "0312345678", true},
		{"before an underscore", "0312345678_x", "0312345678", true},
		{"after a full width decimal", "１.0312345678", "0312345678", true},
		{"a dot after a letter is not a decimal", "v.0312345678", "0312345678", false},
		{"a number that starts with a bracket can follow a word", "TEL(06)6789-0123", "(06)6789-0123", false},
		{"a number that starts with a plus sign can follow a word", "tel+81 90-1234-5678", "+81 90-1234-5678", false},
		{"a bracket number that ends in a digit before a letter", "(06)6789-0123x", "(06)6789-0123", true},
		{"a dot after a space is not a decimal", "price . 03-1234-5678", "03-1234-5678", false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			start := indexOf(testCase.text, testCase.match)
			if start < 0 {
				t.Fatalf("%q is not in %q", testCase.match, testCase.text)
			}

			if got := Embedded(testCase.text, start, start+len(testCase.match)); got != testCase.want {
				t.Errorf("Embedded(%q, %q) = %v, want %v", testCase.text, testCase.match, got, testCase.want)
			}
		})
	}
}

func TestBadRangesAreNeverEmbedded(t *testing.T) {
	for _, bounds := range [][2]int{{-1, 3}, {0, 99}, {3, 3}, {4, 2}} {
		if Embedded("abcdef", bounds[0], bounds[1]) {
			t.Errorf("range %v was embedded", bounds)
		}
	}
}

func FuzzEmbeddedNeverPanics(f *testing.F) {
	f.Add("0.0643290124", 2, 12)
	f.Add("日本語03-1234-5678", 9, 21)
	f.Add("\xff\xfe", 0, 1)
	f.Fuzz(func(t *testing.T, text string, start, end int) {
		Embedded(text, start, end)
	})
}

func indexOf(text, part string) int {
	for index := 0; index+len(part) <= len(text); index++ {
		if text[index:index+len(part)] == part {
			return index
		}
	}

	return -1
}

func TestInUUID(t *testing.T) {
	uuid := "00000000-0000-0000-0000-000000000000"
	for _, testCase := range []struct {
		name  string
		text  string
		match string
		want  bool
	}{
		{"the last group", "id " + uuid + " end", "000000000000", true},
		{"the middle groups", "id " + uuid + " end", "0000-0000-0000", true},
		{"a real uuid with letters", "id 123e4567-e89b-12d3-a456-426614174000", "426614174000", true},
		{"a number with hyphens that is no uuid", "My Number 1234-5678-9018", "1234-5678-9018", false},
		{"a number next to a uuid", uuid + " 123456789018", "123456789018", false},
		{"too short a group", "00000000-0000-0000-0000-00000000000", "00000000000", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			start := indexOf(testCase.text, testCase.match)
			if start < 0 {
				t.Fatalf("%q is not in %q", testCase.match, testCase.text)
			}
			if got := InUUID(testCase.text, start, start+len(testCase.match)); got != testCase.want {
				t.Errorf("InUUID(%q, %q) = %v, want %v", testCase.text, testCase.match, got, testCase.want)
			}
		})
	}
}

func TestInChain(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		text  string
		match string
		want  bool
	}{
		{"a group at the end of a hex dump", "0024 ffff 8000 0014 0000 0000 0000", "0000 0000 0000", true},
		{"a group at the start of a row", "0000 0000 0000  .$..", "0000 0000 0000", false},
		{"a group before more digits", "0000 0000 0000 1234 5678", "0000 0000 0000", true},
		{"an aws account number", "arn:aws:ecs:us-west-2:123456789123:cluster/x", "123456789123", true},
		{"a number after a label", "My Number: 1234 5678 9018", "1234 5678 9018", false},
		{"a number after a word and a space", "ID 1234 5678 9018", "1234 5678 9018", false},
		{"a number alone", "1234 5678 9018", "1234 5678 9018", false},
		{"a phone prefix before a number is no row", "090 1234 5678 9018", "1234 5678 9018", false},
		{"a number at the start of the text", "123456789018 x", "123456789018", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			start := indexOf(testCase.text, testCase.match)
			if start < 0 {
				t.Fatalf("%q is not in %q", testCase.match, testCase.text)
			}
			if got := InChain(testCase.text, start, start+len(testCase.match)); got != testCase.want {
				t.Errorf("InChain(%q, %q) = %v, want %v", testCase.text, testCase.match, got, testCase.want)
			}
		})
	}
}

func TestTrivial(t *testing.T) {
	for value, want := range map[string]bool{
		"0123456789": true, "1234567890": true, "9876543210": true, "0000000000": true, "111111111111": true, "012-345-6789": true,
		"090-1234-5678": false, "03-1234-5678": false, "0120-123-456": false, "123456789018": false, "12345": false, "": false, "０１２３４５６７８９": true,
	} {
		if got := Trivial(value); got != want {
			t.Errorf("Trivial(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestPlaceholderCredentials(t *testing.T) {
	for value, want := range map[string]bool{
		"https://user:pass@":               true,
		"mongodb://bob:bar@":               true,
		"postgres://jack:secret@":          true,
		"https://REDACTED:REDACTED@":       true,
		"https://username:password@":       true,
		"postgres://admin:${DB_PASSWORD}@": true,
		"postgres://admin:<password>@":     true,
		"postgres://admin:%s@":             true,
		"postgres://admin:xxxxxxxx@":       true,
		"postgres://admin:aaaaaaaa@":       true,
		"postgres://admin:k8Zq2vLp9Xw@":    false,
		"postgres://admin:FakePass123@":    false,
		"https://user@":                    false,
	} {
		if got := PlaceholderCredentials(value); got != want {
			t.Errorf("PlaceholderCredentials(%q) = %v, want %v", value, got, want)
		}
	}
}

func FuzzHelpersNeverPanic(f *testing.F) {
	f.Add("00000000-0000-0000-0000-000000000000", 0, 12)
	f.Add("a:123456789123:b", 2, 14)
	f.Add("\xff", 0, 1)
	f.Fuzz(func(t *testing.T, text string, start, end int) {
		InUUID(text, start, end)
		InChain(text, start, end)
		Trivial(text)
		PlaceholderCredentials(text)
	})
}
