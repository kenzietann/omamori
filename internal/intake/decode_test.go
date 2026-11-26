package intake

import (
	"testing"

	"github.com/kenzietann/omamori/internal/event"
)

func TestDecodedFieldsOfARequest(t *testing.T) {
	// The URLs of a real attack (2026-11-26) that the patterns on the raw URL missed.
	cases := []struct {
		url, decoded, compact string
	}{
		{"/v?tag=%2527%2520OR%25201%253D1--", "/v?tag=' OR 1=1--", "/v?tag='OR1=1--"},
		{"/v?id=1/**/UN/**/ION/**/SEL/**/ECT/**/1,2", "/v?id=1 UN ION SEL ECT 1,2", "/v?id=1UNIONSELECT1,2"},
		{"/?q=1%2F%2A%2A%2FUnIoN%2F%2A%2A%2FsElEcT%2F%2A%2A%2F1", "/?q=1 UnIoN sElEcT 1", "/?q=1UnIoNsElEcT1"},
		{"/?path=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "/?path=../../etc/passwd", ""},
	}
	for _, c := range cases {
		fields := map[string]string{event.Category: "webserver", event.URL: c.url}
		addDecoded(fields)
		if fields[URLDecoded] != c.decoded || fields[URLCompact] != c.compact {
			t.Errorf("%s:\n decoded %q, want %q\n compact %q, want %q", c.url, fields[URLDecoded], c.decoded, fields[URLCompact], c.compact)
		}
	}
}

func TestDecodedFieldsAreOnlyAddedWhenTheyDiffer(t *testing.T) {
	fields := map[string]string{event.Category: "webserver", event.URL: "/expenses/list"}
	addDecoded(fields)
	if _, found := fields[URLDecoded]; found {
		t.Errorf("a plain URL got a decoded copy: %v", fields)
	}
	if fields[URLPath] != "/expenses/list" {
		t.Errorf("url_path = %q", fields[URLPath])
	}
	other := map[string]string{event.URL: "/a?x=%27"}
	addDecoded(other)
	if len(other) != 1 {
		t.Errorf("a line that is not a request got fields: %v", other)
	}
}

func TestDecodingKeepsBrokenEscapesAndRemovesControlCharacters(t *testing.T) {
	fields := map[string]string{event.Category: "webserver", event.URL: "/a?x=100%zz&y=%27%0a%00", event.Referrer: "-"}
	addDecoded(fields)
	if got := fields[URLDecoded]; got != "/a?x=100%zz&y='  " {
		t.Errorf("decoded %q", got)
	}
	if _, found := fields[ReferrerDecoded]; found {
		t.Error(`a Referer of "-" got a decoded copy`)
	}
	if fields[URLPath] != "/a" {
		t.Errorf("url_path = %q", fields[URLPath])
	}
}

func TestDecodedReferrer(t *testing.T) {
	fields := map[string]string{event.Category: "webserver", event.URL: "/", event.Referrer: "http://x/?id=1%2527%2520OR%2520%25271"}
	addDecoded(fields)
	if got := fields[ReferrerDecoded]; got != "http://x/?id=1' OR '1" {
		t.Errorf("referrer decoded %q", got)
	}
}
