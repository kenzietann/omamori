package intake

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/event"
)

const suricataAlertSample = `{"timestamp":"2026-11-12T01:02:03.123456+0900","flow_id":1676750115612680,"event_type":"alert","src_ip":"203.0.113.9","src_port":50096,"dest_ip":"192.0.2.10","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature_id":123456,"signature":"Synthetic network test","category":"Example category","severity":2}}`
const zeekHTTPSample = `{"ts":1794430800.25,"uid":"CtestHTTP","id.orig_h":"203.0.113.9","id.orig_p":50096,"id.resp_h":"192.0.2.10","id.resp_p":80,"trans_depth":1,"method":"GET","host":"example.test","uri":"/.env","user_agent":"ExampleBrowser","status_code":404,"response_body_len":20}`

func networkObject(t *testing.T, line string) map[string]any {
	t.Helper()
	var object map[string]any
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	return object
}

func TestNetworkJSONMappings(t *testing.T) {
	cases := []struct {
		name, line, source string
		want               map[string]string
	}{
		{"Suricata alert", suricataAlertSample, "suricata", map[string]string{
			"product": "suricata", "service": "alert", "action": "alert", "category": "network", "src_ip": "203.0.113.9", "dst_ip": "192.0.2.10",
			"src_port": "50096", "dst_port": "80", "protocol": "tcp", "flow_id": "1676750115612680", "signature": "Synthetic network test", "signature_id": "123456", "policy_action": "allowed", "rule_severity": "2",
		}},
		{"Suricata HTTP", `{"timestamp":"2026-11-12T01:02:03Z","event_type":"http","flow_id":1,"src_ip":"::ffff:203.0.113.9","dest_ip":"2001:db8::2","http":{"hostname":"example.test","url":"/login?x=1","http_method":"POST","http_user_agent":"ExampleBrowser","http_refer":"https://example.test/","status":302,"length":2048}}`, "suricata", map[string]string{
			"product": "suricata", "service": "http", "category": "webserver", "action": "http_request", "src_ip": "203.0.113.9", "dst_ip": "2001:db8::2", "url": "/login?x=1", "method": "POST", "status": "302", "bytes": "2048", "http_host": "example.test", "user_agent": "ExampleBrowser", "referrer": "https://example.test/",
		}},
		{"Suricata legacy DNS", `{"timestamp":"2026-11-12T01:02:03Z","event_type":"dns","flow_id":1,"dns":{"type":"answer","rrname":"example.test","rrtype":"A","rcode":"NOERROR"}}`, "suricata", map[string]string{
			"service": "dns", "action": "dns", "dns_query": "example.test", "dns_type": "A", "dns_rcode": "NOERROR", "dns_record_type": "answer",
		}},
		{"Suricata DNS queries", `{"timestamp":"2026-11-12T01:02:03Z","event_type":"dns","flow_id":1,"dns":{"type":"answer","queries":[{"rrname":"example.test","rrtype":"AAAA"}],"rcode":"NXDOMAIN"}}`, "suricata", map[string]string{
			"dns_query": "example.test", "dns_type": "AAAA", "dns_rcode": "NXDOMAIN",
		}},
		{"Suricata flow", `{"timestamp":"2026-11-12T01:02:03Z","event_type":"flow","flow_id":18446744073709551615,"flow":{"state":"closed","bytes_toserver":123,"bytes_toclient":456}}`, "suricata", map[string]string{
			"service": "flow", "action": "flow", "flow_id": "18446744073709551615", "flow_state": "closed", "bytes_to_server": "123", "bytes_to_client": "456",
		}},
		{"Suricata TLS", `{"timestamp":"2026-11-12T01:02:03Z","event_type":"tls","flow_id":1,"tls":{"sni":"example.test","version":"TLS 1.3"}}`, "suricata", map[string]string{
			"service": "tls", "tls_sni": "example.test", "tls_version": "TLS 1.3",
		}},
		{"Zeek connection", `{"ts":1794430800.25,"uid":"CtestConn","id.orig_h":"203.0.113.9","id.orig_p":50096,"id.resp_h":"192.0.2.10","id.resp_p":443,"proto":"tcp","service":"ssl","orig_bytes":100,"resp_bytes":200,"conn_state":"SF"}`, "zeek", map[string]string{
			"product": "zeek", "service": "conn", "category": "network", "action": "network_connect", "src_ip": "203.0.113.9", "dst_ip": "192.0.2.10", "src_port": "50096", "dst_port": "443", "uid": "CtestConn", "app_protocol": "ssl", "conn_state": "SF", "bytes_sent": "100", "bytes_received": "200",
		}},
		{"Zeek HTTP", zeekHTTPSample, "zeek", map[string]string{
			"product": "zeek", "service": "http", "category": "webserver", "action": "http_request", "src_ip": "203.0.113.9", "url": "/.env", "http_host": "example.test", "method": "GET", "status": "404", "bytes": "20",
		}},
		{"Zeek DNS", `{"ts":1794430800.25,"uid":"CtestDNS","id.orig_h":"203.0.113.9","id.resp_h":"192.0.2.53","proto":"udp","trans_id":124,"query":"example.test","qtype_name":"A","rcode_name":"NXDOMAIN"}`, "zeek", map[string]string{
			"service": "dns", "action": "dns", "dns_query": "example.test", "dns_type": "A", "dns_rcode": "NXDOMAIN", "src_ip": "203.0.113.9", "dst_ip": "192.0.2.53",
		}},
		{"Zeek notice without connection", `{"ts":"2026-11-12T01:02:03Z","note":"Scan::Port_Scan","msg":"Synthetic scan notice","src":"203.0.113.9","dst":"192.0.2.10","actions":["Notice::ACTION_LOG"]}`, "zeek", map[string]string{
			"service": "notice", "action": "notice", "signature": "Scan::Port_Scan", "message": "Synthetic scan notice", "src_ip": "203.0.113.9", "dst_ip": "192.0.2.10",
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			object := networkObject(t, test.line)
			object["product"], object["action"], object["outcome"] = "pretend-product", "pretend-action", "success"
			fields := map[string]string{}
			mapping, ok := normalizeNetworkJSON(object, fields)
			if !ok || mapping.Source != test.source || len(mapping.Times) != 1 {
				t.Fatalf("mapping: %#v, recognized: %v", mapping, ok)
			}
			wantFields(t, event.Event{Fields: fields}, test.want)
			if fields[event.Outcome] != "" || fields[event.Host] != "" || fields[event.Action] == "pretend-action" {
				t.Fatalf("unproved outcome, host or input action became canonical: %v", fields)
			}
			again := map[string]string{}
			normalizeNetworkJSON(object, again)
			if !reflect.DeepEqual(fields, again) {
				t.Fatal("normalization was not deterministic")
			}
		})
	}
}

func TestNetworkJSONLookalikesStayGeneric(t *testing.T) {
	for _, line := range []string{
		`{"timestamp":"2026-11-12T01:02:03Z","event_type":"alert"}`,
		`{"timestamp":"2026-11-12T01:02:03Z","event_type":"alert","alert":{"signature":"plain app alert"}}`,
		`{"timestamp":"2026-11-12T01:02:03Z","event_type":"alert","flow_id":false,"alert":{}}`,
		`{"timestamp":"2026-11-12T01:02:03Z","event_type":"custom","flow_id":1,"custom":{}}`,
		`{"timestamp":"2026-11-12T01:02:03Z","event_type":"http","flow_id":1,"http":"not an object"}`,
		`{"ts":1794430800,"uid":"plain-user-id","uri":"/test","method":"GET"}`,
		`{"ts":1794430800,"uid":"Ctest","id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.2"}`,
		`{"ts":1794430800,"note":"normal note","msg":"normal message","actions":[]}`,
	} {
		fields := map[string]string{}
		if mapping, recognized := normalizeNetworkJSON(networkObject(t, line), fields); recognized || mapping.Source != "" || len(fields) != 0 {
			t.Errorf("look-alike was recognized: %s: %#v %v", line, mapping, fields)
		}
	}
}

func TestNetworkJSONDoesNotInventValidFieldsFromBadValues(t *testing.T) {
	line := `{"timestamp":"2026-11-12T01:02:03Z","event_type":"http","flow_id":1,"src_ip":"bad address","dest_ip":"fe80::1%eth0","src_port":-1,"dest_port":70000,"http":{"status":999,"length":-1,"hostname":"target.example","url":"/x"}}`
	fields := map[string]string{}
	if _, ok := normalizeNetworkJSON(networkObject(t, line), fields); !ok {
		t.Fatal("a recognizable record with bad optional fields was dropped")
	}
	for _, name := range []string{event.SourceIP, event.DestIP, event.Host, event.Status, event.Bytes, "src_port", "dst_port", event.Outcome} {
		if _, exists := fields[name]; exists {
			t.Errorf("invalid %s was populated: %q", name, fields[name])
		}
	}

	multiple := networkObject(t, `{"timestamp":"2026-11-12T01:02:03Z","event_type":"dns","flow_id":1,"dns":{"queries":[{"rrname":"a.example"},{"rrname":"b.example"}]}}`)
	fields = map[string]string{}
	normalizeNetworkJSON(multiple, fields)
	if fields["dns_query"] != "" {
		t.Fatal("several DNS questions became one invented query")
	}
}

func TestNetworkDescriptiveTextIsNotCoercedFromOtherScalars(t *testing.T) {
	cases := []struct {
		name, format, line string
		absent             []string
		retained           map[string]string
	}{
		{"Suricata", FormatSuricata,
			`{"timestamp":"2026-11-12T01:02:03Z","event_type":"alert","flow_id":1,"app_proto":false,"alert":{"signature":true,"action":42,"category":false,"signature_id":123,"severity":2},"http":{"url":true,"http_method":42,"http_user_agent":false,"http_refer":123,"hostname":false,"status":404,"length":20}}`,
			[]string{"app_protocol", "signature", "policy_action", "signature_category", "url", "method", "user_agent", "referrer", "http_host"},
			map[string]string{"flow_id": "1", "signature_id": "123", "rule_severity": "2", "status": "404", "bytes": "20", "raw.alert.signature": "true", "raw.http.http_method": "42"}},
		{"Zeek", FormatZeek,
			`{"ts":1794430800.25,"uid":"CtestHTTP","id.orig_h":"203.0.113.9","id.resp_h":"192.0.2.10","trans_depth":1,"uri":"/.env","method":false,"user_agent":123,"referrer":true,"host":42,"status_code":404,"response_body_len":20}`,
			[]string{"method", "user_agent", "referrer", "http_host"},
			map[string]string{"uid": "CtestHTTP", "url": "/.env", "status": "404", "bytes": "20", "raw.method": "false", "raw.host": "42"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, stats := parseOne(t, test.format, test.line)
			if stats.Events != 1 || stats.Malformed != 0 {
				t.Fatalf("bad optional text hid the event: %#v", stats)
			}
			for _, name := range test.absent {
				if value, found := got.Fields[name]; found {
					t.Errorf("non-text %s became %q", name, value)
				}
			}
			wantFields(t, got, test.retained)
		})
	}
}

func TestNetworkJSONThroughIntake(t *testing.T) {
	for _, test := range []struct{ format, line, source string }{
		{FormatJSON, suricataAlertSample, "suricata"}, {FormatSuricata, suricataAlertSample, "suricata"},
		{FormatJSON, zeekHTTPSample, "zeek"}, {FormatZeek, zeekHTTPSample, "zeek"},
	} {
		parsed, stats := parseOne(t, test.format, test.line)
		if parsed.Source != test.source || stats.Events != 1 || stats.Malformed != 0 {
			t.Errorf("%s: source %s, stats %#v", test.format, parsed.Source, stats)
		}
		if parsed.Fields["collector"] != test.source {
			t.Errorf("collector missing: %v", parsed.Fields)
		}
	}
	parsed, stats := parseOne(t, FormatSuricata, zeekHTTPSample)
	if stats.Events != 0 || stats.Malformed != 1 || len(parsed.Fields) != 0 {
		t.Fatal("a forced Suricata parser accepted Zeek")
	}
}

func FuzzNetworkJSONNormalization(f *testing.F) {
	for _, seed := range []string{suricataAlertSample, zeekHTTPSample,
		`{"ts":1,"note":"Test::Notice","msg":"test","actions":[]}`, `{}`, `{"event_type":"alert","alert":{}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > maxLineBytes {
			return
		}
		var object map[string]any
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		if decoder.Decode(&object) != nil {
			return
		}
		fields := map[string]string{}
		mapping, recognized := normalizeNetworkJSON(object, fields)
		if !recognized {
			if len(fields) != 0 {
				t.Fatal("unrecognized data changed fields")
			}
			return
		}
		if mapping.Source != "zeek" && mapping.Source != "suricata" || len(mapping.Times) != 1 {
			t.Fatal("bad mapping state")
		}
		for key, value := range fields {
			if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxValueRunes || !clean(value) {
				t.Fatalf("unbounded or unsafe normalized field %q", key)
			}
		}
	})
}
