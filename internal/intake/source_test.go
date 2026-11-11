package intake

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMixedJSONSourcesAndOriginalFields(t *testing.T) {
	lines := []string{
		`{"timestamp":"2026-11-10T08:15:02Z","event_type":"alert","flow_id":1,"src_ip":"203.0.113.9","alert":{"signature":"synthetic alert","action":"allowed"},"outcome":"success","product":"linux"}`,
		`{"ts":1794298503,"uid":"Ctest","id.orig_h":"203.0.113.9","id.resp_h":"192.0.2.10","uri":"/.env","method":"GET","status_code":404}`,
		`{"timestamp":"2026-11-10T08:15:04Z","message":"ordinary JSON","outcome":"custom"}`,
	}
	events, stats, err := Parse(strings.NewReader(strings.Join(lines, "\n")), "mixed.jsonl", options)
	if err != nil || stats.Events != 3 || stats.Malformed != 0 || strings.Join(stats.Sources, ",") != "json,suricata,zeek" {
		t.Fatalf("read: %+v %v", stats, err)
	}
	if events[0].Source != FormatSuricata || events[0].Fields["product"] != "suricata" || events[0].Fields["outcome"] != "" ||
		events[0].Fields["raw.product"] != "linux" || events[0].Fields["raw.outcome"] != "success" {
		t.Fatalf("canonical fields did not stay separate from original values: %v", events[0])
	}
	if events[1].Source != FormatZeek || events[1].Fields["raw.id.orig_h"] != "203.0.113.9" || events[1].Fields["collector"] != FormatZeek {
		t.Fatalf("Zeek evidence: %v", events[1])
	}
	if events[2].Source != FormatJSON || events[2].Fields["message"] != "ordinary JSON" || events[2].Fields["raw.message"] != "" {
		t.Fatal("generic JSON changed shape")
	}
}

func TestRecognizedSourceRefusesAmbiguousFlattenedEvidence(t *testing.T) {
	line := `{"ts":1794298503,"uid":"Ctest","id.orig_h":"203.0.113.9","id.resp_h":"192.0.2.10","id":{"orig_h":"198.51.100.1"},"uri":"/","method":"GET"}`
	for _, format := range []string{FormatJSON, FormatZeek} {
		_, stats := parseOne(t, format, line)
		if stats.Events != 0 || stats.Malformed != 1 {
			t.Errorf("%s kept contradictory raw evidence: %+v", format, stats)
		}
	}
}

func TestSourceFieldsStayBounded(t *testing.T) {
	object := map[string]any{"timestamp": "2026-11-10T08:15:02Z", "event_type": "alert", "flow_id": 1,
		"alert": map[string]any{"signature": strings.Repeat("x", 4000)}}
	for index := 0; index < 400; index++ {
		object[fmt.Sprintf("field_%03d", index)] = "test"
	}
	data, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	event, stats := parseOne(t, FormatSuricata, string(data))
	if stats.Events != 1 || len(event.Fields) > maxJSONFields || len(event.Fields["signature"]) != maxValueRunes || event.Fields["collector"] != FormatSuricata {
		t.Fatalf("unbounded fields or missing normalized facts: %+v, %d fields", stats, len(event.Fields))
	}
}

func TestInvalidSourceTimestampDoesNotBecomeCollectorTime(t *testing.T) {
	for _, stamp := range []string{`"yesterday"`, `{}`, `[]`, `true`} {
		line := `{"@timestamp":"2026-11-10T08:15:02Z","winlog":{"event_id":1,"provider_name":"Microsoft-Windows-Sysmon","channel":"Microsoft-Windows-Sysmon/Operational","event_data":{"UtcTime":` + stamp + `}}}`
		_, stats := parseOne(t, FormatWindows, line)
		if stats.Events != 0 || stats.Malformed != 1 {
			t.Fatalf("invalid event time %s fell back to collector time: %+v", stamp, stats)
		}
	}
}

func FuzzSourceJSON(f *testing.F) {
	f.Add(`{"timestamp":"2026-11-10T08:15:02Z","event_type":"alert","flow_id":1,"alert":{"signature":"test"}}`)
	f.Add(`{"ts":1794298503,"uid":"Ctest","id.orig_h":"203.0.113.9","id.resp_h":"192.0.2.10","uri":"/","method":"GET"}`)
	f.Add(`{"@timestamp":"2026-11-10T08:15:02Z","winlog":{"event_id":1,"provider_name":"Microsoft-Windows-Sysmon","channel":"Microsoft-Windows-Sysmon/Operational","event_data":{"UtcTime":{}}}}`)
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > maxLineBytes {
			return
		}
		for _, format := range []string{FormatJSON, FormatSuricata, FormatZeek, FormatWazuh, FormatWindows} {
			chosen := Options{Year: 2026, Location: time.UTC, Format: format}
			events, _, _ := Parse(strings.NewReader(line), "fuzz.jsonl", chosen)
			for _, event := range events {
				if len(event.Fields) > maxJSONFields {
					t.Fatal("field limit exceeded")
				}
			}
		}
	})
}
