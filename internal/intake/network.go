package intake

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"

	"github.com/kenzietann/omamori/internal/event"
)

// normalizeNetworkJSON recognizes the native record shapes, not file names or a lone timestamp.
// Original fields are kept by the caller under raw.*. These mappings describe observations;
// a sensor allowing traffic or a connection finishing does not establish attack success.
func normalizeNetworkJSON(object map[string]any, fields map[string]string) (jsonMapping, bool) {
	if kind := suricataKind(object); kind != "" {
		normalizeSuricata(object, fields, kind)
		return jsonMapping{Source: "suricata", Times: []jsonTimestamp{{Value: object["timestamp"]}}}, true
	}
	if kind := zeekKind(object); kind != "" {
		normalizeZeek(object, fields, kind)
		return jsonMapping{Source: "zeek", Times: []jsonTimestamp{{Value: object["ts"]}}}, true
	}
	return jsonMapping{}, false
}

func networkString(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}

// Descriptive exporter fields are text. A malformed boolean or number must not
// turn into a URL, signature or protocol label; numeric fields use their own helpers.
func putNetworkText(fields map[string]string, name string, value any) {
	if text, ok := value.(string); ok {
		putJSONField(fields, name, text)
	}
}

func suricataKind(object map[string]any) string {
	if object["timestamp"] == nil {
		return ""
	}
	kind := networkString(object, "event_type")
	switch kind {
	case "alert", "http", "dns", "flow", "tls":
	default:
		return ""
	}
	if _, ok := object[kind].(map[string]any); !ok {
		return ""
	}
	// An EVE record has a flow identifier or a complete tuple. Bad addresses can still be
	// recognized as EVE, but they never become canonical IP fields.
	if _, ok := networkIdentifier(object["flow_id"]); !ok &&
		(networkString(object, "src_ip") == "" || networkString(object, "dest_ip") == "" || networkString(object, "proto") == "") {
		return ""
	}
	return kind
}

func zeekKind(object map[string]any) string {
	if object["ts"] == nil {
		return ""
	}
	if strings.Contains(networkString(object, "note"), "::") && networkString(object, "msg") != "" {
		if _, actions := object["actions"].([]any); actions || hasZeekTuple(object) {
			return "notice"
		}
	}
	if !hasZeekTuple(object) {
		return ""
	}
	switch {
	case networkString(object, "uri") != "" && (networkString(object, "method") != "" || object["trans_depth"] != nil):
		return "http"
	case networkString(object, "query") != "" && (object["qtype"] != nil || networkString(object, "qtype_name") != "" || object["trans_id"] != nil):
		return "dns"
	case networkString(object, "conn_state") != "" && networkString(object, "proto") != "":
		return "conn"
	}
	return ""
}

func hasZeekTuple(object map[string]any) bool {
	return networkString(object, "uid") != "" && networkString(object, "id.orig_h") != "" && networkString(object, "id.resp_h") != ""
}

func networkIdentifier(value any) (string, bool) {
	var text string
	switch typed := value.(type) {
	case json.Number:
		text = typed.String()
	case string:
		text = typed
	default:
		return "", false
	}
	number, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(number, 10), true
}

func normalizeSuricata(object map[string]any, fields map[string]string, kind string) {
	fields[event.Product], fields[event.Service], fields[event.Category] = "suricata", kind, "network"
	fields[event.Action] = kind
	putJSONIP(fields, event.SourceIP, object["src_ip"])
	putJSONIP(fields, event.DestIP, object["dest_ip"])
	putJSONPort(fields, "src_port", object["src_port"])
	putJSONPort(fields, "dst_port", object["dest_port"])
	putNetworkText(fields, "protocol", strings.ToLower(networkString(object, "proto")))
	putNetworkText(fields, "app_protocol", object["app_proto"])
	if value, valid := networkIdentifier(object["flow_id"]); valid {
		fields["flow_id"] = value
	}
	if kind == "alert" {
		putNetworkText(fields, event.Signature, jsonValue(object, "alert", "signature"))
		putNetworkText(fields, "policy_action", jsonValue(object, "alert", "action"))
		putNetworkText(fields, "signature_category", jsonValue(object, "alert", "category"))
		putJSONInteger(fields, "signature_id", jsonValue(object, "alert", "signature_id"), 0, math.MaxInt64)
		putJSONInteger(fields, "rule_severity", jsonValue(object, "alert", "severity"), 0, math.MaxInt32)
	}
	if kind == "http" {
		fields[event.Category], fields[event.Action] = "webserver", "http_request"
	}
	// EVE alerts can carry the HTTP transaction that caused the sensor match too.
	if _, present := object["http"].(map[string]any); present {
		putNetworkText(fields, event.URL, jsonValue(object, "http", "url"))
		putNetworkText(fields, event.Method, jsonValue(object, "http", "http_method"))
		putNetworkText(fields, event.UserAgent, jsonValue(object, "http", "http_user_agent"))
		putNetworkText(fields, event.Referrer, jsonValue(object, "http", "http_refer"))
		putNetworkText(fields, "http_host", jsonValue(object, "http", "hostname"))
		putJSONInteger(fields, event.Status, jsonValue(object, "http", "status"), 100, 599)
		putJSONInteger(fields, event.Bytes, jsonValue(object, "http", "length"), 0, math.MaxInt64)
	}
	if kind == "dns" {
		putNetworkText(fields, "dns_query", jsonValue(object, "dns", "rrname"))
		putNetworkText(fields, "dns_type", jsonValue(object, "dns", "rrtype"))
		putNetworkText(fields, "dns_rcode", jsonValue(object, "dns", "rcode"))
		putNetworkText(fields, "dns_record_type", jsonValue(object, "dns", "type"))
		// Newer EVE DNS answers keep questions in queries. Pick only a single
		// question: joining distinct names would invent an entity that was never queried.
		if queries, ok := jsonValue(object, "dns", "queries").([]any); ok && len(queries) == 1 {
			if query, ok := queries[0].(map[string]any); ok {
				if fields["dns_query"] == "" {
					putNetworkText(fields, "dns_query", query["rrname"])
				}
				if fields["dns_type"] == "" {
					putNetworkText(fields, "dns_type", query["rrtype"])
				}
			}
		}
	}
	if kind == "tls" {
		putNetworkText(fields, "tls_sni", jsonValue(object, "tls", "sni"))
		putNetworkText(fields, "tls_version", jsonValue(object, "tls", "version"))
	}
	if kind == "flow" {
		putNetworkText(fields, "flow_state", jsonValue(object, "flow", "state"))
		putJSONInteger(fields, "bytes_to_server", jsonValue(object, "flow", "bytes_toserver"), 0, math.MaxInt64)
		putJSONInteger(fields, "bytes_to_client", jsonValue(object, "flow", "bytes_toclient"), 0, math.MaxInt64)
	}
}

func normalizeZeek(object map[string]any, fields map[string]string, kind string) {
	fields[event.Product], fields[event.Service], fields[event.Category] = "zeek", kind, "network"
	fields[event.Action] = kind
	putNetworkText(fields, "uid", object["uid"])
	putJSONIP(fields, event.SourceIP, object["id.orig_h"])
	putJSONIP(fields, event.DestIP, object["id.resp_h"])
	putJSONPort(fields, "src_port", object["id.orig_p"])
	putJSONPort(fields, "dst_port", object["id.resp_p"])
	putNetworkText(fields, "protocol", strings.ToLower(networkString(object, "proto")))
	switch kind {
	case "conn":
		fields[event.Action] = "network_connect"
		putNetworkText(fields, "conn_state", object["conn_state"])
		putNetworkText(fields, "app_protocol", object["service"])
		putJSONInteger(fields, "bytes_sent", object["orig_bytes"], 0, math.MaxInt64)
		putJSONInteger(fields, "bytes_received", object["resp_bytes"], 0, math.MaxInt64)
	case "http":
		fields[event.Category], fields[event.Action] = "webserver", "http_request"
		putNetworkText(fields, event.URL, object["uri"])
		putNetworkText(fields, event.Method, object["method"])
		putNetworkText(fields, event.UserAgent, object["user_agent"])
		putNetworkText(fields, event.Referrer, object["referrer"])
		putNetworkText(fields, "http_host", object["host"])
		putJSONInteger(fields, event.Status, object["status_code"], 100, 599)
		putJSONInteger(fields, event.Bytes, object["response_body_len"], 0, math.MaxInt64)
	case "dns":
		putNetworkText(fields, "dns_query", object["query"])
		putNetworkText(fields, "dns_type", object["qtype_name"])
		putNetworkText(fields, "dns_rcode", object["rcode_name"])
	case "notice":
		putNetworkText(fields, event.Signature, object["note"])
		putNetworkText(fields, event.Message, object["msg"])
		if object["id.orig_h"] == nil {
			putJSONIP(fields, event.SourceIP, object["src"])
		}
		if object["id.resp_h"] == nil {
			putJSONIP(fields, event.DestIP, object["dst"])
		}
	}
}
