package intake

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/event"
)

func normalizeHostJSON(object map[string]any, fields map[string]string) (jsonMapping, bool) {
	if wazuhAlert(object) {
		clearHostFields(fields)
		fields[event.Product], fields[event.Category], fields[event.Action] = "wazuh", "alert", "alert"
		putHostText(fields, event.Service, jsonValue(object, "decoder", "name"))
		putHostText(fields, event.Host, jsonValue(object, "agent", "name"))
		putHostText(fields, "agent_id", jsonValue(object, "agent", "id"))
		putJSONField(fields, "wazuh_rule_id", jsonValue(object, "rule", "id"))
		putJSONInteger(fields, "wazuh_level", jsonValue(object, "rule", "level"), 0, 16)
		putHostText(fields, event.Signature, jsonValue(object, "rule", "description"))
		putHostText(fields, event.Message, jsonValue(object, "full_log"))
		putJSONIP(fields, event.SourceIP, jsonValue(object, "data", "srcip"))
		putJSONIP(fields, event.DestIP, jsonValue(object, "data", "dstip"))
		putHostText(fields, event.User, jsonValue(object, "data", "dstuser"))
		if fields[event.User] == "" {
			putHostText(fields, event.User, jsonValue(object, "data", "srcuser"))
		}
		times := []jsonTimestamp{{Value: jsonValue(object, "timestamp")}}
		if system, ok := jsonValue(object, "data", "win", "system").(map[string]any); ok {
			data, _ := jsonValue(object, "data", "win", "eventdata").(map[string]any)
			shape := windowsRecord{
				provider: hostJSONText(system, "providerName"), channel: hostJSONText(system, "channel"),
				id: jsonValue(system, "eventID"), host: jsonValue(system, "computer"),
				message: jsonValue(system, "message"), time: jsonValue(system, "systemTime"),
				data: data, lowerCamel: true,
			}
			if shape.valid() {
				times = append(shape.normalize(fields), times...)
			}
		}
		return jsonMapping{Source: "wazuh", Times: times}, true
	}

	if winlog, ok := jsonValue(object, "winlog").(map[string]any); ok {
		data, _ := jsonValue(winlog, "event_data").(map[string]any)
		shape := windowsRecord{
			provider: hostJSONText(winlog, "provider_name"), channel: hostJSONText(winlog, "channel"),
			id: jsonValue(winlog, "event_id"), host: jsonValue(winlog, "computer_name"),
			message: jsonValue(object, "message"), time: jsonValue(winlog, "time_created"), data: data,
		}
		if shape.valid() {
			times := append(shape.normalize(fields), jsonTimestamp{Value: jsonValue(object, "@timestamp")})
			return jsonMapping{Source: "windows", Times: times}, true
		}
	}

	shape := windowsRecord{
		provider: hostJSONText(object, "SourceName"), channel: hostJSONText(object, "Channel"),
		id: jsonValue(object, "EventID"), host: jsonValue(object, "Hostname"),
		message: jsonValue(object, "Message"), time: jsonValue(object, "EventTime"), data: object,
	}
	if shape.valid() && shape.time != nil {
		return jsonMapping{Source: "windows", Times: shape.normalize(fields)}, true
	}
	return jsonMapping{}, false
}

func wazuhAlert(object map[string]any) bool {
	if _, err := strconv.ParseUint(jsonText(object, "rule", "id"), 10, 64); err != nil {
		return false
	}
	if strings.TrimSpace(hostJSONText(object, "agent", "id")) == "" ||
		strings.TrimSpace(hostJSONText(object, "decoder", "name")) == "" {
		return false
	}
	level, err := strconv.ParseInt(jsonText(object, "rule", "level"), 10, 64)
	return err == nil && level >= 0 && level <= 16
}

func hostJSONText(object map[string]any, keys ...string) string {
	text, _ := jsonValue(object, keys...).(string)
	return text
}

// Windows schema text is never coerced from numbers or booleans: a malformed username must not
// create the account "true", or link it to a different source's real user with that name.
func putHostText(fields map[string]string, name string, value any) {
	if text, ok := value.(string); ok {
		switch name {
		case event.User, event.Host, "target_user", "user_domain":
			if strings.IndexFunc(text, unicode.IsControl) >= 0 || utf8.RuneCountInString(text) > maxValueRunes {
				return
			}
		}
		putJSONField(fields, name, text)
	}
}

type windowsRecord struct {
	provider, channel string
	id, host          any
	message, time     any
	data              map[string]any
	lowerCamel        bool
}

func (record windowsRecord) valid() bool {
	text, scalar := scalar(record.id)
	id, err := strconv.ParseInt(text, 10, 64)
	return scalar && err == nil && id >= 0 && id <= 65535 &&
		strings.TrimSpace(record.provider) != "" && strings.TrimSpace(record.channel) != ""
}

func (record windowsRecord) field(name string) any {
	if record.lowerCamel {
		name = strings.ToLower(name[:1]) + name[1:]
	}
	return record.data[name]
}

func clearHostFields(fields map[string]string) {
	for _, key := range []string{event.Product, event.Service, event.Category, event.Action, event.Outcome,
		event.User, event.SourceIP, event.DestIP, event.Host, event.Process, event.Command, event.AuthBy,
		"event_id", "channel", "provider", "src_port", "dst_port", "protocol", "process_id", "process_guid",
		"parent_process", "parent_command", "parent_process_id", "parent_process_guid", "logon_type",
		"target_user", "user_domain", "auth_status", "auth_substatus"} {
		delete(fields, key)
	}
}

func (record windowsRecord) normalize(fields map[string]string) []jsonTimestamp {
	clearHostFields(fields)
	fields[event.Product], fields[event.Service] = "windows", "eventlog"
	putHostText(fields, "provider", record.provider)
	putHostText(fields, "channel", record.channel)
	putJSONInteger(fields, "event_id", record.id, 0, 65535)
	putHostText(fields, event.Host, record.host)
	putHostText(fields, event.Message, record.message)
	times := []jsonTimestamp{{Value: record.time}}
	sysmon := strings.EqualFold(record.provider, "Microsoft-Windows-Sysmon") &&
		strings.EqualFold(record.channel, "Microsoft-Windows-Sysmon/Operational")
	security := strings.EqualFold(record.provider, "Microsoft-Windows-Security-Auditing") &&
		strings.EqualFold(record.channel, "Security")
	if sysmon {
		fields[event.Service] = "sysmon"
		times = append([]jsonTimestamp{{Value: record.field("UtcTime"), UTC: true}}, times...)
		switch fields["event_id"] {
		case "1":
			fields[event.Category], fields[event.Action] = "process_creation", "process_create"
			putHostText(fields, event.Command, record.field("CommandLine"))
			putHostText(fields, "parent_process", record.field("ParentImage"))
			putHostText(fields, "parent_command", record.field("ParentCommandLine"))
			putJSONInteger(fields, "parent_process_id", record.field("ParentProcessId"), 0, 4294967295)
			putHostText(fields, "parent_process_guid", record.field("ParentProcessGuid"))
		case "3":
			fields[event.Category], fields[event.Action] = "network_connection", "network_connect"
			putJSONIP(fields, event.SourceIP, record.field("SourceIp"))
			putJSONIP(fields, event.DestIP, record.field("DestinationIp"))
			putJSONPort(fields, "src_port", record.field("SourcePort"))
			putJSONPort(fields, "dst_port", record.field("DestinationPort"))
			protocol, _ := record.field("Protocol").(string)
			if strings.EqualFold(protocol, "tcp") || strings.EqualFold(protocol, "udp") {
				fields["protocol"] = strings.ToLower(protocol)
			}
		}
		if fields[event.Action] != "" {
			putHostText(fields, event.Process, record.field("Image"))
			putHostText(fields, event.User, record.field("User"))
			putJSONInteger(fields, "process_id", record.field("ProcessId"), 0, 4294967295)
			putHostText(fields, "process_guid", record.field("ProcessGuid"))
		}
	} else if security {
		fields[event.Service] = "security"
		if fields["event_id"] == "4624" || fields["event_id"] == "4625" {
			fields[event.Category], fields[event.Action], fields[event.Outcome] = "authentication", "login", "failure"
			if fields["event_id"] == "4624" {
				fields[event.Outcome] = "success"
			}
			putHostText(fields, "target_user", record.field("TargetUserName"))
			putHostText(fields, "user_domain", record.field("TargetDomainName"))
			domainValue := record.field("TargetDomainName")
			domainText, domainIsText := domainValue.(string)
			domainMissing := domainValue == nil || domainIsText && (strings.TrimSpace(domainText) == "" || domainText == "-")
			if user := fields["target_user"]; user != "" && (domainMissing || fields["user_domain"] != "") {
				if domain := fields["user_domain"]; domain != "" && !strings.ContainsAny(user, `\@`) {
					user = domain + `\` + user
				}
				putHostText(fields, event.User, user)
			}
			putJSONIP(fields, event.SourceIP, record.field("IpAddress"))
			putJSONPort(fields, "src_port", record.field("IpPort"))
			putJSONInteger(fields, "logon_type", record.field("LogonType"), 0, 65535)
			putHostText(fields, event.AuthBy, record.field("AuthenticationPackageName"))
			putHostText(fields, event.Process, record.field("ProcessName"))
			putHostText(fields, "auth_status", record.field("Status"))
			putHostText(fields, "auth_substatus", record.field("SubStatus"))
		}
	}
	return times
}
