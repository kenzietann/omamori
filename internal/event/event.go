// Package event is the common shape of a log event. Every parser turns its lines into these, and the rule
// engine reads only these, so a rule does not care if an event came from sshd, a web server or Suricata.
//
// The field names are the same everywhere (action, outcome, user, src_ip, ...), as in the Elastic Common Schema
// but flat and short. A parser fills the fields it knows and leaves the others out.
package event

import (
	"sort"
	"strings"
	"time"
)

// Field names that parsers and rules share.
const (
	Action    = "action"
	Outcome   = "outcome"
	User      = "user"
	SourceIP  = "src_ip"
	DestIP    = "dst_ip"
	Host      = "host"
	Process   = "process"
	Command   = "command"
	URL       = "url"
	Method    = "method"
	Status    = "status"
	Bytes     = "bytes"
	UserAgent = "user_agent"
	Referrer  = "referrer"
	Message   = "message"
	Signature = "signature"
	Service   = "service"
	Category  = "category"
	Product   = "product"
	AuthBy    = "auth_method"
)

// Event is one thing that happened. Ref says where it came from, for example "auth.log:12".
type Event struct {
	Time   time.Time
	Source string
	Ref    string
	Fields map[string]string
}

// Get returns a field and whether the event has it. The name can be a name that Sigma rules use.
func (event Event) Get(name string) (string, bool) {
	value, found := event.Fields[Canonical(name)]

	return value, found
}

// aliases maps the field names of shared Sigma rules to the names of this package. Keys are lower case.
var aliases = map[string]string{
	"c-ip": SourceIP, "sourceip": SourceIP, "source_ip": SourceIP, "src": SourceIP, "clientip": SourceIP, "remote_addr": SourceIP,
	"destinationip": DestIP, "dest_ip": DestIP, "dst": DestIP,
	"sc-status": Status, "cs-method": Method, "cs-user-agent": UserAgent, "cs-referer": Referrer,
	"cs-uri": URL, "cs-uri-query": URL, "cs-uri-stem": URL, "c-uri": URL, "request": URL,
	"cs-username": User, "username": User, "targetusername": User,
	"commandline": Command, "image": Process, "computername": Host, "hostname": Host,
}

// Canonical gives the name under which a field is kept.
func Canonical(name string) string {
	if alias, found := aliases[strings.ToLower(name)]; found {
		return alias
	}

	return name
}

// Sort puts events in the order of time. Events with the same time keep their order.
func Sort(events []Event) {
	sort.SliceStable(events, func(first, second int) bool { return events[first].Time.Before(events[second].Time) })
}
