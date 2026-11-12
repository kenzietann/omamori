package event

import (
	"sort"
	"strings"
	"time"
)

const (
	Action     = "action"
	Outcome    = "outcome"
	User       = "user"
	SourceIP   = "src_ip"
	DestIP     = "dst_ip"
	Host       = "host"
	Process    = "process"
	Command    = "command"
	URL        = "url"
	Method     = "method"
	Status     = "status"
	Bytes      = "bytes"
	UserAgent  = "user_agent"
	Referrer   = "referrer"
	Message    = "message"
	Signature  = "signature"
	Service    = "service"
	Category   = "category"
	Product    = "product"
	AuthBy     = "auth_method"
	Collector  = "collector"
	EventID    = "event_id"
	SourcePort = "src_port"
	DestPort   = "dst_port"
	Protocol   = "protocol"
)

type Event struct {
	Time   time.Time
	Source string
	Ref    string
	Fields map[string]string
}

func (event Event) Get(name string) (string, bool) {
	value, found := event.Fields[Canonical(name)]

	return value, found
}

var aliases = map[string]string{
	"c-ip": SourceIP, "sourceip": SourceIP, "source_ip": SourceIP, "src": SourceIP, "clientip": SourceIP, "remote_addr": SourceIP,
	"destinationip": DestIP, "dest_ip": DestIP, "dst": DestIP,
	"sc-status": Status, "cs-method": Method, "cs-user-agent": UserAgent, "cs-referer": Referrer,
	"cs-uri": URL, "cs-uri-query": URL, "cs-uri-stem": URL, "c-uri": URL, "request": URL,
	"cs-username": User, "username": User, "targetusername": User,
	"commandline": Command, "image": Process, "computername": Host, "hostname": Host,
	"eventid": EventID, "sourceport": SourcePort, "destinationport": DestPort,
}

func Canonical(name string) string {
	if alias, found := aliases[strings.ToLower(name)]; found {
		return alias
	}

	return name
}

func Sort(events []Event) {
	sort.SliceStable(events, func(first, second int) bool { return events[first].Time.Before(events[second].Time) })
}
