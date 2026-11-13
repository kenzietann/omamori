package intake

import (
	"strings"
	"testing"
	"time"
)

func TestGroupAddsAndSSHPenaltiesAreRead(t *testing.T) {
	testCases := []struct {
		name string
		line string
		want map[string]string
		not  []string
	}{
		{"usermod into sudo", "2026-11-12T14:00:35.320008+00:00 web01 usermod[61]: add 'support2' to group 'sudo'",
			map[string]string{"action": "group_add", "user": "support2", "group": "sudo"}, []string{"group_file"}},
		{"usermod, the shadow line", "2026-11-12T14:00:35.320019+00:00 web01 usermod[61]: add 'support2' to shadow group 'sudo'",
			map[string]string{"action": "group_add", "user": "support2", "group": "sudo", "group_file": "gshadow"}, nil},
		{"gpasswd into wheel", "Nov 12 14:00:35 web01 gpasswd[70]: user deploy added by root to group wheel",
			map[string]string{"action": "group_add", "user": "deploy", "group": "wheel"}, []string{"group_file"}},
		{"sshd penalty drop", "2026-11-12T14:00:35.209069+00:00 web01 sshd[13]: drop connection #0 from [172.21.0.3]:41440 on [172.21.0.2]:22 penalty: failed authentication",
			map[string]string{"service": "sshd", "action": "connection_dropped", "outcome": "failure", "src_ip": "172.21.0.3", "reason": "failed authentication"}, nil},
		{"sshd penalty drop over IPv6", "Nov 12 14:00:35 web01 sshd[13]: drop connection #3 from [2001:db8::7]:41440 on [2001:db8::1]:22 penalty: exceeded LoginGraceTime",
			map[string]string{"action": "connection_dropped", "src_ip": "2001:db8::7", "reason": "exceeded LoginGraceTime"}, nil},
		{"a drop with a broken address is not a drop", "Nov 12 14:00:35 web01 sshd[13]: drop connection #0 from [not-an-ip]:1 on [172.21.0.2]:22 penalty: failed authentication",
			map[string]string{"service": "sshd"}, []string{"action", "src_ip"}},
		{"usermod removing from a group", "Nov 12 14:00:35 web01 usermod[61]: delete 'support2' from group 'sudo'",
			map[string]string{"service": "usermod"}, []string{"action", "group"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			events, _, err := Parse(strings.NewReader(testCase.line+"\n"), "auth.log", Options{Year: 2026, Location: time.UTC})
			if err != nil || len(events) != 1 {
				t.Fatalf("%d events, %v", len(events), err)
			}
			fields := events[0].Fields
			for name, value := range testCase.want {
				if fields[name] != value {
					t.Errorf("%s = %q, want %q (fields %v)", name, fields[name], value, fields)
				}
			}
			for _, name := range testCase.not {
				if _, found := fields[name]; found {
					t.Errorf("%s should not be set: %v", name, fields)
				}
			}
		})
	}
}
