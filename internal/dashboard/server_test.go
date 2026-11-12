package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/forensics"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/scenario"
	"github.com/kenzietann/omamori/internal/store"
	"github.com/kenzietann/omamori/internal/taskrun"
)

func fixture(t *testing.T) (*Server, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "evidence")
	os.Mkdir(root, 0700)
	os.WriteFile(filepath.Join(root, "auth.log"), []byte("Nov 10 08:15:02 host useradd[9]: new user: name=alice, UID=1002\n"), 0600)
	db, err := store.Open(context.Background(), store.Config{DSN: filepath.Join(base, "data.db")})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{DB: db, Root: root, DatabasePath: filepath.Join(base, "data.db"), Provider: taskrun.Config{OutputBase: filepath.Join(base, "out")}}, "127.0.0.1:8765")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); db.Close() })
	return s, root
}
func call(s *Server, method, path string, value any) *httptest.ResponseRecorder {
	var body []byte
	if value != nil {
		body, _ = json.Marshal(value)
	}
	r := httptest.NewRequest(method, "http://"+s.address+path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Authorization", "Bearer "+s.token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://"+s.address)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func readJob(t *testing.T, s *Server, id string) JobView {
	t.Helper()
	w := call(s, "GET", "/api/jobs/"+id, nil)
	var j JobView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &j) != nil {
		t.Fatalf("job: %d %s", w.Code, w.Body)
	}
	return j
}
func waitJob(t *testing.T, s *Server, id string) JobView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		j := readJob(t, s, id)
		if j.State != "preparing" && j.State != "running" {
			return j
		}
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatal("job timed out")
	return JobView{}
}
func prepare(t *testing.T, s *Server, input jobRequest) JobView {
	t.Helper()
	w := call(s, "POST", "/api/jobs", input)
	var j JobView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &j) != nil {
		t.Fatalf("prepare: %d %s", w.Code, w.Body)
	}
	return waitJob(t, s, j.ID)
}
func TestHTTPAccessBoundary(t *testing.T) {
	s, _ := fixture(t)
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		want   int
	}{
		{"missing token", func(r *http.Request) { r.Header.Del("Authorization") }, 401},
		{"wrong token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }, 401},
		{"foreign host", func(r *http.Request) { r.Host = "evil.test:8765" }, 403},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }, 403},
		{"cross site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"remote client", func(r *http.Request) { r.RemoteAddr = "203.0.113.1:1111" }, 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://"+s.address+"/api/runs", nil)
			r.RemoteAddr = "127.0.0.1:2222"
			r.Header.Set("Authorization", "Bearer "+s.token)
			test.change(r)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatalf("got %d", w.Code)
			}
		})
	}
	w := call(s, "GET", "/", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "app.js") || strings.Contains(w.Body.String(), s.token) {
		t.Fatal("static bootstrap leaks token or fails")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("missing browser policy")
	}
	r := httptest.NewRequest("POST", "http://"+s.address+"/api/cases", strings.NewReader(`{"title":"x"}`))
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("Authorization", "Bearer "+s.token)
	r.Header.Set("Content-Type", "text/plain")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal("simple cross-site content type accepted")
	}
}
func TestLocalJobConfirmationPersistenceAndEvidence(t *testing.T) {
	s, root := fixture(t)
	before, _ := os.ReadFile(filepath.Join(root, "auth.log"))
	j := prepare(t, s, jobRequest{Kind: "detect", Path: ".", Year: 2026, Zone: "UTC"})
	if j.State != "ready" {
		t.Fatalf("%+v", j)
	}
	runs, _ := s.config.DB.ListRuns(context.Background(), store.Query{})
	if len(runs) != 0 {
		t.Fatal("preview saved a run")
	}
	if _, err := os.Stat(s.config.Provider.OutputBase); !os.IsNotExist(err) {
		t.Fatal("preview wrote output")
	}
	if w := call(s, "POST", "/api/jobs/"+j.ID+"/confirm", map[string]any{}); w.Code != 200 {
		t.Fatal(w.Body)
	}
	if w := call(s, "POST", "/api/jobs/"+j.ID+"/confirm", map[string]any{}); w.Code != 409 {
		t.Fatal("confirmed twice")
	}
	j = waitJob(t, s, j.ID)
	if j.State != "complete" || j.RunID == "" {
		t.Fatalf("%+v", j)
	}
	events := call(s, "GET", "/api/events?run="+j.RunID, nil)
	if events.Code != 200 || !strings.Contains(events.Body.String(), "alice") {
		t.Fatal(events.Body)
	}
	detail := call(s, "GET", "/api/runs/"+j.RunID+"/alerts/a1", nil)
	if detail.Code != 200 {
		t.Fatal(detail.Body)
	}
	event := call(s, "GET", "/api/runs/"+j.RunID+"/events/e1", nil)
	if event.Code != 200 {
		t.Fatal(event.Body)
	}
	c := call(s, "POST", "/api/cases", store.CaseInput{Title: "Review", Status: "open"})
	var caseValue store.Case
	json.Unmarshal(c.Body.Bytes(), &caseValue)
	attached := call(s, "POST", "/api/cases/"+caseValue.ID+"/alerts", store.AlertRef{RunID: j.RunID, AlertID: "a1"})
	if attached.Code != 200 {
		t.Fatal(attached.Body)
	}
	stale := call(s, "PATCH", "/api/cases/"+caseValue.ID, map[string]any{"title": "changed", "notes": "", "status": "closed", "version": 1})
	if stale.Code != 409 {
		t.Fatal("stale update accepted")
	}
	timeline := call(s, "GET", "/api/timeline?case="+caseValue.ID, nil)
	if timeline.Code != 200 || !strings.Contains(timeline.Body.String(), "alice") {
		t.Fatal(timeline.Body)
	}
	after, _ := os.ReadFile(filepath.Join(root, "auth.log"))
	if !bytes.Equal(before, after) {
		t.Fatal("input changed")
	}
}
func TestPathsUnknownFieldsAndCancellation(t *testing.T) {
	s, root := fixture(t)
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(root, "escape"))
	for _, path := range []string{"../", outside, "escape"} {
		j := prepare(t, s, jobRequest{Kind: "detect", Path: path, Year: 2026, Zone: "UTC"})
		if j.State != "failed" {
			t.Fatalf("path accepted %s: %+v", path, j)
		}
	}
	w := call(s, "POST", "/api/jobs", map[string]any{"kind": "detect", "path": ".", "shell": "touch file"})
	if w.Code != 400 {
		t.Fatal("unknown command accepted")
	}
	j := prepare(t, s, jobRequest{Kind: "detect", Path: ".", Year: 2026, Zone: "UTC"})
	call(s, "POST", "/api/jobs/"+j.ID+"/cancel", map[string]any{})
	if w := call(s, "POST", "/api/jobs/"+j.ID+"/confirm", map[string]any{}); w.Code != 409 {
		t.Fatal("cancelled preview executed")
	}
}

type fakeProvider struct {
	mutex    sync.Mutex
	requests int
	block    bool
}

func (p *fakeProvider) Name() string { return "test" }
func (p *fakeProvider) Send(ctx context.Context, safe outbound.SafeRequest) (outbound.Response, error) {
	p.mutex.Lock()
	p.requests++
	p.mutex.Unlock()
	if len(safe.Request().Tools) != 0 {
		return outbound.Response{}, errors.New("tools present")
	}
	if p.block {
		<-ctx.Done()
		return outbound.Response{}, ctx.Err()
	}
	return outbound.Response{Text: `{"claims":[{"kind":"alert","alerts":["a1"],"evidence":["a1_e1"],"count":1}]}`, TokensUsed: 10}, nil
}
func TestAIHasPreviewAndExplicitConfirmation(t *testing.T) {
	s, _ := fixture(t)
	p := &fakeProvider{}
	s.config.Provider.LookupEnv = func(string) string { return "test-key" }
	s.config.Provider.NewProvider = func(_, _, _, _ string) (outbound.Provider, error) { return p, nil }
	j := prepare(t, s, jobRequest{Kind: "analyze", Path: ".", Year: 2026, Zone: "UTC", Provider: "openai", Model: "test"})
	if j.State != "ready" || p.requests != 0 || !strings.Contains(j.Preview, "claims") {
		t.Fatalf("preview: %+v", j)
	}
	call(s, "POST", "/api/jobs/"+j.ID+"/confirm", map[string]any{})
	j = waitJob(t, s, j.ID)
	p.mutex.Lock()
	calls := p.requests
	p.mutex.Unlock()
	if calls != 1 || j.State != "complete" || j.RunID == "" {
		t.Fatalf("AI run: %+v calls %d", j, calls)
	}
}

func TestCancelledAIRequestStopsAndShutdownCompletes(t *testing.T) {
	s, _ := fixture(t)
	p := &fakeProvider{block: true}
	s.config.Provider.LookupEnv = func(string) string { return "test-key" }
	s.config.Provider.NewProvider = func(_, _, _, _ string) (outbound.Provider, error) { return p, nil }
	j := prepare(t, s, jobRequest{Kind: "analyze", Path: ".", Year: 2026, Zone: "UTC", Provider: "openai", Model: "test"})
	call(s, "POST", "/api/jobs/"+j.ID+"/confirm", map[string]any{})
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mutex.Lock()
		calls := p.requests
		p.mutex.Unlock()
		if calls > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("provider did not start")
		}
		time.Sleep(time.Millisecond)
	}
	call(s, "POST", "/api/jobs/"+j.ID+"/cancel", map[string]any{})
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not stop the provider")
	}
	if j := readJob(t, s, j.ID); j.State != "cancelled" {
		t.Fatalf("%+v", j)
	}
}
func TestExpiredPreviewDoesNotBlockNewWork(t *testing.T) {
	s, _ := fixture(t)
	j := prepare(t, s, jobRequest{Kind: "detect", Path: ".", Year: 2026, Zone: "UTC"})
	s.mutex.Lock()
	s.jobs[j.ID].cancel()
	s.mutex.Unlock()
	if got := readJob(t, s, j.ID); got.State != "cancelled" || got.Preview != "" {
		t.Fatal("expired evidence retained")
	}
	next := prepare(t, s, jobRequest{Kind: "detect", Path: ".", Year: 2026, Zone: "UTC"})
	if next.State != "ready" {
		t.Fatalf("%+v", next)
	}
}
func TestLocalPreviewRedactsRuleMetadata(t *testing.T) {
	s, root := fixture(t)
	folder := filepath.Join(root, "rules")
	os.Mkdir(folder, 0700)
	const secret = "AKIAIOSFODNN7EXAMPLE"
	os.WriteFile(filepath.Join(folder, "r.yml"), []byte("title: "+secret+"\nname: r\nlevel: low\ndetection:\n  s: {action: user_created}\n  condition: s\n"), 0600)
	j := prepare(t, s, jobRequest{Kind: "detect", Path: "auth.log", Rules: "rules", Year: 2026, Zone: "UTC"})
	if j.State != "ready" || strings.Contains(j.Preview, secret) {
		t.Fatal("unsafe local preview")
	}
	call(s, "POST", "/api/jobs/"+j.ID+"/confirm", map[string]any{})
	j = waitJob(t, s, j.ID)
	if j.State != "complete" {
		t.Fatalf("%+v", j)
	}
	for _, name := range []string{"report.md", "report.html", "alerts.json"} {
		text, err := os.ReadFile(filepath.Join(j.SavedTo, name))
		if err != nil || strings.Contains(string(text), secret) {
			t.Fatalf("unsafe %s: %v", name, err)
		}
	}
}

func TestForensicJobKeepsVerifiableManifest(t *testing.T) {
	s, root := fixture(t)
	folder := filepath.Join(root, "host")
	if err := scenario.WriteHost(folder, scenario.GenerateHost(3, time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC), true)); err != nil {
		t.Fatal(err)
	}
	j := prepare(t, s, jobRequest{Kind: "forensics", Path: "host/root", Processes: "host/snapshots/ps.txt", Sockets: "host/snapshots/ss.txt", Year: 2026, Zone: "UTC"})
	if j.State != "ready" {
		t.Fatalf("%+v", j)
	}
	call(s, "POST", "/api/jobs/"+j.ID+"/confirm", map[string]any{})
	j = waitJob(t, s, j.ID)
	if j.State != "complete" {
		t.Fatalf("%+v", j)
	}
	manifest, err := os.ReadFile(filepath.Join(j.SavedTo, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	differences, _, err := forensics.Verify(filepath.Join(folder, "root"), manifest)
	if err != nil || len(differences) != 2 {
		t.Fatalf("manifest: %v %v", differences, err)
	}
	for _, difference := range differences {
		if !difference.NotChecked || !strings.HasPrefix(difference.Path, "snapshot:") {
			t.Fatalf("artifact changed: %#v", difference)
		}
	}
	run, err := s.config.DB.GetRun(context.Background(), j.RunID)
	if err != nil || run.Mode != "forensics" || run.AlertCount < 20 {
		t.Fatalf("stored forensic run: %#v %v", run, err)
	}
}
