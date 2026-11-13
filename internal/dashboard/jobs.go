package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kenzietann/omamori/internal/analysisrun"
	"github.com/kenzietann/omamori/internal/detect"
	"github.com/kenzietann/omamori/internal/filerules"
	"github.com/kenzietann/omamori/internal/forensics"
	"github.com/kenzietann/omamori/internal/htmlreport"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/rules"
	"github.com/kenzietann/omamori/internal/runstore"
	"github.com/kenzietann/omamori/internal/sanitizer"
	"github.com/kenzietann/omamori/internal/taskrun"
)

type JobView struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	State    string   `json:"state"`
	Message  string   `json:"message"`
	Preview  string   `json:"preview,omitempty"`
	Consent  string   `json:"consent,omitempty"`
	RunID    string   `json:"run_id,omitempty"`
	SavedTo  string   `json:"saved_to,omitempty"`
	Progress []string `json:"progress"`
}
type job struct {
	view   JobView
	ctx    context.Context
	cancel context.CancelFunc
	run    func(context.Context, func(string)) (string, string, bool, error)
	busy   bool
}
type jobRequest struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	Rules     string `json:"rules"`
	Year      int    `json:"year"`
	Zone      string `json:"timezone"`
	Format    string `json:"format"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	Reasoning string `json:"reasoning"`
	Processes string `json:"processes"`
	Sockets   string `json:"sockets"`
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.expireLocked()
	result := []JobView{}
	for i := len(s.order) - 1; i >= 0; i-- {
		result = append(result, s.jobs[s.order[i]].view)
	}
	respond(w, result)
}
func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.expireLocked()
	j := s.jobs[r.PathValue("id")]
	if j == nil {
		http.Error(w, "job not found", 404)
		return
	}
	respond(w, j.view)
}
func (s *Server) prepareJob(w http.ResponseWriter, r *http.Request) {
	var input jobRequest
	if !decode(w, r, &input) {
		return
	}
	if input.Kind != "detect" && input.Kind != "analyze" && input.Kind != "forensics" && input.Kind != "forensics-analyze" {
		http.Error(w, "unknown run type", 400)
		return
	}
	if input.Path == "" {
		http.Error(w, "choose a path relative to the evidence root", 400)
		return
	}
	if input.Year == 0 {
		input.Year = time.Now().Year()
	}
	if input.Year < 1970 || input.Year > 2200 {
		http.Error(w, "invalid year", 400)
		return
	}
	if input.Zone == "" {
		input.Zone = "UTC"
	}
	if _, err := time.LoadLocation(input.Zone); err != nil {
		http.Error(w, "unknown time zone", 400)
		return
	}
	if input.Format != "" && input.Format != "syslog" && input.Format != "web" && input.Format != "json" && input.Format != "suricata" && input.Format != "zeek" && input.Format != "wazuh" && input.Format != "windows" {
		http.Error(w, "unknown log format", 400)
		return
	}
	s.mutex.Lock()
	s.expireLocked()
	if s.closed {
		s.mutex.Unlock()
		http.Error(w, "dashboard is shutting down", 503)
		return
	}
	for _, j := range s.jobs {
		if j.busy || j.view.State == "ready" {
			s.mutex.Unlock()
			http.Error(w, "a run is active or still stopping; wait for it before preparing another", 409)
			return
		}
	}
	if len(s.order) >= 20 {
		delete(s.jobs, s.order[0])
		s.order = s.order[1:]
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Minute)
	j := &job{view: JobView{ID: randomID()[:24], Kind: input.Kind, State: "preparing", Message: "Reading the selected evidence", Progress: []string{}}, ctx: ctx, cancel: cancel, busy: true}
	s.jobs[j.view.ID] = j
	s.order = append(s.order, j.view.ID)
	s.workers.Add(1)
	respond(w, j.view)
	s.mutex.Unlock()
	go func() {
		defer s.workers.Done()
		run, preview, consent, err := s.prepare(ctx, j.view.ID, input)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		j.busy = false
		if ctx.Err() != nil {
			j.view.State = "cancelled"
			j.view.Message = "Run cancelled or expired"
			j.cancel()
			return
		}
		if err != nil {
			j.view.State = "failed"
			j.view.Message = s.prepareError(err)
			j.cancel()
			return
		}
		j.run = run
		j.view.Preview = preview
		j.view.Consent = consent
		j.view.State = "ready"
		j.view.Message = "Review the preview before confirming"
	}()
}
func (s *Server) prepareError(err error) string {
	switch {
	case errors.Is(err, taskrun.ErrNeedsKey):
		return "The selected provider has no configured key. Set its environment variable or use the CLI key setup."
	case errors.Is(err, taskrun.ErrNeedsModel):
		return "Choose a model for this provider."
	case errors.Is(err, taskrun.ErrReasoning):
		return "The reasoning level is not supported by this model."
	case errors.Is(err, pathguard.ErrOutsideRoot), errors.Is(err, pathguard.ErrInvalidPath):
		return "The selected path is outside the approved evidence root or cannot be read."
	case errors.Is(err, pathguard.ErrFoldersOverlap):
		return "Output and database files must stay outside the selected evidence."
	default:
		return "Could not prepare this run. Check the selected path, log format, rules and provider settings."
	}
}
func (s *Server) prepare(ctx context.Context, id string, input jobRequest) (func(context.Context, func(string)) (string, string, bool, error), string, string, error) {
	fail := func(err error) (func(context.Context, func(string)) (string, string, bool, error), string, string, error) {
		return nil, "", "", err
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	target, err := s.root.Resolve(input.Path)
	if err != nil {
		return fail(err)
	}
	output := filepath.Join(s.config.Provider.OutputBase, "dashboard-"+id)
	if err := pathguard.CheckOutputFolder(target, output); err != nil {
		return fail(err)
	}
	if s.config.DatabasePath != "" {
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if err := pathguard.CheckOutputFolder(target, s.config.DatabasePath+suffix); err != nil {
				return fail(err)
			}
		}
	}
	location, _ := time.LoadLocation(input.Zone)
	isForensic := input.Kind == "forensics" || input.Kind == "forensics-analyze"
	if !isForensic && (input.Processes != "" || input.Sockets != "") {
		return fail(errors.New("snapshots require forensic triage"))
	}
	sources := []string{target}
	options := forensics.Options{Year: input.Year, Location: location}
	for _, snapshot := range []struct {
		path        string
		destination *string
	}{{input.Processes, &options.Processes}, {input.Sockets, &options.Sockets}} {
		if snapshot.path == "" {
			continue
		}
		resolved, err := s.root.Resolve(snapshot.path)
		if err != nil {
			return fail(err)
		}
		if err := pathguard.CheckOutputFolder(resolved, output); err != nil {
			return fail(err)
		}
		if s.config.DatabasePath != "" {
			for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
				if err := pathguard.CheckOutputFolder(resolved, s.config.DatabasePath+suffix); err != nil {
					return fail(err)
				}
			}
		}
		*snapshot.destination = resolved
		sources = append(sources, resolved)
	}
	set, err := rules.Builtin()
	if isForensic {
		set, err = rules.BuiltinForensics()
	}
	from := "built-in"
	if input.Rules != "" {
		path, resolveErr := s.root.Resolve(input.Rules)
		if resolveErr != nil {
			return fail(resolveErr)
		}
		set, err = rules.Load(path)
		from = "custom folder"
	}
	if err != nil || len(set.Rules()) == 0 {
		return fail(errors.New("invalid rules"))
	}
	now := time.Now()
	if s.config.Provider.Now != nil {
		now = s.config.Provider.Now()
	}
	base := analysisrun.Base{}
	var outcome detect.Outcome
	if isForensic {
		files, fileErr := filerules.Builtin()
		if fileErr != nil {
			return fail(fileErr)
		}
		options.FileRules = &files
		result, readErr := forensics.Run(target, set, from, options, now)
		if readErr != nil {
			return fail(readErr)
		}
		outcome = result.Outcome
		base = analysisrun.Base{Report: forensics.Markdown(result), Prefix: "forensics", Files: map[string]string{"manifest.json": result.ManifestText, "manifest.sha256": result.ManifestSHA256 + "  manifest.json\n"}}
	} else {
		outcome, err = detect.RunContext(ctx, []string{target}, set, from, intake.Options{Year: input.Year, Location: location, Format: input.Format}, now)
		if err != nil {
			return fail(err)
		}
		if len(outcome.Intake.Files) == 0 {
			return fail(errors.New("no logs"))
		}
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	if input.Kind == "analyze" || input.Kind == "forensics-analyze" {
		config := s.config.Provider
		config.Target = target
		if info, err := os.Stat(target); err == nil && !info.IsDir() {
			config.Target = filepath.Dir(target)
		}
		config.OutputBase = output
		session, err := analysisrun.Prepare(ctx, analysisrun.Config{Provider: config, Sources: sources, Store: s.config.DB, Base: base}, outcome, taskrun.Setup{ProviderID: input.Provider, Model: input.Model, Reasoning: input.Reasoning})
		if err != nil {
			return fail(err)
		}
		request, err := session.Preview()
		if err != nil {
			return fail(err)
		}
		encoded, err := json.MarshalIndent(request, "", "  ")
		if err != nil {
			return fail(err)
		}
		return func(ctx context.Context, progress func(string)) (string, string, bool, error) {
			session.Confirm()
			result, err := session.Run(ctx, func(p analysisrun.Progress) { progress(p.Message) })
			return result.RunID, result.SavedTo, result.Complete, err
		}, string(encoded), session.ConsentText(), nil
	}
	frozen, err := runstore.Build(outcome, nil)
	if err != nil {
		return fail(err)
	}
	if isForensic {
		frozen.Mode = "forensics"
		frozen.Label = "Local forensic triage"
	}
	report := base.Report
	if report == "" {
		report = detect.Markdown(outcome)
	}
	alerts, err := detect.JSON(outcome)
	if err != nil {
		return fail(err)
	}
	report, _ = (&sanitizer.Sanitizer{}).Sanitize(report)
	alerts, _ = (&sanitizer.Sanitizer{}).Sanitize(alerts)
	if !json.Valid([]byte(alerts)) {
		return fail(errors.New("report sanitization failed"))
	}
	preview := fmt.Sprintf("%d parsed events · %d detected alerts\n\nSave a sanitized run to the configured database and write reports. No AI provider will be contacted.\n\n%s", len(outcome.Intake.Events), len(outcome.Result.Alerts), report)
	return func(ctx context.Context, progress func(string)) (string, string, bool, error) {
		if ctx.Err() != nil {
			return "", "", false, ctx.Err()
		}
		progress("Writing local reports")
		writer, err := reportwriter.NewRun(sources, output)
		if err != nil {
			return "", "", false, err
		}
		files := map[string]string{"report.md": report, "report.html": htmlreport.Render(report), "alerts.json": alerts}
		for name, text := range base.Files {
			files[name] = text
		}
		for name, text := range files {
			if err := writer.Write(name, text); err != nil {
				return "", output, false, err
			}
		}
		progress("Saving sanitized events and alerts")
		saved, err := s.config.DB.SaveRun(ctx, frozen)
		return saved.ID, output, err == nil, err
	}, preview, "Run local analysis and save its sanitized results. No AI provider is used.", nil
}
func (s *Server) confirmJob(w http.ResponseWriter, r *http.Request) {
	s.mutex.Lock()
	j := s.jobs[r.PathValue("id")]
	if j == nil {
		s.mutex.Unlock()
		http.Error(w, "job not found", 404)
		return
	}
	if s.closed || j.view.State != "ready" || j.ctx.Err() != nil {
		s.mutex.Unlock()
		http.Error(w, "this preview is no longer ready", 409)
		return
	}
	j.view.State = "running"
	j.view.Message = "Run confirmed"
	j.view.Preview = ""
	j.busy = true
	run := j.run
	j.run = nil
	s.workers.Add(1)
	respond(w, j.view)
	s.mutex.Unlock()
	go func() {
		defer s.workers.Done()
		ctx, cancel := context.WithTimeout(j.ctx, 5*time.Minute)
		defer cancel()
		progress := func(message string) {
			s.mutex.Lock()
			defer s.mutex.Unlock()
			j.view.Message = message
			j.view.Progress = append(j.view.Progress, message)
			if len(j.view.Progress) > 50 {
				j.view.Progress = j.view.Progress[len(j.view.Progress)-50:]
			}
		}
		id, path, complete, err := run(ctx, progress)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		j.busy = false
		wasCancelled := ctx.Err() != nil
		j.cancel()
		j.view.RunID = id
		j.view.SavedTo = path
		switch {
		case wasCancelled:
			j.view.State = "cancelled"
			j.view.Message = "Run cancelled or timed out"
		case err != nil:
			j.view.State = "failed"
			j.view.Message = "Run failed. Any saved reports are listed below."
		case !complete:
			j.view.State = "incomplete"
			j.view.Message = "Review incomplete; inspect the saved findings and coverage."
		default:
			j.view.State = "complete"
			j.view.Message = "Run complete"
		}
	}()
}
func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	j := s.jobs[r.PathValue("id")]
	if j == nil {
		http.Error(w, "job not found", 404)
		return
	}
	if j.view.State == "preparing" || j.view.State == "ready" || j.view.State == "running" {
		j.cancel()
		j.run = nil
		j.view.Preview = ""
		j.view.State = "cancelled"
		j.view.Message = "Cancellation requested"
	}
	respond(w, j.view)
}

func (s *Server) expireLocked() {
	for _, j := range s.jobs {
		if j.view.State == "ready" && j.ctx.Err() != nil {
			j.run = nil
			j.view.Preview = ""
			j.view.State = "cancelled"
			j.view.Message = "Preview expired; prepare a new run"
			j.cancel()
		}
	}
}
