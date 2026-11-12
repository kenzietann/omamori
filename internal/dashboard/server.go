// Package dashboard provides a loopback-only HTTP adapter over Omamori's shared services.
package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/pathguard"
	"github.com/kenzietann/omamori/internal/store"
	"github.com/kenzietann/omamori/internal/taskrun"
)

//go:embed assets/*
var assets embed.FS

var ErrConfig = errors.New("the dashboard configuration is not valid")

type Config struct {
	DB                                              *store.DB
	Root                                            string
	DatabasePath                                    string
	Provider                                        taskrun.Config
	DefaultProvider, DefaultModel, DefaultReasoning string
}
type Server struct {
	config         Config
	root           *pathguard.Root
	address, token string
	mux            *http.ServeMux
	ctx            context.Context
	cancel         context.CancelFunc
	workers        sync.WaitGroup
	mutex          sync.Mutex
	jobs           map[string]*job
	order          []string
	closed         bool
}

func randomID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("system randomness unavailable")
	}
	return hex.EncodeToString(b[:])
}
func New(config Config, address string) (*Server, error) {
	host, port, err := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	if err != nil || host != "127.0.0.1" || portErr != nil || number < 1 || number > 65535 || config.DB == nil || config.Provider.OutputBase == "" {
		return nil, ErrConfig
	}
	root, err := pathguard.NewRoot(config.Root)
	if err != nil {
		return nil, ErrConfig
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{config: config, root: root, address: address, token: randomID(), mux: http.NewServeMux(), ctx: ctx, cancel: cancel, jobs: map[string]*job{}}
	s.routes()
	return s, nil
}

// URL carries the token in the fragment, which is never sent in an HTTP request or referrer.
func (s *Server) URL() string { return "http://" + s.address + "/#token=" + s.token }
func (s *Server) Close() {
	s.mutex.Lock()
	s.closed = true
	s.cancel()
	for _, j := range s.jobs {
		if j.cancel != nil {
			j.cancel()
		}
	}
	s.mutex.Unlock()
	s.workers.Wait()
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if r.Host != s.address {
		http.Error(w, "host refused", http.StatusForbidden)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		http.Error(w, "loopback access only", http.StatusForbidden)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+s.address {
		http.Error(w, "origin refused", http.StatusForbidden)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(auth), []byte(s.token)) != 1 {
			http.Error(w, "open the dashboard link printed in your terminal", http.StatusUnauthorized)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	s.mux.ServeHTTP(w, r.WithContext(ctx))
}
func (s *Server) routes() {
	static, _ := fs.Sub(assets, "assets")
	s.mux.Handle("GET /", http.FileServer(http.FS(static)))
	s.mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		providers := []map[string]any{}
		for _, p := range outbound.Providers() {
			providers = append(providers, map[string]any{"id": p.ID, "name": p.Name, "local": p.Local, "configured": p.Local, "model": p.DefaultModel})
		}
		respond(w, map[string]any{"root": s.config.Root, "providers": providers, "provider": s.config.DefaultProvider, "model": s.config.DefaultModel, "reasoning": s.config.DefaultReasoning})
	})
	s.mux.HandleFunc("GET /api/runs", s.runs)
	s.mux.HandleFunc("GET /api/runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		value, err := s.config.DB.GetRun(r.Context(), r.PathValue("id"))
		reply(w, value, err)
	})
	s.mux.HandleFunc("GET /api/runs/{run}/events/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.config.DB.GetEvent(r.Context(), r.PathValue("run"), r.PathValue("id"))
		reply(w, v, e)
	})
	s.mux.HandleFunc("GET /api/runs/{run}/alerts/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.config.DB.GetAlert(r.Context(), r.PathValue("run"), r.PathValue("id"))
		reply(w, v, e)
	})
	s.mux.HandleFunc("GET /api/events", s.events)
	s.mux.HandleFunc("GET /api/alerts", s.alerts)
	s.mux.HandleFunc("GET /api/timeline", s.timeline)
	s.mux.HandleFunc("GET /api/cases", s.cases)
	s.mux.HandleFunc("GET /api/cases/{id}", func(w http.ResponseWriter, r *http.Request) {
		value, err := s.config.DB.GetCase(r.Context(), r.PathValue("id"))
		reply(w, value, err)
	})
	s.mux.HandleFunc("POST /api/cases", func(w http.ResponseWriter, r *http.Request) {
		var input store.CaseInput
		if !decode(w, r, &input) {
			return
		}
		value, err := s.config.DB.CreateCase(r.Context(), input)
		reply(w, value, err)
	})
	s.mux.HandleFunc("PATCH /api/cases/{id}", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Title   string `json:"title"`
			Notes   string `json:"notes"`
			Status  string `json:"status"`
			Version int    `json:"version"`
		}
		if !decode(w, r, &input) {
			return
		}
		value, err := s.config.DB.UpdateCase(r.Context(), r.PathValue("id"), input.Version, store.CaseInput{Title: input.Title, Notes: input.Notes, Status: input.Status})
		reply(w, value, err)
	})
	for _, method := range []string{"POST", "DELETE"} {
		s.mux.HandleFunc(method+" /api/cases/{id}/alerts", func(w http.ResponseWriter, r *http.Request) {
			var input store.AlertRef
			if !decode(w, r, &input) {
				return
			}
			var err error
			if r.Method == "POST" {
				err = s.config.DB.AddCaseAlert(r.Context(), r.PathValue("id"), input.RunID, input.AlertID)
			} else {
				err = s.config.DB.RemoveCaseAlert(r.Context(), r.PathValue("id"), input.RunID, input.AlertID)
			}
			if err != nil {
				reply(w, nil, err)
				return
			}
			value, err := s.config.DB.GetCase(r.Context(), r.PathValue("id"))
			reply(w, value, err)
		})
	}
	s.mux.HandleFunc("GET /api/jobs", s.listJobs)
	s.mux.HandleFunc("POST /api/jobs", s.prepareJob)
	s.mux.HandleFunc("GET /api/jobs/{id}", s.getJob)
	s.mux.HandleFunc("POST /api/jobs/{id}/confirm", s.confirmJob)
	s.mux.HandleFunc("POST /api/jobs/{id}/cancel", s.cancelJob)
}
func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		http.Error(w, "invalid JSON request", 400)
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		http.Error(w, "one JSON object is required", 400)
		return false
	}
	return true
}
func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(value)
}
func reply(w http.ResponseWriter, value any, err error) {
	if err == nil {
		respond(w, value)
		return
	}
	status := 500
	message := "operation failed; check the input and configuration"
	switch {
	case errors.Is(err, store.ErrInvalid):
		status = 400
		message = "invalid record or filter"
	case errors.Is(err, store.ErrNotFound):
		status = 404
		message = "record not found"
	case errors.Is(err, store.ErrConflict):
		status = 409
		message = "this record changed; reload before editing"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status = 408
		message = "operation cancelled or timed out"
	}
	http.Error(w, message, status)
}
func query(r *http.Request) (store.Query, error) {
	v := r.URL.Query()
	q := store.Query{RunID: v.Get("run"), CaseID: v.Get("case"), Text: v.Get("text"), Source: v.Get("source"), Level: v.Get("level"), Rule: v.Get("rule"), Field: v.Get("field"), Value: v.Get("value"), Status: v.Get("status"), Limit: 50}
	var err error
	if v.Has("limit") {
		q.Limit, err = strconv.Atoi(v.Get("limit"))
		if err != nil || q.Limit < 1 || q.Limit > 200 {
			return q, store.ErrInvalid
		}
	}
	if v.Has("offset") {
		q.Offset, err = strconv.Atoi(v.Get("offset"))
		if err != nil {
			return q, store.ErrInvalid
		}
	}
	if v.Get("from") != "" {
		q.From, err = time.Parse(time.RFC3339Nano, v.Get("from"))
		if err != nil {
			return q, store.ErrInvalid
		}
	}
	if v.Get("to") != "" {
		q.To, err = time.Parse(time.RFC3339Nano, v.Get("to"))
		if err != nil {
			return q, store.ErrInvalid
		}
	}
	return q, nil
}
func (s *Server) runs(w http.ResponseWriter, r *http.Request) {
	q, e := query(r)
	if e != nil {
		reply(w, nil, e)
		return
	}
	v, e := s.config.DB.ListRuns(r.Context(), q)
	reply(w, v, e)
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q, e := query(r)
	if e != nil {
		reply(w, nil, e)
		return
	}
	v, e := s.config.DB.SearchEvents(r.Context(), q)
	reply(w, v, e)
}
func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	q, e := query(r)
	if e != nil {
		reply(w, nil, e)
		return
	}
	v, e := s.config.DB.SearchAlerts(r.Context(), q)
	reply(w, v, e)
}
func (s *Server) timeline(w http.ResponseWriter, r *http.Request) {
	q, e := query(r)
	if e != nil {
		reply(w, nil, e)
		return
	}
	v, e := s.config.DB.Timeline(r.Context(), q)
	reply(w, v, e)
}
func (s *Server) cases(w http.ResponseWriter, r *http.Request) {
	q, e := query(r)
	if e != nil {
		reply(w, nil, e)
		return
	}
	v, e := s.config.DB.ListCases(r.Context(), q)
	reply(w, v, e)
}
