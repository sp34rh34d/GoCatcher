// Package capture records every caught request: it keeps an in-memory ring,
// appends each record to a JSONL file, notifies live subscribers (dashboard),
// and supports filtering and export (JSON / CSV / HAR).
package capture

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Record is a single captured HTTP (or DNS) request.
type Record struct {
	Seq     int               `json:"seq"`
	Time    time.Time         `json:"time"`
	Proto   string            `json:"proto"` // "http", "https", "dns"
	Method  string            `json:"method"`
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Query   string            `json:"query"`
	Remote  string            `json:"remote"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty"`
	Body    string            `json:"body,omitempty"`
	Files   []string          `json:"files,omitempty"`
	Alert   string            `json:"alert,omitempty"` // e.g. "XSS", "SSRF" when a callback matched
	Token   string            `json:"token,omitempty"` // correlation id if present
	Decoded string            `json:"decoded,omitempty"`
}

// Store is the central, concurrency-safe capture sink.
type Store struct {
	mu      sync.RWMutex
	ring    []Record
	max     int
	seq     int
	file    *os.File
	subs    map[int]chan Record
	nextSub int
}

// New creates a Store with an in-memory ring of `max` records. If jsonlPath is
// non-empty, records are also appended there.
func New(max int, jsonlPath string) *Store {
	s := &Store{max: max, subs: map[int]chan Record{}}
	if jsonlPath != "" {
		if f, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			s.file = f
		}
	}
	return s
}

// Add stores a record, assigns its sequence number, persists it and fans it out
// to subscribers. It returns the stored copy (with Seq/Time filled).
func (s *Store) Add(r Record) Record {
	s.mu.Lock()
	s.seq++
	r.Seq = s.seq
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	s.ring = append(s.ring, r)
	if len(s.ring) > s.max {
		s.ring = s.ring[len(s.ring)-s.max:]
	}
	if s.file != nil {
		if b, err := json.Marshal(r); err == nil {
			s.file.Write(append(b, '\n'))
		}
	}
	subs := make([]chan Record, 0, len(s.subs))
	for _, ch := range s.subs {
		subs = append(subs, ch)
	}
	s.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- r:
		default: // drop for slow subscribers
		}
	}
	return r
}

// All returns a copy of the current ring, newest last.
func (s *Store) All() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, len(s.ring))
	copy(out, s.ring)
	return out
}

// Count returns how many records are currently buffered.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ring)
}

// Filter returns records matching every key=substring pair (keys: method, path,
// host, remote, alert, token, proto). An empty filter returns everything.
func (s *Store) Filter(f map[string]string) []Record {
	all := s.All()
	if len(f) == 0 {
		return all
	}
	out := make([]Record, 0, len(all))
	for _, r := range all {
		if recordMatches(r, f) {
			out = append(out, r)
		}
	}
	return out
}

func recordMatches(r Record, f map[string]string) bool {
	for k, v := range f {
		v = strings.ToLower(v)
		var field string
		switch k {
		case "method":
			field = r.Method
		case "path":
			field = r.Path
		case "host":
			field = r.Host
		case "remote":
			field = r.Remote
		case "alert":
			field = r.Alert
		case "token":
			field = r.Token
		case "proto":
			field = r.Proto
		default:
			continue
		}
		if !strings.Contains(strings.ToLower(field), v) {
			return false
		}
	}
	return true
}

// Subscribe registers a live feed channel; the returned func unsubscribes.
func (s *Store) Subscribe() (<-chan Record, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextSub
	s.nextSub++
	ch := make(chan Record, 64)
	s.subs[id] = ch
	return ch, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if c, ok := s.subs[id]; ok {
			close(c)
			delete(s.subs, id)
		}
	}
}

// ExportJSON writes all records as a JSON array.
func (s *Store) ExportJSON(path string) error {
	b, err := json.MarshalIndent(s.All(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ExportCSV writes a flat CSV of the records.
func (s *Store) ExportCSV(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"seq", "time", "proto", "method", "host", "path", "query", "remote", "alert", "token"})
	for _, r := range s.All() {
		w.Write([]string{
			strconv.Itoa(r.Seq), r.Time.Format(time.RFC3339), r.Proto, r.Method,
			r.Host, r.Path, r.Query, r.Remote, r.Alert, r.Token,
		})
	}
	return nil
}

// ExportHAR writes a minimal HAR 1.2 log of the HTTP records.
func (s *Store) ExportHAR(path string) error {
	type nv struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type entry struct {
		Started string `json:"startedDateTime"`
		Time    int    `json:"time"`
		Request struct {
			Method      string `json:"method"`
			URL         string `json:"url"`
			HTTPVersion string `json:"httpVersion"`
			Headers     []nv   `json:"headers"`
			QueryString []nv   `json:"queryString"`
			Cookies     []nv   `json:"cookies"`
			HeadersSize int    `json:"headersSize"`
			BodySize    int    `json:"bodySize"`
		} `json:"request"`
		Response map[string]any `json:"response"`
		Cache    map[string]any `json:"cache"`
		Timings  map[string]any `json:"timings"`
	}
	entries := []entry{}
	for _, r := range s.All() {
		if r.Proto == "dns" {
			continue
		}
		var e entry
		e.Started = r.Time.Format(time.RFC3339)
		e.Request.Method = r.Method
		scheme := r.Proto
		if scheme == "" {
			scheme = "http"
		}
		url := scheme + "://" + r.Host + r.Path
		if r.Query != "" {
			url += "?" + r.Query
		}
		e.Request.URL = url
		e.Request.HTTPVersion = "HTTP/1.1"
		for k, v := range r.Headers {
			e.Request.Headers = append(e.Request.Headers, nv{k, v})
		}
		for k, v := range r.Cookies {
			e.Request.Cookies = append(e.Request.Cookies, nv{k, v})
		}
		e.Request.HeadersSize = -1
		e.Request.BodySize = len(r.Body)
		e.Response = map[string]any{"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
			"headers": []nv{}, "cookies": []nv{}, "content": map[string]any{"size": 0, "mimeType": "text/plain"},
			"redirectURL": "", "headersSize": -1, "bodySize": 0}
		e.Cache = map[string]any{}
		e.Timings = map[string]any{"send": 0, "wait": 0, "receive": 0}
		entries = append(entries, e)
	}
	har := map[string]any{"log": map[string]any{
		"version": "1.2",
		"creator": map[string]any{"name": "GoCatcher", "version": "1.0"},
		"entries": entries,
	}}
	b, err := json.MarshalIndent(har, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Close flushes the JSONL file.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		s.file.Close()
		s.file = nil
	}
}
