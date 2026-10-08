// Package alert classifies incoming requests that look like payload callbacks
// (XSS hooks, blind SSTI/XXE/SSRF beacons), decodes their data, annotates the
// capture record, and fans the event out to notification sinks.
package alert

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"gocatcher/internal/capture"
	"gocatcher/internal/config"
	"gocatcher/internal/notify"
	"gocatcher/internal/ui"
)

// rule maps a path substring to an alert kind.
type rule struct {
	needle string
	kind   string
}

var rules = []rule{
	{"/collect", "XSS"},
	{"/xss", "XSS"},
	{"/ssti-oob", "SSTI"},
	{"/xxe-oob", "XXE"},
	{"/evil.dtd", "XXE"},
	{"/ssrf-hit", "SSRF"},
	{"/ssrf-redir", "SSRF"},
	{"/csrf-hit", "CSRF"},
	{"/lfi", "LFI"},
	{"/rfi", "RFI"},
	{"/redir", "OPEN-REDIRECT"},
	{"/log4", "LOG4SHELL"},
	{"/jndi", "LOG4SHELL"},
	{"/sqli", "SQLI"},
	{"/pp", "PROTOTYPE-POLLUTION"},
	{"/c/", "CALLBACK"},
}

// classify returns the alert kind for a path, or "" if it is not a callback.
func classify(path string) string {
	p := strings.ToLower(path)
	for _, r := range rules {
		if strings.Contains(p, r.needle) {
			return r.kind
		}
	}
	return ""
}

// token pulls a correlation id from /c/<id> or a t=/token= query param.
func token(path, query string) string {
	if i := strings.Index(path, "/c/"); i >= 0 {
		rest := path[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			rest = rest[:j]
		}
		if rest != "" {
			return rest
		}
	}
	if q, err := url.ParseQuery(query); err == nil {
		for _, k := range []string{"t", "token", "id"} {
			if v := q.Get(k); v != "" {
				return v
			}
		}
	}
	return ""
}

// decode unpacks the base64 JSON beacon (the `b` param from the XSS hook) and
// renders it as an indented tree; otherwise it surfaces any `data`/`d` param.
func decode(query string) (string, string) {
	q, err := url.ParseQuery(query)
	if err != nil {
		return "", ""
	}
	if b := q.Get("b"); b != "" {
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			raw, err = base64.URLEncoding.DecodeString(b)
		}
		if err == nil {
			var m map[string]any
			if json.Unmarshal(raw, &m) == nil {
				return prettyMap(m), string(raw)
			}
			return string(raw), string(raw)
		}
	}
	for _, k := range []string{"data", "d", "x"} {
		if v := q.Get(k); v != "" {
			return v, v
		}
	}
	if e := q.Get("err"); e != "" {
		return "error: " + e, e
	}
	return "", ""
}

func prettyMap(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := fmt.Sprintf("%v", m[k])
		if len(v) > 300 {
			v = v[:300] + "…"
		}
		fmt.Fprintf(&b, "%s%s:%s %s\n", ui.Green, k, ui.Reset, v)
	}
	return strings.TrimRight(b.String(), "\n")
}

// Inspect annotates r if it is a callback, prints a highlighted block, and
// dispatches notifications. It returns true when an alert fired.
func Inspect(r *capture.Record, c config.Config) bool {
	kind := classify(r.Path)
	if kind == "" {
		return false
	}
	r.Alert = kind
	r.Token = token(r.Path, r.Query)
	pretty, raw := decode(r.Query)
	r.Decoded = raw

	ui.AlertBanner(kind, r.Remote, r.Path, r.Token, pretty)

	if notify.Configured(c) {
		notify.Dispatch(c, notify.Alert{
			Kind: kind, Title: kind + " callback fired",
			Detail: pretty, Remote: r.Remote, Path: r.Path,
			Token: r.Token, Time: r.Time.Format("2006-01-02 15:04:05"),
		})
	}
	return true
}
