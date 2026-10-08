// Package routes holds the custom-route store and its INI persistence.
// It is the Go port of the custom_routes handling in GoCatcher.py.
package routes

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"gocatcher/internal/ui"
)

// Route is a single registered custom route.
type Route struct {
	Path    string            // URL path (without leading slash)
	File    string            // backing file served for this path
	Headers map[string]string // extra response headers
}

// Store maps a route id (uuid string) to its Route.
type Store map[string]Route

// List prints the routes as an aligned table (mirrors tabulate output).
func (s Store) List() {
	if len(s) == 0 {
		ui.Info("no custom route yet")
		return
	}

	ids := make([]string, 0, len(s))
	for id := range s {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rows := [][]string{{"Route id", "Path", "File", "Headers"}}
	for _, id := range ids {
		r := s[id]
		rows = append(rows, []string{id, r.Path, r.File, formatHeaders(r.Headers)})
	}

	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	printRow := func(row []string) {
		parts := make([]string, len(row))
		for i, cell := range row {
			parts[i] = fmt.Sprintf("%-*s", widths[i], cell)
		}
		fmt.Println(strings.TrimRight(strings.Join(parts, "  "), " "))
	}

	printRow(rows[0])
	sep := make([]string, len(widths))
	for i, w := range widths {
		sep[i] = strings.Repeat("-", w)
	}
	printRow(sep)
	for _, row := range rows[1:] {
		printRow(row)
	}
}

func formatHeaders(h map[string]string) string {
	if len(h) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("'%s': '%s'", k, h[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// Save writes the store to custom_routes.ini in an INI format. Headers are
// serialized as JSON so they round-trip cleanly on Load.
func (s Store) Save() error {
	if len(s) == 0 {
		ui.Info("no custom route yet!")
	}

	ids := make([]string, 0, len(s))
	for id := range s {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var b strings.Builder
	for _, id := range ids {
		r := s[id]
		hdr, _ := json.Marshal(r.Headers)
		fmt.Fprintf(&b, "[%s]\n", id)
		fmt.Fprintf(&b, "path = %s\n", r.Path)
		fmt.Fprintf(&b, "file = %s\n", r.File)
		fmt.Fprintf(&b, "headers = %s\n\n", string(hdr))
	}

	if err := os.WriteFile("custom_routes.ini", []byte(b.String()), 0o644); err != nil {
		return err
	}
	ui.Info("custom_routes.ini created successfully")
	return nil
}

// Load reads custom_routes.ini into the store (replacing existing entries that
// share an id). Returns false if the file does not exist.
func (s Store) Load() bool {
	f, err := os.Open("custom_routes.ini")
	if err != nil {
		ui.Error("file custom_routes.ini not found!")
		return false
	}
	defer f.Close()

	var section string
	cur := Route{}
	flush := func() {
		if section != "" {
			s[section] = cur
		}
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			section = strings.TrimSpace(line[1 : len(line)-1])
			cur = Route{Headers: map[string]string{}}
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "path":
			cur.Path = val
		case "file":
			cur.File = val
		case "headers":
			m := map[string]string{}
			_ = json.Unmarshal([]byte(val), &m)
			cur.Headers = m
		}
	}
	flush()

	ui.Info("custom_routes.ini loaded successfully")
	return true
}
