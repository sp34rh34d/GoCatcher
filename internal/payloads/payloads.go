// Package payloads ships the built-in XSS/CSRF/SSTI/XXE/SSRF test payloads.
// They are embedded into the binary and, on startup, written to routes/ and
// registered as ordinary custom routes (UUID id + on-disk file), so they show
// up in `list` exactly like a user-added route and are available immediately.
//
// FOR AUTHORIZED TESTING / CTF / BUG BOUNTY ONLY.
package payloads

import (
	_ "embed"
	"os"
	"path/filepath"

	"gocatcher/internal/routes"
)

//go:embed assets/xss.js
var xss []byte

//go:embed assets/csrf.html
var csrf []byte

//go:embed assets/ssti.txt
var ssti []byte

//go:embed assets/xxe.xml
var xxe []byte

//go:embed assets/evil.dtd
var evilDTD []byte

//go:embed assets/ssrf.txt
var ssrf []byte

//go:embed assets/lfi.txt
var lfi []byte

//go:embed assets/redirect.txt
var redirect []byte

//go:embed assets/deserialization.txt
var deser []byte

//go:embed assets/log4shell.txt
var log4shell []byte

//go:embed assets/sqli.txt
var sqli []byte

//go:embed assets/prototype.txt
var prototype []byte

// entry is one built-in payload: a stable UUID, the route path, the file it is
// written to, its response headers and the embedded content.
type entry struct {
	id          string
	path        string
	file        string
	contentType string
	data        []byte
}

func builtins() []entry {
	return []entry{
		{"3f1c9a7e-5b2d-4c8a-9e71-0a1b2c3d4e5f", "xss", "routes/xss.bin", "application/javascript", xss},
		{"7a2d4b6c-1e3f-4a5b-8c9d-0e1f2a3b4c5d", "csrf", "routes/csrf.bin", "text/html;++charset=utf-8", csrf},
		{"b9e8d7c6-4a3b-4c2d-9e1f-5a6b7c8d9e0f", "ssti", "routes/ssti.bin", "text/plain;++charset=utf-8", ssti},
		{"c4d5e6f7-8a9b-4c1d-ae2f-3b4c5d6e7f80", "xxe", "routes/xxe.bin", "application/xml", xxe},
		{"d1e2f3a4-b5c6-4d7e-8f90-1a2b3c4d5e6f", "evil.dtd", "routes/evil.dtd.bin", "application/xml-dtd", evilDTD},
		{"e5f6a7b8-c9d0-4e1f-a2b3-c4d5e6f7a8b9", "ssrf", "routes/ssrf.bin", "text/plain;++charset=utf-8", ssrf},
		{"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "lfi", "routes/lfi.bin", "text/plain;++charset=utf-8", lfi},
		{"f0e1d2c3-b4a5-4968-8778-6a5b4c3d2e1f", "redirect", "routes/redirect.bin", "text/plain;++charset=utf-8", redirect},
		{"9a8b7c6d-5e4f-4039-a2b1-c0d9e8f7a6b5", "deser", "routes/deser.bin", "text/plain;++charset=utf-8", deser},
		{"2b3c4d5e-6f70-4812-9394-a5b6c7d8e9f0", "log4shell", "routes/log4shell.bin", "text/plain;++charset=utf-8", log4shell},
		{"6c7d8e9f-0a1b-4c2d-8e3f-4a5b6c7d8e9f", "sqli", "routes/sqli.bin", "text/plain;++charset=utf-8", sqli},
		{"8e9f0a1b-2c3d-4e5f-9a0b-1c2d3e4f5a6b", "pp", "routes/pp.bin", "text/plain;++charset=utf-8", prototype},
	}
}

// Seed extracts the built-in payloads to routes/ (without overwriting an
// existing file) and registers them in the store with a UUID id, unless the
// user already defined that id.
func Seed(store routes.Store) {
	for _, e := range builtins() {
		if _, exists := store[e.id]; exists {
			continue
		}
		if _, err := os.Stat(e.file); err != nil {
			_ = os.MkdirAll(filepath.Dir(e.file), 0o755)
			_ = os.WriteFile(e.file, e.data, 0o644)
		}
		store[e.id] = routes.Route{
			Path:    e.path,
			File:    e.file,
			Headers: map[string]string{"Content-Type": e.contentType},
		}
	}
}
