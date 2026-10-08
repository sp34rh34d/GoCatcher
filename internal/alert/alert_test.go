package alert

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"/collect": "XSS", "/ssti-oob": "SSTI", "/xxe-oob": "XXE",
		"/ssrf-hit": "SSRF", "/c/abc": "CALLBACK", "/nothing": "",
	}
	for path, want := range cases {
		if got := classify(path); got != want {
			t.Errorf("classify(%q)=%q want %q", path, got, want)
		}
	}
}

func TestToken(t *testing.T) {
	if got := token("/c/XYZ", ""); got != "XYZ" {
		t.Errorf("path token got %q", got)
	}
	if got := token("/x", "t=tok9&a=1"); got != "tok9" {
		t.Errorf("query token got %q", got)
	}
}

func TestDecode(t *testing.T) {
	b := base64.StdEncoding.EncodeToString([]byte(`{"cookie":"S=1"}`))
	pretty, _ := decode("b=" + b)
	if !strings.Contains(pretty, "cookie") {
		t.Fatalf("decode missing cookie: %q", pretty)
	}
}
