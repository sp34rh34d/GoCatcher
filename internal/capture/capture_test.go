package capture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAddRingAndFilter(t *testing.T) {
	s := New(3, "")
	for _, p := range []string{"/a", "/b", "/c", "/d"} {
		s.Add(Record{Method: "GET", Path: p})
	}
	if s.Count() != 3 {
		t.Fatalf("ring should cap at 3, got %d", s.Count())
	}
	if all := s.All(); all[len(all)-1].Seq != 4 {
		t.Fatalf("last seq should be 4, got %d", all[len(all)-1].Seq)
	}
	s.Add(Record{Method: "POST", Path: "/login", Alert: "XSS"})
	if got := len(s.Filter(map[string]string{"alert": "xss"})); got != 1 {
		t.Fatalf("filter alert=xss got %d", got)
	}
	if got := len(s.Filter(map[string]string{"method": "GET"})); got == 0 {
		t.Fatalf("filter method=GET got 0")
	}
}

func TestExports(t *testing.T) {
	s := New(10, "")
	s.Add(Record{Method: "GET", Host: "h", Path: "/x", Query: "a=1"})
	dir := t.TempDir()
	for _, f := range []struct {
		name string
		fn   func(string) error
	}{
		{"out.json", s.ExportJSON}, {"out.csv", s.ExportCSV}, {"out.har", s.ExportHAR},
	} {
		p := filepath.Join(dir, f.name)
		if err := f.fn(p); err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		if b, _ := os.ReadFile(p); len(b) == 0 {
			t.Fatalf("%s empty", f.name)
		}
	}
}
