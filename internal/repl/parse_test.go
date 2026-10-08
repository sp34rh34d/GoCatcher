package repl

import "testing"

func TestParseLineFlags(t *testing.T) {
	pa := parseLine([]string{"run", "--port", "9000", "--dashboard", "--dns", "--quiet"})
	if pa.option != "run" || pa.port != "9000" || !pa.dashboard || !pa.dns || !pa.quiet {
		t.Fatalf("unexpected parse: %+v", pa)
	}
}

func TestParseLinePositional(t *testing.T) {
	pa := parseLine([]string{"export", "json", "out.json"})
	if len(pa.rest) != 2 || pa.rest[0] != "json" || pa.rest[1] != "out.json" {
		t.Fatalf("rest=%v", pa.rest)
	}
}

func TestParseHeadersRepeatable(t *testing.T) {
	pa := parseLine([]string{"add", "--path", "x", "--header", "A:1", "--header", "B:2"})
	if len(pa.headers) != 2 {
		t.Fatalf("headers=%v", pa.headers)
	}
}
