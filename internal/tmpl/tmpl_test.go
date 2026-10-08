package tmpl

import "testing"

func TestApply(t *testing.T) {
	in := []byte(`src="{{callback_url}}/x?t={{token}}" ip={{victim_ip}} host={{host}}`)
	got := string(Apply(in, Vars{CallbackURL: "http://c:8080", Token: "T1", VictimIP: "1.2.3.4", Host: "h"}))
	want := `src="http://c:8080/x?t=T1" ip=1.2.3.4 host=h`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestApplyNoPlaceholders(t *testing.T) {
	in := []byte("plain payload")
	if got := Apply(in, Vars{CallbackURL: "x"}); string(got) != "plain payload" {
		t.Fatalf("unexpected: %q", got)
	}
}
