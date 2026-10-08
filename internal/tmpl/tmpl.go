// Package tmpl performs lightweight placeholder substitution on payloads as
// they are served, so stored payloads never need the callback host hard-coded.
package tmpl

import "strings"

// Vars are the values substituted into payload placeholders.
type Vars struct {
	CallbackURL string
	Token       string
	VictimIP    string
	Host        string
}

// Apply replaces {{callback_url}}, {{token}}, {{victim_ip}} and {{host}} in the
// payload. If no placeholders are present the input is returned unchanged.
func Apply(data []byte, v Vars) []byte {
	s := string(data)
	if !strings.Contains(s, "{{") {
		return data
	}
	rep := strings.NewReplacer(
		"{{callback_url}}", v.CallbackURL,
		"{{token}}", v.Token,
		"{{victim_ip}}", v.VictimIP,
		"{{host}}", v.Host,
	)
	return []byte(rep.Replace(s))
}
