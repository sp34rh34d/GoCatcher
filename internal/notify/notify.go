// Package notify pushes alerts to external services (Slack, Discord, Telegram,
// or a generic JSON webhook) configured by the user.
package notify

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"gocatcher/internal/config"
)

var client = &http.Client{Timeout: 8 * time.Second}

// Alert is the payload delivered to notification sinks.
type Alert struct {
	Kind   string `json:"kind"`   // XSS, SSRF, XXE, SSTI, CSRF, CALLBACK...
	Title  string `json:"title"`  // short human summary
	Detail string `json:"detail"` // multi-line context
	Remote string `json:"remote"` // source IP
	Path   string `json:"path"`   // request path
	Token  string `json:"token"`  // correlation id
	Time   string `json:"time"`   // RFC3339
}

// Configured reports whether any notification sink is set.
func Configured(c config.Config) bool {
	return c.SlackWebhook != "" || c.DiscordWebhook != "" ||
		(c.TelegramToken != "" && c.TelegramChat != "") || c.WebhookURL != ""
}

// Dispatch sends the alert to every configured sink (fire-and-forget).
func Dispatch(c config.Config, a Alert) {
	text := "🔔 GoCatcher " + a.Kind + " — " + a.Title +
		"\nfrom " + a.Remote + "  path " + a.Path
	if a.Token != "" {
		text += "  token " + a.Token
	}
	if a.Detail != "" {
		text += "\n" + a.Detail
	}

	if c.SlackWebhook != "" {
		go postJSON(c.SlackWebhook, map[string]string{"text": text})
	}
	if c.DiscordWebhook != "" {
		go postJSON(c.DiscordWebhook, map[string]string{"content": text})
	}
	if c.TelegramToken != "" && c.TelegramChat != "" {
		api := "https://api.telegram.org/bot" + c.TelegramToken + "/sendMessage"
		go postForm(api, url.Values{"chat_id": {c.TelegramChat}, "text": {text}})
	}
	if c.WebhookURL != "" {
		go postJSON(c.WebhookURL, a)
	}
}

func postJSON(endpoint string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}
}

func postForm(endpoint string, vals url.Values) {
	if resp, err := client.PostForm(endpoint, vals); err == nil {
		resp.Body.Close()
	}
}
