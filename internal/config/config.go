// Package config persists GoCatcher preferences to ~/.gocatcher.conf as simple
// key=value lines (editor, callback URL, webhook endpoints, dashboard token).
package config

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Config holds persisted user preferences.
type Config struct {
	Editor         string // chosen editor binary (nano/nvim/vim)
	CallbackURL    string // public URL used to template payloads (serveo/EC2)
	SlackWebhook   string // Slack incoming-webhook URL
	DiscordWebhook string // Discord webhook URL
	TelegramToken  string // Telegram bot token
	TelegramChat   string // Telegram chat id
	WebhookURL     string // generic JSON webhook URL
	DashboardToken string // bearer token protecting the live dashboard
}

func path() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".gocatcher.conf"
	}
	return filepath.Join(home, ".gocatcher.conf")
}

var keymap = map[string]func(*Config, string){
	"editor":          func(c *Config, v string) { c.Editor = v },
	"callback_url":    func(c *Config, v string) { c.CallbackURL = v },
	"slack_webhook":   func(c *Config, v string) { c.SlackWebhook = v },
	"discord_webhook": func(c *Config, v string) { c.DiscordWebhook = v },
	"telegram_token":  func(c *Config, v string) { c.TelegramToken = v },
	"telegram_chat":   func(c *Config, v string) { c.TelegramChat = v },
	"webhook_url":     func(c *Config, v string) { c.WebhookURL = v },
	"dashboard_token": func(c *Config, v string) { c.DashboardToken = v },
}

// Load reads the config file, returning a zero Config if it does not exist.
func Load() Config {
	c := Config{}
	f, err := os.Open(path())
	if err != nil {
		return c
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if set, ok := keymap[strings.TrimSpace(key)]; ok {
			set(&c, strings.TrimSpace(val))
		}
	}
	return c
}

// Save writes the config file.
func Save(c Config) error {
	fields := map[string]string{
		"editor":          c.Editor,
		"callback_url":    c.CallbackURL,
		"slack_webhook":   c.SlackWebhook,
		"discord_webhook": c.DiscordWebhook,
		"telegram_token":  c.TelegramToken,
		"telegram_chat":   c.TelegramChat,
		"webhook_url":     c.WebhookURL,
		"dashboard_token": c.DashboardToken,
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		if fields[k] != "" {
			b.WriteString(k + " = " + fields[k] + "\n")
		}
	}
	return os.WriteFile(path(), []byte(b.String()), 0o644)
}
