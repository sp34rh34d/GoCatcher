// Package repl implements the interactive GoCatcher shell. It is the Go port of
// the main loop in GoCatcher.py.
package repl

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"

	"gocatcher/internal/capture"
	"gocatcher/internal/catcher"
	"gocatcher/internal/config"
	"gocatcher/internal/payloads"
	"gocatcher/internal/routes"
	"gocatcher/internal/ui"
)

var commands = []string{"exit", "help", "run", "add", "del", "load", "save", "list",
	"editor", "history", "export", "replay", "set", "config"}

// stringSlice backs the repeatable --header flag.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// parsedArgs holds every recognized flag for one command line.
type parsedArgs struct {
	option    string
	port      string
	iface     string
	ssl       bool
	key       string
	pub       string
	path      string
	id        string
	headers   stringSlice
	serveo    bool
	tunnel    string
	dashboard bool
	dns       bool
	dnsPort   string
	quiet     bool
	logFile   string
	rest      []string
}

func parseLine(tokens []string) parsedArgs {
	pa := parsedArgs{}
	if len(tokens) == 0 {
		return pa
	}
	pa.option = tokens[0]

	fs := flag.NewFlagSet("gocatcher", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&pa.port, "port", "8080", "")
	fs.StringVar(&pa.iface, "interface", "0.0.0.0", "")
	fs.BoolVar(&pa.ssl, "ssl", false, "")
	fs.StringVar(&pa.key, "key", "", "")
	fs.StringVar(&pa.pub, "pub", "", "")
	fs.StringVar(&pa.path, "path", "", "")
	fs.StringVar(&pa.id, "id", "", "")
	fs.Var(&pa.headers, "header", "")
	fs.BoolVar(&pa.serveo, "serveo", false, "")
	fs.StringVar(&pa.tunnel, "tunnel", "", "")
	fs.BoolVar(&pa.dashboard, "dashboard", false, "")
	fs.BoolVar(&pa.dns, "dns", false, "")
	fs.StringVar(&pa.dnsPort, "dns-port", "5353", "")
	fs.BoolVar(&pa.quiet, "quiet", false, "")
	fs.StringVar(&pa.logFile, "log", "", "")

	if err := fs.Parse(tokens[1:]); err != nil {
		// Match Python behavior: on a parse error, treat the command as unknown.
		pa.option = ""
		return pa
	}
	pa.rest = fs.Args()
	return pa
}

// Run starts the REPL loop and blocks until the user exits.
func Run() {
	store := routes.Store{}
	payloads.Seed(store) // preload built-in XSS/CSRF/SSTI/XXE/SSRF routes
	cap := capture.New(5000, "gocatcher_requests.jsonl")
	defer cap.Close()
	ui.Menu()

	completer := readline.NewPrefixCompleter()
	for _, cmd := range commands {
		completer.Children = append(completer.Children, readline.PcItem(cmd))
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:       ui.Prompt(),
		AutoComplete: completer,
	})
	if err != nil {
		ui.Error("readline: " + err.Error())
		return
	}
	defer rl.Close()

	for {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			ui.Error("Stopped by user!")
			return
		}
		if err == io.EOF {
			ui.Info("quitting...")
			return
		}

		tokens := strings.Fields(strings.TrimSpace(line))
		if len(tokens) == 0 {
			continue
		}
		args := parseLine(tokens)

		switch args.option {
		case "exit":
			ui.Info("quitting...")
			return
		case "run":
			runServer(store, cap, args)
		case "list":
			store.List()
		case "save":
			_ = store.Save()
		case "load":
			store.Load()
		case "add":
			addRoute(store, args)
		case "del":
			delRoute(store, args)
		case "editor":
			resolveEditor(true) // force re-selection and persist
		case "history":
			showHistory(cap, args)
		case "export":
			exportCaptures(cap, args)
		case "replay":
			replayRequest(cap, args)
		case "set":
			setConfig(args)
		case "config":
			showConfig()
		case "help":
			ui.HelpMenu()
		}
	}
}

func runServer(store routes.Store, cap *capture.Store, args parsedArgs) {
	port, err := strconv.Atoi(args.port)
	if err != nil {
		ui.Error("invalid --port value")
		return
	}
	dnsPort, _ := strconv.Atoi(args.dnsPort)
	rc := catcher.New(catcher.Options{
		BindAddress:     args.iface,
		BindPort:        port,
		EnableSSL:       args.ssl,
		PrivateKey:      args.key,
		PublicKey:       args.pub,
		CustomRoutes:    store,
		EnableServeo:    args.serveo,
		Tunnel:          args.tunnel,
		EnableDashboard: args.dashboard,
		EnableDNS:       args.dns,
		DNSPort:         dnsPort,
		Quiet:           args.quiet,
		LogFile:         args.logFile,
		Store:           cap,
		Cfg:             config.Load(),
	})
	rc.Run()
}

func addRoute(store routes.Store, args parsedArgs) {
	if args.path == "" {
		ui.Error("You need to set a route name, use --path my_new_rute")
		return
	}

	if err := os.MkdirAll("routes", 0o755); err != nil {
		ui.Error(err.Error())
		return
	}
	file := "routes/" + args.path + ".bin"
	editFile(file)

	headers := map[string]string{}
	for _, h := range args.headers {
		k, v, ok := strings.Cut(h, ":")
		if ok {
			headers[k] = v
		}
	}
	store[newUUID()] = routes.Route{Path: args.path, File: file, Headers: headers}
}

func delRoute(store routes.Store, args parsedArgs) {
	if args.id == "" {
		ui.Error("id is required!, use --id <uuid>")
		return
	}
	if _, ok := store[args.id]; !ok {
		ui.Info("custom route id not found!")
		return
	}
	delete(store, args.id)
}

// showHistory prints captured requests, optionally filtered by key=substring
// pairs (e.g. history path=/ssrf method=POST alert=XSS).
func showHistory(cap *capture.Store, args parsedArgs) {
	filter := map[string]string{}
	for _, kv := range args.rest {
		if k, v, ok := strings.Cut(kv, "="); ok {
			filter[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	recs := cap.Filter(filter)
	if len(recs) == 0 {
		ui.Info("no captured requests yet")
		return
	}
	fmt.Printf("%-5s %-8s %-6s %-26s %-16s %s\n", "SEQ", "TIME", "METHOD", "PATH", "REMOTE", "ALERT")
	fmt.Println(strings.Repeat("-", 78))
	for _, r := range recs {
		path := r.Path
		if r.Query != "" {
			path += "?" + r.Query
		}
		if len(path) > 26 {
			path = path[:25] + "…"
		}
		fmt.Printf("%-5d %-8s %-6s %-26s %-16s %s\n",
			r.Seq, r.Time.Format("15:04:05"), r.Method, path, r.Remote, r.Alert)
	}
	fmt.Printf("%d request(s)\n", len(recs))
}

// exportCaptures writes the captures to a file. Usage: export <json|csv|har> <path>
func exportCaptures(cap *capture.Store, args parsedArgs) {
	if len(args.rest) < 2 {
		ui.Error("usage: export <json|csv|har> <file>")
		return
	}
	format, path := strings.ToLower(args.rest[0]), args.rest[1]
	var err error
	switch format {
	case "json":
		err = cap.ExportJSON(path)
	case "csv":
		err = cap.ExportCSV(path)
	case "har":
		err = cap.ExportHAR(path)
	default:
		ui.Error("unknown format: " + format + " (use json|csv|har)")
		return
	}
	if err != nil {
		ui.Error("export: " + err.Error())
		return
	}
	ui.Info(fmt.Sprintf("exported %d record(s) to %s", cap.Count(), path))
}

// replayRequest resends a captured request to a new target.
// Usage: replay <seq> <target-base-url>
func replayRequest(cap *capture.Store, args parsedArgs) {
	if len(args.rest) < 2 {
		ui.Error("usage: replay <seq> <target-base-url>")
		return
	}
	seq, err := strconv.Atoi(args.rest[0])
	if err != nil {
		ui.Error("invalid seq")
		return
	}
	var rec *capture.Record
	for _, r := range cap.All() {
		if r.Seq == seq {
			rc := r
			rec = &rc
			break
		}
	}
	if rec == nil {
		ui.Error("seq not found in history")
		return
	}
	target := strings.TrimRight(args.rest[1], "/")
	url := target + rec.Path
	if rec.Query != "" {
		url += "?" + rec.Query
	}
	req, err := http.NewRequest(rec.Method, url, strings.NewReader(rec.Body))
	if err != nil {
		ui.Error("replay: " + err.Error())
		return
	}
	for k, v := range rec.Headers {
		if k == "Host" || k == "Content-Length" {
			continue
		}
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		ui.Error("replay: " + err.Error())
		return
	}
	defer resp.Body.Close()
	ui.Info(fmt.Sprintf("replayed #%d %s %s -> %s", seq, rec.Method, url, resp.Status))
}

// setConfig updates a persisted setting. Usage: set <key> <value>
func setConfig(args parsedArgs) {
	if len(args.rest) < 2 {
		ui.Error("usage: set <callback-url|slack|discord|telegram-token|telegram-chat|webhook|dashboard-token> <value>")
		return
	}
	key := strings.ToLower(args.rest[0])
	val := strings.Join(args.rest[1:], " ")
	cfg := config.Load()
	switch key {
	case "callback-url":
		cfg.CallbackURL = val
	case "slack":
		cfg.SlackWebhook = val
	case "discord":
		cfg.DiscordWebhook = val
	case "telegram-token":
		cfg.TelegramToken = val
	case "telegram-chat":
		cfg.TelegramChat = val
	case "webhook":
		cfg.WebhookURL = val
	case "dashboard-token":
		cfg.DashboardToken = val
	default:
		ui.Error("unknown setting: " + key)
		return
	}
	if err := config.Save(cfg); err != nil {
		ui.Error("save: " + err.Error())
		return
	}
	ui.Info(key + " saved")
}

// showConfig prints the current persisted configuration (secrets masked).
func showConfig() {
	cfg := config.Load()
	mask := func(s string) string {
		if s == "" {
			return "-"
		}
		if len(s) <= 8 {
			return "••••"
		}
		return s[:4] + "…" + s[len(s)-4:]
	}
	fmt.Printf("  editor          : %s\n", orDash(cfg.Editor))
	fmt.Printf("  callback_url    : %s\n", orDash(cfg.CallbackURL))
	fmt.Printf("  slack_webhook   : %s\n", mask(cfg.SlackWebhook))
	fmt.Printf("  discord_webhook : %s\n", mask(cfg.DiscordWebhook))
	fmt.Printf("  telegram_token  : %s\n", mask(cfg.TelegramToken))
	fmt.Printf("  telegram_chat   : %s\n", orDash(cfg.TelegramChat))
	fmt.Printf("  webhook_url     : %s\n", mask(cfg.WebhookURL))
	fmt.Printf("  dashboard_token : %s\n", mask(cfg.DashboardToken))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type editorChoice struct{ bin, label string }

// supportedEditors lists the editors GoCatcher can open, in detection order.
// Windows gets notepad (always present) first; other systems get nano/nvim/vim.
func supportedEditors() []editorChoice {
	if runtime.GOOS == "windows" {
		return []editorChoice{
			{"notepad", "notepad"},
			{"notepad++", "notepad++"},
			{"nvim", "neovim (nvim)"},
			{"vim", "vim"},
		}
	}
	return []editorChoice{
		{"nano", "nano"},
		{"nvim", "neovim (nvim)"},
		{"vim", "vim"},
	}
}

// resolveEditor returns the editor binary to use. It reuses the saved choice
// when that editor is still installed; otherwise it detects the installed
// editors, asks the user to pick one (arrow-key menu), and persists the choice
// for future routes. Returns "" if the user cancelled or none are installed.
func resolveEditor(force bool) string {
	if !force {
		cfg := config.Load()
		if cfg.Editor != "" {
			if _, err := exec.LookPath(cfg.Editor); err == nil {
				return cfg.Editor
			}
		}
	}

	editors := supportedEditors()
	var bins, labels []string
	for _, e := range editors {
		if _, err := exec.LookPath(e.bin); err == nil {
			bins = append(bins, e.bin)
			labels = append(labels, e.label)
		}
	}
	switch len(bins) {
	case 0:
		names := make([]string, len(editors))
		for i, e := range editors {
			names[i] = e.bin
		}
		ui.Error("no editor found — install one of: " + strings.Join(names, ", "))
		return ""
	case 1:
		ui.Info("using " + bins[0] + " (only editor found) — saved for next routes")
	default:
		idx, ok := ui.Select("SELECT EDITOR", labels)
		if !ok {
			ui.Error("editor selection cancelled")
			return ""
		}
		bins = bins[idx : idx+1]
	}

	chosen := bins[0]
	cfg := config.Load() // preserve other settings when saving the editor
	cfg.Editor = chosen
	if err := config.Save(cfg); err != nil {
		ui.Error("could not save editor preference: " + err.Error())
	} else {
		ui.Info("editor set to " + chosen + " (change it anytime with: editor)")
	}
	return chosen
}

// editFile opens the backing file in the resolved editor.
func editFile(path string) {
	editor := resolveEditor(false)
	if editor == "" {
		return
	}
	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		ui.Error("editor: " + err.Error())
	}
}

// newUUID returns a random RFC-4122 v4 UUID string.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
