package catcher

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"gocatcher/internal/ui"
)

// tunnelProvider resolves which tunnel to start: the explicit --tunnel value,
// or "serveo" when the legacy --serveo flag was given.
func (rc *RequestCatcher) tunnelProvider() string {
	if rc.opt.Tunnel != "" {
		return strings.ToLower(rc.opt.Tunnel)
	}
	if rc.opt.EnableServeo {
		return "serveo"
	}
	return ""
}

// startTunnel launches the selected public-URL provider.
func (rc *RequestCatcher) startTunnel(provider string) {
	port := rc.opt.BindPort
	switch provider {
	case "serveo":
		rc.sshTunnel("serveo", []string{
			"-R", fmt.Sprintf("80:localhost:%d", port), "serveo.net",
		})
	case "localhost.run", "lhr":
		rc.sshTunnel("localhost.run", []string{
			"-R", fmt.Sprintf("80:localhost:%d", port), "nokey@localhost.run",
		})
	case "pinggy":
		// Pinggy uses port 443 and a remote-forward spec of 0:localhost:PORT.
		rc.sshTunnel("pinggy", []string{
			"-p", "443", "-R", fmt.Sprintf("0:localhost:%d", port), "a.pinggy.io",
		})
	case "ngrok":
		rc.ngrokTunnel(port)
	case "nip.io", "nipio":
		rc.nipio(port)
	default:
		ui.Error("unknown tunnel: " + provider + " (serveo | localhost.run | pinggy | ngrok | nip.io)")
	}
}

// sshTunnel runs an ssh reverse-tunnel provider and streams its output so the
// assigned public URL — or any error — is always visible.
func (rc *RequestCatcher) sshTunnel(name string, extra []string) {
	ui.Info("Starting tunnel via " + name)
	args := append([]string{
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=60",
		"-o", "ExitOnForwardFailure=yes",
	}, extra...)

	rc.tunnelCmd = exec.Command("ssh", args...)
	stdout, err := rc.tunnelCmd.StdoutPipe()
	if err != nil {
		ui.Error(name + ": " + err.Error())
		return
	}
	rc.tunnelCmd.Stderr = rc.tunnelCmd.Stdout // merge stderr so errors are visible
	if err := rc.tunnelCmd.Start(); err != nil {
		ui.Error(name + ": " + err.Error() + " (is ssh installed?)")
		return
	}

	gotURL := false
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if u := extractURL(line); u != "" {
			ui.Info(name + " » " + u)
			gotURL = true
		} else {
			ui.Info(name + ": " + line)
		}
	}
	if !gotURL {
		ui.Error(name + ": tunnel closed without a URL — the service may be down or " +
			"outbound SSH is blocked. Try another: run --tunnel localhost.run | pinggy | ngrok")
	}
}

// ngrokTunnel shells out to the ngrok binary and parses its logfmt output.
func (rc *RequestCatcher) ngrokTunnel(port int) {
	if _, err := exec.LookPath("ngrok"); err != nil {
		ui.Error("ngrok: binary not found — install it and run `ngrok config add-authtoken <token>`")
		return
	}
	ui.Info("Starting tunnel via ngrok")
	rc.tunnelCmd = exec.Command("ngrok", "http", fmt.Sprintf("%d", port),
		"--log", "stdout", "--log-format", "logfmt")
	stdout, err := rc.tunnelCmd.StdoutPipe()
	if err != nil {
		ui.Error("ngrok: " + err.Error())
		return
	}
	rc.tunnelCmd.Stderr = rc.tunnelCmd.Stdout
	if err := rc.tunnelCmd.Start(); err != nil {
		ui.Error("ngrok: " + err.Error())
		return
	}
	gotURL := false
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// ngrok logfmt lines carry: url=https://xxxx.ngrok-free.app
		if i := strings.Index(line, "url=https://"); i >= 0 {
			u := strings.Fields(line[i+4:])[0]
			ui.Info("ngrok » " + u)
			gotURL = true
			continue
		}
		if strings.Contains(line, "lvl=eror") || strings.Contains(line, "err=") {
			ui.Error("ngrok: " + line)
		}
	}
	if !gotURL {
		ui.Error("ngrok: no URL (check your authtoken and ngrok status)")
	}
}

// nipio prints a nip.io hostname for this host's IP. nip.io is wildcard DNS,
// not a tunnel: it resolves <name>.<ip>.nip.io -> <ip>, so it only reaches
// GoCatcher if that IP is reachable by the target (public IP / same LAN).
func (rc *RequestCatcher) nipio(port int) {
	ip := rc.opt.BindAddress
	if ip == "0.0.0.0" || ip == "" || ip == "::" {
		ip = outboundIP()
	}
	scheme := rc.scheme()
	host := fmt.Sprintf("gocatcher.%s.nip.io", ip)
	ui.Info(fmt.Sprintf("nip.io » %s://%s:%d  (resolves to %s)", scheme, host, port, ip))
	ui.Info("nip.io is DNS only — reachable only if " + ip + " is routable from the target")
}

// extractURL returns the first https?:// token found in a line, else "".
func extractURL(line string) string {
	for _, tok := range strings.Fields(line) {
		tok = strings.Trim(tok, "\"'()<>,")
		if strings.HasPrefix(tok, "https://") || strings.HasPrefix(tok, "http://") {
			return tok
		}
	}
	return ""
}

// outboundIP discovers the primary outbound interface IP (no traffic is sent).
func outboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
