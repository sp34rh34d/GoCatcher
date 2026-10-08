// Package ui holds terminal colors and the formatted-output helpers used
// throughout GoCatcher. It is the Go port of core/utilities.py.
package ui

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/textproto"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Foreground colors (Python class `c`).
const (
	Black     = "\033[30m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Orange    = "\033[33m"
	Blue      = "\033[34m"
	Purple    = "\033[35m"
	Reset     = "\033[0m"
	Cyan      = "\033[36m"
	LightGrey = "\033[37m"
)

// Background colors (Python class `bc`). Only the ones used are kept.
const (
	BgBlack = "\033[40m"
)

func now() string { return time.Now().Format("2006-01-02 15:04:05.000000") }

// Info prints an informational line.
func Info(msg string) {
	fmt.Printf("[%si%s] %s - %s%s%s\r\n", Blue, Reset, now(), Blue, msg, Reset)
}

// Error prints an error line.
func Error(msg string) {
	fmt.Printf("\n[%s*%s] %s - %s%s%s\n\r", Red, Reset, now(), Red, msg, Reset)
}

// NewRequest returns the banner printed above every caught request.
func NewRequest() string {
	return fmt.Sprintf("\n=========================%s[ New request caught - %s ]%s=========================\n\r",
		BgBlack, now(), Reset)
}

// RequestInfo returns the method/remote-addr/path summary line.
func RequestInfo(method, remoteAddr, path string) string {
	return fmt.Sprintf("[%s%s%s][%s%s%s] -> %s%s%s\n\r",
		Orange, method, Reset, Orange, remoteAddr, Reset, Blue, path, Reset)
}

// RequestHeaders renders the request headers as a tree.
func RequestHeaders(h http.Header) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := fmt.Sprintf("%s[      Headers      ]%s\n\r", BgBlack, Reset)
	total := 0
	for _, k := range keys {
		total += len(h[k])
	}
	i := 0
	for _, k := range keys {
		for _, v := range h[k] {
			i++
			prefix := "├──"
			if i == total {
				prefix = "└──"
			}
			out += fmt.Sprintf(" %s%s[ %s%s :%s %s \n\r", prefix, BgBlack, Green, k, Reset, v)
		}
	}
	return out
}

// RequestCookies renders request cookies, or nothing when there are none.
func RequestCookies(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		parts = append(parts, fmt.Sprintf("'%s': '%s'", ck.Name, ck.Value))
	}
	out := fmt.Sprintf("\n%s[      Cookies      ]%s\n\r", BgBlack, Reset)
	out += fmt.Sprintf(" └──%s[ %sCookies :%s {%s}\n\r", BgBlack, Green, Reset, strings.Join(parts, ", "))
	return out
}

// RequestPostData renders POST body data (form map or raw string).
func RequestPostData(data string) string {
	if data == "" {
		return ""
	}
	out := fmt.Sprintf("\n%s[      Post Data      ]%s\n\r", BgBlack, Reset)
	out += fmt.Sprintf(" └──%s[ %sParameters :%s%s\n\r", BgBlack, Green, Reset, data)
	return out
}

// SaveFile writes an uploaded file to files/<md5(filename)>.bin and returns the
// rendered tree fragment describing it (mirrors msg.requestFiles per file).
func SaveFile(field, filename, contentType string, content []byte) string {
	sum := md5.Sum([]byte(filename))
	saved := hex.EncodeToString(sum[:]) + ".bin"
	_ = os.MkdirAll("files", 0o755)
	_ = os.WriteFile("files/"+saved, content, 0o644)

	out := fmt.Sprintf(" ├──%s[ %sFile field :%s [%s%s%s]: filename=%s%s%s, content-type=%s%s%s\n\r",
		BgBlack, Green, Reset, Orange, field, Reset, Orange, filename, Reset, Orange, contentType, Reset)
	out += fmt.Sprintf(" ├──[%s Content :%s %d bytes\n\r", Green, Reset, len(content))
	out += fmt.Sprintf(" └──[%s File saved as files/%s%s\n\r", Green, saved, Reset)
	return out
}

// FilesHeader returns the "Files" section header (printed once when files exist).
func FilesHeader() string {
	return fmt.Sprintf("\n%s[      Files      ]%s\n\r", BgBlack, Reset)
}

// CanonicalHeaderKey exposes textproto canonicalization for callers that build
// header maps by hand.
func CanonicalHeaderKey(k string) string { return textproto.CanonicalMIMEHeaderKey(k) }

// ---------------------------------------------------------------------------
// HALO / UNSC holographic theme
// ---------------------------------------------------------------------------

// Truecolor HALO palette (24-bit ANSI). Cyan hologram + Forerunner amber.
const (
	hScan1  = "\033[38;2;0;90;110m" // figlet scanline (dim -> bright)
	hScan2  = "\033[38;2;0;130;160m"
	hScan3  = "\033[38;2;30;170;200m"
	hScan4  = "\033[38;2;70;205;225m"
	hScan5  = "\033[38;2;130;232;242m"
	hScan6  = "\033[38;2;190;248;252m"
	hFrame  = "\033[38;2;0;160;190m"  // steady frame cyan
	hLabel  = "\033[38;2;90;175;190m" // dim label text
	hAmber  = "\033[38;2;255;176;0m"  // Forerunner amber accent
	hOnline = "\033[38;2;90;230;150m" // status LED
	hDim    = "\033[38;2;70;120;135m" // faint helper text
)

const inner = 75 // interior width of the main holo frame

func visibleWidth(s string) int {
	n, inEsc := 0, false
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
		n++
	}
	return n
}

func padTo(s string, w int) string {
	if d := w - visibleWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// wrapWords splits a space-separated string into lines no wider than w runes.
// Returns nil for an empty string so callers can skip rendering.
func wrapWords(s string, w int) []string {
	if s == "" {
		return nil
	}
	if w < 1 {
		w = 1
	}
	var lines []string
	cur := ""
	for _, word := range strings.Fields(s) {
		switch {
		case cur == "":
			cur = word
		case len(cur)+1+len(word) <= w:
			cur += " " + word
		default:
			lines = append(lines, cur)
			cur = word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// row renders one framed content line of the main holo frame.
func row(content string) string {
	return hFrame + "║ " + Reset + padTo(content, inner) + hFrame + " ║" + Reset
}

var figlet = []string{
	" ██████╗  ██████╗  ██████╗ █████╗ ████████╗ ██████╗██╗  ██╗███████╗██████╗ ",
	"██╔════╝ ██╔═══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔══██╗",
	"██║  ███╗██║   ██║██║     ███████║   ██║   ██║     ███████║█████╗  ██████╔╝",
	"██║   ██║██║   ██║██║     ██╔══██║   ██║   ██║     ██╔══██║██╔══╝  ██╔══██╗",
	"╚██████╔╝╚██████╔╝╚██████╗██║  ██║   ██║   ╚██████╗██║  ██║███████╗██║  ██║",
	" ╚═════╝  ╚═════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ",
}

var scan = []string{hScan1, hScan2, hScan3, hScan4, hScan5, hScan6}

// Banner prints the holographic GOCATCHER header with a UNSC status bar.
func Banner() {
	top := hFrame + "╔" + strings.Repeat("═", inner+2) + "╗" + Reset
	div := hFrame + "╟" + strings.Repeat("─", inner+2) + "╢" + Reset
	bot := hFrame + "╚" + strings.Repeat("═", inner+2) + "╝" + Reset

	fmt.Println()
	fmt.Println(top)
	for i, line := range figlet {
		fmt.Println(row(scan[i] + line + Reset))
	}
	fmt.Println(div)

	status := fmt.Sprintf("%s◆ %sUNSC TACTICAL HTTP INTERCEPT SYSTEM%s", hFrame, hLabel, Reset)
	right := fmt.Sprintf("%sBUILD 1.0%s   %s[ %s●%s ONLINE ]%s", hDim, Reset, hFrame, hOnline, hFrame, Reset)
	gap := inner - visibleWidth(status) - visibleWidth(right)
	if gap < 1 {
		gap = 1
	}
	fmt.Println(row(status + strings.Repeat(" ", gap) + right))

	credit := fmt.Sprintf("%s◇ operator:%s sp34rh34d   %s◇ net:%s x/@spearh34d", hDim, hLabel, hDim, hLabel)
	fmt.Println(row(credit + Reset))
	fmt.Println(bot)
	fmt.Println()
}

// command is one entry in the HALO command interface.
type command struct{ name, flags, desc string }

var commandList = []command{
	{"run", "--port --interface --ssl --key --pub --tunnel <serveo|localhost.run|pinggy|ngrok|nip.io> --dashboard --dns --quiet --log", "start intercept server + monitor mode"},
	{"add", "--path --header", "register a payload route (opens editor)"},
	{"del", "--id <uuid>", "purge a registered route"},
	{"list", "", "enumerate active routes"},
	{"save", "", "commit routes to custom_routes.ini"},
	{"load", "", "restore routes from custom_routes.ini"},
	{"history", "[key=val …]", "show captured requests (filter by path/method/alert)"},
	{"export", "<json|csv|har> <file>", "export captured requests"},
	{"replay", "<seq> <target-url>", "resend a captured request to a new target"},
	{"set", "<key> <value>", "set callback-url / webhooks / dashboard-token"},
	{"config", "", "show saved configuration"},
	{"editor", "", "choose editor for new routes (nano/neovim/vim)"},
	{"help", "", "render this command interface"},
	{"exit", "", "terminate session"},
}

// HelpMenu prints the HALO command interface panel.
func HelpMenu() {
	title := hAmber + "COMMAND INTERFACE" + hFrame
	seg := "─┤ " + title + " ├"
	top := hFrame + "┌" + seg + strings.Repeat("─", (inner+2)-visibleWidth(seg)) + "┐" + Reset
	bot := hFrame + "└" + strings.Repeat("─", inner+2) + "┘" + Reset

	prow := func(c string) string {
		return hFrame + "│ " + Reset + padTo(c, inner) + hFrame + " │" + Reset
	}

	fmt.Println()
	fmt.Println(top)
	fmt.Println(prow(""))
	for _, cmd := range commandList {
		name := padTo(hAmber+"▸ "+cmd.name+Reset, 10)
		line := name + hLabel + cmd.desc + Reset
		fmt.Println(prow(line))
		// Wrap long flag lists so they never overflow the panel border.
		for i, seg := range wrapWords(cmd.flags, inner-12) {
			lead := "└ "
			if i > 0 {
				lead = "  "
			}
			fmt.Println(prow(padTo("", 10) + hDim + lead + seg + Reset))
		}
	}
	fmt.Println(prow(""))
	hint := fmt.Sprintf("%shint:%s header spaces -> use ++  (X-Flag:just++testing)", hDim, hLabel)
	fmt.Println(prow(hint + Reset))
	nav := fmt.Sprintf("%snav:%s TAB complete   ↑↓ history   ^C abort", hDim, hLabel)
	fmt.Println(prow(nav + Reset))
	fmt.Println(bot)
	fmt.Println()
}

// Menu prints the full startup interface: holo header + command panel.
func Menu() {
	Banner()
	HelpMenu()
}

// Prompt returns the REPL prompt string. The readline library emulates ANSI on
// Windows with a fixed-size escape parser that panics on 24-bit truecolor
// sequences, so there we fall back to a plain prompt.
func Prompt() string {
	if runtime.GOOS == "windows" {
		return "GOCATCHER > "
	}
	return fmt.Sprintf("%s╺┤%s ◆ %sGOCATCHER%s ◆ %s├╸%s▸%s ",
		hFrame, hAmber, hScan5, hAmber, hFrame, hOnline, Reset)
}
