package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// Select renders an arrow-key navigable menu (HALO styled) and returns the
// chosen index. ok is false if the user cancelled (Esc/q/Ctrl-C).
//
// When stdin is not an interactive terminal it falls back to a numbered prompt
// so scripted/piped input still works.
func Select(title string, options []string) (idx int, ok bool) {
	if len(options) == 0 {
		return 0, false
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return selectFallback(title, options)
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return selectFallback(title, options)
	}
	defer term.Restore(fd, oldState)

	in := bufio.NewReader(os.Stdin)
	sel := 0

	render := func(first bool) {
		if !first {
			// Move cursor up over the previously drawn option lines.
			fmt.Fprintf(os.Stdout, "\033[%dA", len(options))
		}
		for i, opt := range options {
			cursor := "  "
			line := hLabel + opt + Reset
			if i == sel {
				cursor = hAmber + "▸ " + Reset
				line = hScan5 + opt + Reset
			}
			fmt.Fprintf(os.Stdout, "\r\033[K  %s%s\r\n", cursor, line)
		}
	}

	fmt.Fprintf(os.Stdout, "\r\n%s┤ %s%s%s ├%s\r\n",
		hFrame, hAmber, title, hFrame, Reset)
	fmt.Fprintf(os.Stdout, "%s  ↑/↓ move   ⏎ select   esc cancel%s\r\n", hDim, Reset)
	render(true)

	for {
		b, err := in.ReadByte()
		if err != nil {
			return 0, false
		}
		switch b {
		case '\r', '\n': // confirm
			return sel, true
		case 3, 'q': // Ctrl-C or q -> cancel
			return 0, false
		case 27: // ESC — lone Esc cancels, otherwise an arrow sequence
			if in.Buffered() == 0 {
				return 0, false
			}
			c1, _ := in.ReadByte()
			if c1 != '[' && c1 != 'O' {
				continue
			}
			switch c2, _ := in.ReadByte(); c2 {
			case 'A': // up
				sel = (sel - 1 + len(options)) % len(options)
				render(false)
			case 'B': // down
				sel = (sel + 1) % len(options)
				render(false)
			}
		case 'k': // vim up
			sel = (sel - 1 + len(options)) % len(options)
			render(false)
		case 'j': // vim down
			sel = (sel + 1) % len(options)
			render(false)
		}
	}
}

// selectFallback is the non-interactive path: print a numbered list and read a
// line from stdin.
func selectFallback(title string, options []string) (int, bool) {
	fmt.Printf("\n%s┤ %s%s%s ├%s\n", hFrame, hAmber, title, hFrame, Reset)
	for i, opt := range options {
		fmt.Printf("  %s%d%s) %s\n", hAmber, i+1, Reset, opt)
	}
	fmt.Printf("%sselect [1-%d]: %s", hDim, len(options), Reset)

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(options) {
		return 0, false
	}
	return n - 1, true
}
