//go:build windows

package ui

import (
	"os"

	"golang.org/x/sys/windows"
)

// init enables ANSI/VT escape processing on the Windows console so the
// truecolor banner and logs render instead of printing raw escape codes.
// (Supported on Windows 10+; it is a no-op on older consoles.)
func init() {
	for _, h := range []windows.Handle{
		windows.Handle(os.Stdout.Fd()),
		windows.Handle(os.Stderr.Fd()),
	} {
		var mode uint32
		if err := windows.GetConsoleMode(h, &mode); err != nil {
			continue
		}
		windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
}
