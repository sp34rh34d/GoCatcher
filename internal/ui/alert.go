package ui

import (
	"fmt"
	"strings"
)

// AlertBanner prints a high-visibility block when a payload callback fires.
func AlertBanner(kind, remote, path, token, decoded string) {
	bar := hAmber + strings.Repeat("▰", 60) + Reset
	fmt.Println()
	fmt.Println(bar)
	fmt.Printf("%s🔔 %s%s FIRED%s  from %s%s%s  →  %s%s%s\n",
		hAmber, hOnline, kind, Reset, hScan5, remote, Reset, hScan5, path, Reset)
	if token != "" {
		fmt.Printf("%s   token:%s %s\n", hDim, Reset, token)
	}
	if decoded != "" {
		fmt.Printf("%s   ── decoded ──%s\n", hDim, Reset)
		for _, line := range strings.Split(decoded, "\n") {
			fmt.Printf("   %s\n", line)
		}
	}
	fmt.Println(bar)
	fmt.Println()
}
