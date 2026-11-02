// Validate one Mihomo DOMAIN-REGEX pattern with Go's RE2-compatible regexp engine.
package main

import (
	"fmt"
	"os"
	"regexp"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: validate_regex PATTERN")
		os.Exit(2)
	}
	if _, err := regexp.Compile(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
