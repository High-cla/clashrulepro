// Validate Mihomo DOMAIN-REGEX patterns with Go's RE2-compatible regexp engine.
package main

import (
	"fmt"
	"os"
	"regexp"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: validate_regex validate PATTERN | validate_regex match PATTERN TEXT")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 3 {
		usage()
	}

	switch os.Args[1] {
	case "validate":
		if len(os.Args) != 3 {
			usage()
		}
		if _, err := regexp.Compile(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "match":
		if len(os.Args) != 4 {
			usage()
		}
		// Preserve the validator's former case-insensitive search semantics.
		re, err := regexp.Compile("(?i:" + os.Args[2] + ")")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !re.MatchString(os.Args[3]) {
			os.Exit(1)
		}
	default:
		usage()
	}
}
