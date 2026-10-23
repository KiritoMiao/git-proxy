package version

import (
	_ "embed"
	"strings"
)

//go:embed version.txt
var number string

// Number is managed by Release Please and embedded in every binary.
func Number() string { return strings.TrimSpace(number) }

// Revision is set to the source commit by release builds.
var Revision = "unknown"

const Repository = "https://github.com/KiritoMiao/git-proxy"
