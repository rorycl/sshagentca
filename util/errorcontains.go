package util

import (
	"strings"
)

// https://stackoverflow.com/a/55803656
func ErrorContains(out error, want string) bool {
	if out == nil {
		return want == ""
	}
	if want == "" {
		return false
	}
	return strings.Contains(out.Error(), want)
}
