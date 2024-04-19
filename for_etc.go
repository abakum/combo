//go:build !windows
// +build !windows

package main

import (
	"os"
	"runtime"
	"strings"
)

func userName() string {
	return os.Getenv("USER")
}

func banner(imag string) string {
	goos := runtime.GOOS
	return strings.Join([]string{
		imag,
		Ver,
		goos,
	}, "_")
}
