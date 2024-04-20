//go:build !windows
// +build !windows

package main

import (
	"os"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
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

// Пишем сертификат value в ветку реестра для putty клиента
func puttySession(key, value string) {
}

func puttyHostCA(id string, data []byte, pub ssh.PublicKey) {
}
