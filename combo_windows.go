//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func userName() string {
	return os.Getenv("USERNAME")
}

func banner(imag string) string {
	goos := runtime.GOOS
	majorVersion, minorVersion, buildNumber := windows.RtlGetNtVersionNumbers()
	goos = fmt.Sprintf("%s_%d.%d.%d", goos, majorVersion, minorVersion, buildNumber)
	return strings.Join([]string{
		imag,
		Ver,
		goos,
	}, "_")
}

// Пишем сертификат value в ветку реестра для putty клиента
func puttySession(key, value string) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER,
		filepath.Join(PuTTY, Sessions, key),
		registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err == nil {
		if value != "" {
			rk.SetStringValue("DetachedCertificate", value)
		}
		// Для удобства
		rk.SetDWordValue("WarnOnClose", 0)
		rk.SetDWordValue("FullScreenOnAltEnter", 1)
		rk.Close()
	} else {
		Println(err)
	}
}

func puttyHostCA(key, value string) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER,
		filepath.Join(PuTTY, SshHostCAs, key),
		registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err == nil {
		rk.SetStringValue("PublicKey", value)
		rk.SetStringValue("Validity", "*")
		rk.SetDWordValue("PermitRSASHA1", 0)
		rk.SetDWordValue("PermitRSASHA256", 1)
		rk.SetDWordValue("PermitRSASHA512", 1)
		rk.Close()
	} else {
		Println(err)
	}
}
