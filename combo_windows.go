//go:build windows
// +build windows

package main

import (
	"path/filepath"
	"strconv"

	"github.com/abakum/winssh"
	"golang.org/x/sys/windows/registry"
)

var (
	PuTTY = `SOFTWARE\SimonTatham\PuTTY`
)

// Пишем сертификат value для putty клиента
func PuttySessionCert(key, value string) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER,
		filepath.Join(PuTTY, Sessions, key),
		registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err == nil {
		rk.SetStringValue("DetachedCertificate", value)
		rk.Close()
	} else {
		Println(err)
	}
}

// Пишем user host port для putty клиента
func PuttySession(key string, values ...string) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER,
		filepath.Join(PuTTY, Sessions, key),
		registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err == nil {
		if len(values) > 0 {
			UserName, HostName, PortNumber := winssh.UserName(), LH, PORT
			if len(values) > 0 {
				UserName = values[0]
			}
			if len(values) > 1 {
				HostName = values[1]
			}
			if len(values) > 2 {
				PortNumber = values[2]
			}
			rk.SetStringValue("UserName", UserName)
			rk.SetStringValue("HostName", HostName)

			i, err := strconv.Atoi(PortNumber)
			if err != nil {
				i, _ = strconv.Atoi(PORT)
			}
			rk.SetDWordValue("PortNumber", uint32(i))
		}
		// Для удобства
		rk.SetDWordValue("WarnOnClose", 0)
		rk.SetDWordValue("FullScreenOnAltEnter", 1)
		rk.Close()
	} else {
		Println(err)
	}
}

func PuttyHostCA(key, value string) {
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
