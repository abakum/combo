//go:build windows
// +build windows

package main

import (
	"path/filepath"
	"strconv"

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
func PuttySession(key string, keys, defs []string, values ...string) (err error) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER,
		filepath.Join(PuTTY, Sessions, key),
		registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer rk.Close()
	if len(values) > 0 {
		value := ""
		for i, k := range keys {
			if len(values) > i {
				value = values[i]
			} else {
				value = defs[i]
			}

			if i, err := strconv.Atoi(value); err == nil {
				rk.SetDWordValue(k, uint32(i))
			} else {
				rk.SetStringValue(k, value)
			}
		}
	}
	// Для удобства
	rk.SetDWordValue("WarnOnClose", 0)
	rk.SetDWordValue("FullScreenOnAltEnter", 1)
	return
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
