//go:build windows
// +build windows

package main

import (
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

var (
	PuTTY = `SOFTWARE\SimonTatham\PuTTY`
)

// Пишем user host port для putty клиента
func PuttySession(key string, keys, defs []string, values ...string) (err error) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER,
		filepath.Join(PuTTY, Sessions, key),
		registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer rk.Close()
	value := ""
	for i, k := range keys {
		if len(values) > i {
			value = values[i]
		} else {
			value = defs[i]
		}

		if k == "ProxyHost" {
			if value == "" {
				defs[ProxyI] = "0"
				defs[ProxyI+1] = "_"
				defs[ProxyI+2] = defs[2]
			} else {
				defs[ProxyI] = "6"
				ss := strings.Split(value, "@")
				if len(ss) > 1 {
					defs[ProxyI+1] = ss[0]
					value = ss[1]
				}
				ss = strings.Split(value, ":")
				if len(ss) > 1 {
					value = ss[0]
					defs[ProxyI+2] = ss[1]
				}
			}
		}
		if i, err := strconv.Atoi(value); err == nil {
			rk.SetDWordValue(k, uint32(i))
		} else {
			rk.SetStringValue(k, value)
		}
	}
	return
}

func PuttyConf(name string, kv map[string]string) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER,
		name,
		registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		Println(err)
		return
	}
	defer rk.Close()

	for k, v := range kv {
		if i, err := strconv.Atoi(v); err == nil {
			rk.SetDWordValue(k, uint32(i))
		} else {
			rk.SetStringValue(k, v)
		}
	}
}
