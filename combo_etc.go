//go:build !windows
// +build !windows

package main

import (
	"os"
	"path"
	"strings"

	"github.com/abakum/winssh"
	"github.com/magiconair/properties"
)

var (
	PuTTY = winssh.UserHomeDirs(".putty")
)

// Пишем user host port для putty клиента
func PuttySession(key string, keys, defs []string, values ...string) (err error) {
	dir := path.Join(PuTTY, strings.ToLower(Sessions))
	os.MkdirAll(dir, 0700)
	name := path.Join(dir, key)
	p, er := properties.LoadFile(name, properties.UTF8)
	if er != nil {
		p = properties.NewProperties()
	}
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
		p.SetValue(k, value)
	}

	f, err := os.Create(name)
	if err != nil {
		return
	}
	defer f.Close()
	p.WriteSeparator = "="
	_, err = p.Write(f, properties.UTF8)
	if err != nil {
		return
	}
	err = f.Chmod(FILEMODE)
	return
}

func PuttyConf(name string, kv map[string]string) {
	os.MkdirAll(path.Dir(name), 0700)
	p, err := properties.LoadFile(name, properties.UTF8)
	if err != nil {
		Println(err)
		p = properties.NewProperties()
	}

	for k, v := range kv {
		p.SetValue(k, v)
	}

	f, err := os.Create(name)
	if err != nil {
		Println(err)
		return
	}
	defer f.Close()
	p.WriteSeparator = "="
	p.Write(f, properties.UTF8)
	f.Chmod(FILEMODE)
}
