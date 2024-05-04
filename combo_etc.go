//go:build !windows
// +build !windows

package main

import (
	"bufio"
	"os"
	"path"
	"strings"

	"github.com/abakum/winssh"
)

var (
	PuTTY       = winssh.UserHomeDirs(".putty")
	Sessions    = path.Join(PuTTY, "sessions")
	SshHostCAs  = path.Join(PuTTY, "sshhostcas")
	SshHostKeys = path.Join(PuTTY, "sshhostkeys")
)

// Пишем user host port для putty клиента
func PuttySession(key string, keys, defs []string, values ...string) (err error) {
	name := path.Join(Sessions, key)
	p := confToMap(name, EQ)
	for i, k := range keys {
		if k == "" {
			continue
		}
		value := defs[i]
		if len(values) > i {
			value = values[i]
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
		p[k] = value
	}
	return mapToConf(name, EQ, p)
}

func confToMap(name, separator string) (kv map[string]string) {
	kv = make(map[string]string)
	file, err := os.Open(name)
	if err != nil {
		Println(err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := scanner.Text()
		if s == "" {
			continue
		}
		ss := strings.Split(s, separator)
		v := ""
		if len(ss) > 1 {
			v = ss[1]
		}
		kv[ss[0]] = v
	}
	return
}

func mapToConf(name, separator string, p map[string]string) (err error) {
	os.MkdirAll(path.Dir(name), 0700)
	f, err := os.Create(name)
	if err != nil {
		return
	}
	defer f.Close()
	defer f.Chmod(FILEMODE)
	for k, v := range p {
		_, err = f.WriteString(k + separator + v + "\n")
		if err != nil {
			return
		}
	}
	return
}

func PuttyConf(name, separator string, kv map[string]string) {
	p := confToMap(name, separator)
	for k, v := range kv {
		if k == "" {
			continue
		}
		p[k] = v
	}
	mapToConf(name, separator, p)
}
