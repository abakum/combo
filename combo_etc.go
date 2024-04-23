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

// Пишем сертификат value для putty клиента
func PuttySessionCert(key, value string) {
	dir := path.Join(PuTTY, strings.ToLower(Sessions))
	os.MkdirAll(dir, 0700)
	name := path.Join(dir, key)
	p, err := properties.LoadFile(name, properties.UTF8)
	if err != nil {
		Println(err)
		p = properties.NewProperties()
	}
	p.SetValue("DetachedCertificate", value)
	f, err := os.Create(name)
	if err != nil {
		Println(err)
		return
	}
	defer f.Close()
	p.WriteSeparator = "="
	p.Write(f, properties.UTF8)
	f.Chmod(0644)
}

// Пишем user host port для putty клиента
func PuttySession(key string, values ...string) (err error) {
	dir := path.Join(PuTTY, strings.ToLower(Sessions))
	os.MkdirAll(dir, 0700)
	name := path.Join(dir, key)
	p, er := properties.LoadFile(name, properties.UTF8)
	if er != nil {
		p = properties.NewProperties()
	}
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
		p.SetValue("UserName", UserName)
		p.SetValue("HostName", HostName)
		p.SetValue("PortNumber", PortNumber)
		p.SetValue("Protocol", "ssh")
	}
	// Для удобства
	p.SetValue("WarnOnClose", 0)
	p.SetValue("FullScreenOnAltEnter", 1)
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
	err = f.Chmod(0644)
	return
}

func PuttyHostCA(key, value string) {
	dir := path.Join(PuTTY, strings.ToLower(SshHostCAs))
	os.MkdirAll(dir, 0700)
	name := path.Join(dir, key)
	p, err := properties.LoadFile(name, properties.UTF8)
	if err != nil {
		Println(err)
		p = properties.NewProperties()
	}
	p.SetValue("PublicKey", value)
	p.SetValue("Validity", "*")
	p.SetValue("PermitRSASHA1", 0)
	p.SetValue("PermitRSASHA256", 1)
	p.SetValue("PermitRSASHA512", 1)
	f, err := os.Create(name)
	if err != nil {
		Println(err)
		return
	}
	defer f.Close()
	p.WriteSeparator = "="
	p.Write(f, properties.UTF8)
	f.Chmod(0644)
}
