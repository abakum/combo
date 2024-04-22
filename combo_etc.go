//go:build !windows
// +build !windows

package main

import (
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/magiconair/properties"
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
	dir := path.Join(UserHomeDirs(".putty"), strings.ToLower(Sessions))
	os.MkdirAll(dir, 0755)
	name := path.Join(dir, key)
	p, err := properties.LoadFile(name, properties.UTF8)
	if err != nil {
		Println(err)
		p = properties.NewProperties()
	}
	if value != "" {
		p.SetValue("DetachedCertificate", value)
	}
	// Для удобства
	p.SetValue("WarnOnClose", 0)
	p.SetValue("FullScreenOnAltEnter", 1)
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

func puttyHostCA(key, value string) {
	dir := path.Join(UserHomeDirs(".putty"), SshHostCAs)
	os.MkdirAll(dir, 0755)
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
