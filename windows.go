//go:build windows
// +build windows

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
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

// `ssh -p 2222 a@127.0.0.1 command`
// `ssh -p 2222 a@127.0.0.1 -T`
func NoPTY(s gl.Session) {
	args, cmdLine := ShArgs(s)
	e := winssh.Env(s, args[0])

	cmd := exec.Command(args[0])
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: cmdLine}
	cmd.Dir = Home(s)
	cmd.Env = append(os.Environ(), e...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		letf.Println("unable to open stdout pipe", err)
		return
	}

	cmd.Stderr = cmd.Stdout

	stdin, err := cmd.StdinPipe()
	if err != nil {
		letf.Println("unable to open stdin pipe", err)
		return
	}

	err = cmd.Start()
	if err != nil {
		letf.Println("could not start", cmdLine, err)
		return
	}
	ppid := cmd.Process.Pid
	ltf.Println(cmdLine, ppid)

	go func() {
		<-s.Context().Done()
		stdout.Close()
	}()

	go io.Copy(stdin, s)
	go io.Copy(s, stdout)
	ltf.Println(cmdLine, "done", cmd.Wait())
}

// Пишем сертификат value в ветку реестра для putty клиента
func puttySession(key, value string) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER, key, registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		Println(err)
	}
	defer rk.Close()
	if value != "" {
		rk.SetStringValue("DetachedCertificate", value)
	}
	// Для удобства
	rk.SetDWordValue("WarnOnClose", 0)
	rk.SetDWordValue("FullScreenOnAltEnter", 1)
}

func puttyHostCA(id string, data []byte, pub ssh.PublicKey) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER,
		`SOFTWARE\SimonTatham\PuTTY\SshHostCAs\`+id,
		registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err == nil {
		rk.SetStringValue("PublicKey", strings.TrimSpace(strings.TrimPrefix(string(data), pub.Type())))
		rk.SetStringValue("Validity", "*")
		rk.SetDWordValue("PermitRSASHA1", 0)
		rk.SetDWordValue("PermitRSASHA256", 1)
		rk.SetDWordValue("PermitRSASHA512", 1)
		rk.Close()
	} else {
		Println(err)
	}
}
