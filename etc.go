//go:build !windows
// +build !windows

package main

import (
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
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

// `ssh -p 2222 a@127.0.0.1 command`
// `ssh -p 2222 a@127.0.0.1 -T`
func NoPTY(s gl.Session) {
	args, cmdLine := ShArgs(s)
	e := winssh.Env(s, args[0])

	cmd := exec.Command(args[0], args[1:]...)
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
}

func puttyHostCA(id string, data []byte, pub ssh.PublicKey) {
}
