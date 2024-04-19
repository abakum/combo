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

	"github.com/abakum/go-console"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"golang.org/x/sys/windows"
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

// for shell and exec
func ShellOrExec(s gl.Session) {
	RemoteAddr := s.RemoteAddr()
	defer func() {
		ltf.Println(RemoteAddr, "done")
	}()

	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		NoPTY(s)
		return
	}
	// ssh -p 2222 a@127.0.0.1
	// ssh -p 2222 a@127.0.0.1 -t commands
	stdout, err := console.New(ptyReq.Window.Width, ptyReq.Window.Width)
	if err != nil {
		letf.Println("unable to create console", err)
		NoPTY(s)
		return
	}
	args, cmdLine := ShArgs(s)
	defer func() {
		ltf.Println(cmdLine, "done")
		if stdout != nil {
			// stdout.Close()
			stdout.Kill()
		}
	}()
	stdout.SetCWD(winssh.Home(s))
	stdout.SetENV(winssh.Env(s, args[0]))
	err = stdout.Start(args)
	if err != nil {
		letf.Println("unable to start", cmdLine, err)
		NoPTY(s)
		return
	}

	SetConsoleTitle(s)
	ppid, _ := stdout.Pid()
	ltf.Println(cmdLine, ppid)
	go func() {
		for {
			if stdout == nil || s == nil {
				return
			}
			select {
			case <-s.Context().Done():
				stdout.Close()
				return
			case win := <-winCh:
				ltf.Println("PTY SetSize", win)
				if win.Height == 0 && win.Width == 0 {
					stdout.Close()
					return
				}
				if err := stdout.SetSize(win.Width, win.Height); err != nil {
					letf.Println(err)
				}
			}
		}
	}()

	go io.Copy(stdout, s)
	io.Copy(s, stdout)
}

func quote(s string) string {
	if strings.Contains(s, " ") {
		return fmt.Sprintf(`"%s"`, s)
	}
	return s
}

// `ssh -p 2222 a@127.0.0.1 command`
// `ssh -p 2222 a@127.0.0.1 -T`
func NoPTY(s gl.Session) {
	args, cmdLine := ShArgs(s)
	e := winssh.Env(s, args[0])

	// cmd := exec.Command(args[0], args[1:]...)
	cmd := exec.Command(args[0])
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: cmdLine}
	cmd.Dir = winssh.Home(s)
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

// cmd as shell
func ShArgs(s gl.Session) (args []string, cmdLine string) {
	const SH = "cmd.exe"
	var err error
	for _, shell := range []string{
		os.Getenv("ComSpec"),
		SH,
	} {
		if cmdLine, err = exec.LookPath(shell); err == nil {
			break
		}
	}
	if err != nil {
		cmdLine = SH
	}
	args = []string{cmdLine}
	if s.RawCommand() != "" {
		args = append(args, "/c")
		args = append(args, s.RawCommand())
		cmdLine = fmt.Sprintf(`%s /c %s`, quote(args[0]), quote(s.RawCommand()))
	}
	return
}
