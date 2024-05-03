package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/abakum/go-netstat/netstat"
	"github.com/abakum/go-sshlib"
	"github.com/abakum/pageant"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	USER   = 1024
	SOCKS5 = "1080"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, strings.TrimSpace(strings.ReplaceAll(value, "*", ALL)))
	return nil
}

var (
	A, // агент
	E, // emulate ANSI
	X, // proXy
	a, // без агента
	_ bool
	L,
	R,
	_ arrayFlags
	S,
	_ string
)

func client(user, host, port, imag string, signers []ssh.Signer) {

	hostKeyFallback, err := knownhosts.New(filepath.Join(winssh.UserHomeDirs(".ssh"), "known_hosts"))
	if err != nil {
		Println(err)
	}
	certCheck := &ssh.CertChecker{
		IsHostAuthority: func(p ssh.PublicKey, addr string) bool {
			ok := gl.KeysEqual(p, signers[0].PublicKey())
			s := "was not"
			if ok {
				s = "is"
			}
			Println("host", addr, s, "authorized by cert", FingerprintSHA256(p))
			return ok
		},
		HostKeyFallback: hostKeyFallback,
	}

	con := &sshlib.Connect{
		ForwardAgent:    A,
		TTY:             true,
		HostKeyCallback: certCheck.CheckHostKey,
		Version:         winssh.Banner(),
		// KnownHostsFiles:     []string{filepath.Join(winssh.UserHomeDirs(".ssh"), "known_hosts")},
		// CheckKnownHosts:     true,
		// OverwriteKnownHosts: true,
	}

	Fatal(con.CreateClient(host, port, user, []ssh.AuthMethod{ssh.PublicKeys(signers...)}))

	serverVersion := string(con.Client.ServerVersion())
	Println(serverVersion)

	if con.ForwardAgent {
		rw, err := pageant.NewConn()
		if err == nil {
			defer rw.Close()
			con.Agent = agent.NewClient(rw)
		}
	}

	cmd := strings.Join(flag.Args()[1:], " ")

	VisitAll(user, host, port, imag, cmd)

	if cmd != "" {
		Println(cmd, con.CommandAnsi(cmd, E, strings.Contains(serverVersion, OSSH)))
		return
	}

	if actual(flag.CommandLine, "S") {
		i5, err := strconv.Atoi(S)
		if err == nil && !isListen("", i5, 0) {
			L = append(L, S)
			// gosysproxy.SetGlobalProxy("socks=" + net.JoinHostPort(LH, S))
			if X {
				setX("all_proxy", "socks://"+net.JoinHostPort(LH, S))
				Println("setX", "all_proxy", "socks://"+net.JoinHostPort(LH, S))
			}
			closer.Bind(func() {
				// gosysproxy.Off()
				if X {
					setX("all_proxy", "")
					Println("setX", "all_proxy", "")
				}
			})
		}
	}

	for _, o := range L {
		tryBindL(imag, con, parseHPHP(o, USER)...)
	}

	for _, o := range R {
		tryBindR(imag, con, parseHPHP(o, USER)...)
	}

	ska(con)
	con.ShellAnsi(nil, E)
}

func quote(s string) string {
	if strings.Contains(s, " ") {
		return fmt.Sprintf(`"%s"`, s)
	}
	return s
}

// KeepAlive for portforward
func ska(con *sshlib.Connect) {
	if isListen("", 0, os.Getpid()) {
		session, err := con.CreateSession()
		if err != nil {
			return
		}
		con.SendKeepAliveInterval = 100
		con.SendKeepAliveMax = 3
		go con.SendKeepAlive(session)
	}
}

func tryBindL(imag string, con *sshlib.Connect, hp ...string) (hphp []string, err error) {
	hphp = hp[:]
	err = fmt.Errorf("empty")
	if con == nil {
		return
	}
	if len(hphp) < 2 {
		hphp = []string{LH, strconv.Itoa(USER)}
	}
	p, er := strconv.Atoi(hphp[1])
	if er != nil {
		p = USER
	}
	if len(hphp) > 2 {
		for i := 0; i < 10; i++ {
			hphp[1] = strconv.Itoa(p)
			err = con.TCPLocalForward(net.JoinHostPort(hphp[0], hphp[1]), net.JoinHostPort(hphp[2], hphp[3]))
			Println(imag, "-L", strings.Join(hphp, ":"), err)
			if err == nil {
				return
			}
			p++
		}
		return
	}
	go func() {
		ltf.Printf("%s -D %s:%s\n", imag, hphp[0], hphp[1])
		con.TCPDynamicForward(hphp[0], hphp[1])
	}()
	return
}

func tryBindR(imag string, con *sshlib.Connect, hp ...string) (hphp []string, err error) {
	hphp = hp[:]
	err = fmt.Errorf("empty")
	if con == nil {
		return
	}
	if len(hphp) < 2 {
		hphp = []string{LH, strconv.Itoa(USER)}
	}
	p, er := strconv.Atoi(hphp[1])
	if er != nil {
		p = USER
	}
	if len(hphp) > 2 {
		for i := 0; i < 10; i++ {
			hphp[1] = strconv.Itoa(p)
			err = con.TCPRemoteForward(net.JoinHostPort(hphp[0], hphp[1]), net.JoinHostPort(hphp[2], hphp[3]))
			Println(imag, "-R", strings.Join(hphp, ":"), err)
			if err == nil {
				return
			}
			p++
		}
		return
	}
	go func() {
		ltf.Printf("%s -R %s:%s\n", imag, hphp[0], hphp[1])
		con.TCPReverseDynamicForward(hphp[0], hphp[1])
	}()
	return
}

// return h:p:h:p or h:p then need cgi
func parseHPHP(opt string, port int) (res []string) {
	bp := strconv.Itoa(port)
	if opt == "" {
		opt = LH
	}
	hphp := strings.Split(opt, ":")
	if len(hphp) > 0 && hphp[0] == "" { // :
		hphp[0] = LH
	}

	_, er := strconv.Atoi(hphp[0])
	if er == nil { // port
		hphp = append([]string{LH}, hphp...)
	}
	// h:p:h:p || h:p || h
	if len(hphp) > 1 && hphp[1] == "" {
		hphp[1] = bp
	}
	if len(hphp) > 2 && hphp[2] == "" {
		hphp[2] = LH
	}
	// Println(hphp, len(hphp))
	switch {
	case len(hphp) > 3: // h:p:h:p
		if hphp[2] == "" { // h:p: -> h:p:LH
			hphp[2] = LH
		}
		if hphp[3] == "" { // h:p:h: -> h:p:h:p
			hphp[3] = hphp[1]
		}
		return hphp[:4]
	case len(hphp) > 2: // h:p:h -> h:p:h:p
		return append(hphp, hphp[1])
	case len(hphp) > 1: // h:p -> cgi
		return hphp
	default: // h -> cgi
		return append(hphp, bp)
	}
}

func setX(key, val string) {
	set := exec.Command("setx", key, val)
	Println(fmt.Sprintf(`%s>%s %s`, "Run", quote(set.Args[0]), strings.Join(set.Args[1:], " ")), set.Run())
}

func clientOpt(imag string) {
	flag.BoolVar(&A, "A", false, fmt.Sprintf("`enable authentication agent` forwarding as - перенос авторизации как `ssh -A`\nexample - пример `%s -A`", imag))
	flag.BoolVar(&E, "E", false, fmt.Sprintf("`ansi` emulate - помочь консоли поддерживать ansi последовательности\nexample - пример `%s -E`", imag))
	flag.Var(&L, "L", fmt.Sprintf("`local` port forwarding as - перенос ближнего порта как `ssh -L [bindHost:]bindPort[:dialHost:dialPort]` or\nlocal socks5 proxy as `ssh -D [bindHost:]bindPort`\nexample - пример `%s -L 80:0.0.0.0:80`", imag))
	flag.Var(&R, "R", fmt.Sprintf("`remote` port forwarding as - перенос дальнего порта как `ssh -R [bindHost:]bindPort:dialHost:dialPort` or\nremote socks5 proxy  as `ssh -R [bindHost:]bindPort`\nexample - пример `%s -R *:80::80`", imag))
	flag.StringVar(&S, "S", SOCKS5, fmt.Sprintf("port for proxy - порт для прокси `Socks5`\nexample - пример `%s -S 8080`", imag))
	if runtime.GOOS == "windows" {
		flag.BoolVar(&X, "X", X, fmt.Sprintf("set by - устанавливать с помощью `setX` all_proxy\nexample - пример `%s -X`", imag))
	}
	flag.BoolVar(&a, "a", false, fmt.Sprintf("`disable authentication agent` forwarding as - не переносить авторизацию как `ssh -a`\nexample - пример `%s -a`", imag))
}

func actual(fs *flag.FlagSet, fn string) bool {
	return reflect.Indirect(reflect.ValueOf(fs)).FieldByName("actual").MapIndex(reflect.ValueOf(fn)).IsValid()
}

func isListen(host string, port int, pid int) (ok bool) {
	up := uint16(port)
	tabs, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen && (host == "" || host == s.LocalAddr.IP.String()) && (s.LocalAddr.Port == up || s.Process != nil && s.Process.Pid == pid)
	})
	return err == nil && len(tabs) > 0
}

func VisitAll(u, h, p, imag, cmd string) {
	o := ""
	flag.VisitAll(func(f *flag.Flag) {
		minus := "-"
		if actual(flag.CommandLine, f.Name) {
			minus += minus
		}
		if f.Name != "l" {
			o += fmt.Sprintf("%s%s=%s ", minus, f.Name, f.Value)
		}
	})
	ltf.Printf("%s %s%s %s\n", imag, o, strings.TrimSuffix(u+"@"+h+":"+p, ":"+PORT), cmd)
}
