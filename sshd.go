package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/abakum/go-ansiterm"
	"github.com/abakum/go-netstat/netstat"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

// sshd
func server(Hp string) {
	ctxRWE, caRW := context.WithCancel(context.Background())
	defer caRW()

	ForwardedTCPHandler := &gl.ForwardedTCPHandler{}

	server := gl.Server{
		Addr: Hp,
		// next for ssh -R host:port:x:x
		ReversePortForwardingCallback: gl.ReversePortForwardingCallback(func(ctx gl.Context, host string, port uint32) bool {
			li.Println("Attempt to bind - Начать слушать", host, port, "granted - позволено")
			return true
		}),
		RequestHandlers: map[string]gl.RequestHandler{
			"tcpip-forward":        ForwardedTCPHandler.HandleSSHRequest, // to allow remote forwarding
			"cancel-tcpip-forward": ForwardedTCPHandler.HandleSSHRequest, // to allow remote forwarding
		},
		// before for ssh ssh -R host:port:x:x

		// next for ssh -L x:dhost:dport
		LocalPortForwardingCallback: gl.LocalPortForwardingCallback(func(ctx gl.Context, dhost string, dport uint32) bool {
			li.Println("Accepted forward - Разрешен перенос", dhost, dport)
			return true
		}),
		ChannelHandlers: map[string]gl.ChannelHandler{
			"session":      winssh.SessionHandler, // to allow agent forwarding
			"direct-tcpip": gl.DirectTCPIPHandler, // to allow local forwarding
		},
		// before for ssh -L x:dhost:dport

		SubsystemHandlers: map[string]gl.SubsystemHandler{
			"sftp":                  winssh.SubsystemHandlerSftp,  // to allow sftp
			winssh.AgentRequestType: winssh.SubsystemHandlerAgent, // to allow agent forwarding
		},
		SessionRequestCallback: SessionRequestCallback,
		// IdleTimeout:            -time.Second * 100, // send `keepalive` every 100 seconds
		// MaxTimeout:             -time.Second * 300, // сlosing the session after 300 seconds with no response
		Version: banner(),
	}

	// next for server key
	// server.AddHostKey(Signer)
	server.AddHostKey(certSigner(Signer, Signer, Imag)) //selfsigned ca
	// before for server key

	// next for client keys
	publicKeyOption := gl.PublicKeyAuth(func(ctx gl.Context, key gl.PublicKey) bool {
		Println("User", ctx.User(), "from", ctx.RemoteAddr())
		Println("key", FingerprintSHA256(key))
		if Authorized(key, AuthorizedKeys) {
			return true
		}

		cert, ok := key.(*ssh.Certificate)
		if !ok {
			return false
		}
		// next for certificate of client
		if cert.CertType != ssh.UserCert {
			Println(fmt.Errorf("ssh: cert has type %d", cert.CertType))
			return false
		}
		if !gl.KeysEqual(cert.SignatureKey, Signer.PublicKey()) {
			Println(fmt.Errorf("ssh: certificate signed by unrecognized authority %s", FingerprintSHA256(cert.SignatureKey)))
			return false
		}
		if err := CertCheck.CheckCert(Imag, cert); err != nil { //ctx.User()
			Println(err)
			return false
		}
		//  cert.Permissions
		Println("Authorized by certificate", FingerprintSHA256(cert.SignatureKey))
		return true

	})

	server.SetOption(publicKeyOption)
	// before for client keys

	gl.Handle(func(s gl.Session) {
		defer s.Exit(0)
		clientVersion := s.Context().ClientVersion()
		ltf.Println(clientVersion)
		if len(s.Command()) > 1 {
			base := filepath.Base(s.Command()[0])
			bas := strings.Split(base, ".")[0]
			if strings.EqualFold(bas, Imag) && s.Command()[1] == CGIR {
				caRW()
			}
		}
		if !strings.Contains(clientVersion, OSSH) {
			// Not for OpenSSH
			time.AfterFunc(time.Millisecond*333, func() {
				title := SetConsoleTitle(CutSSH2(s.Context().ClientVersion()) + "@" + CutSSH2(s.Context().ServerVersion()))
				s.Write([]byte(title))
			})
		}
		// winssh.ShellOrExec(s)
		ShellOrExec(s)
	})

	li.Printf("%s daemon waiting on - сервер ожидает на %s\n", Image, Hp)
	li.Println("to connect use - чтоб подключится используй", use(Hp))

	go func() {
		watch(ctxRWE, caRW, Hp)
		ltf.Println("local done")
		server.Close()
	}()
	go established(ctxRWE, Image)
	Println("ListenAndServe", server.ListenAndServe())
}

// Подписываем ключём ЦС caSigner замок хоста hostSigner и его принципал
func certSigner(caSigner, hostSigner ssh.Signer, id string) ssh.Signer {
	mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner), []string{caSigner.PublicKey().Type()})
	if err != nil {
		return hostSigner
	}
	certificate := ssh.Certificate{
		Key:         hostSigner.PublicKey(),
		CertType:    ssh.HostCert,
		KeyId:       id,
		ValidBefore: ssh.CertTimeInfinity,
	}
	err = certificate.SignCert(rand.Reader, mas)
	if err != nil {
		return hostSigner
	}
	certSigner, err := ssh.NewCertSigner(&certificate, hostSigner)
	if err != nil {
		return hostSigner
	}
	return certSigner
}

// Баннер без префикса SSH2
func CutSSH2(s string) string {
	after, _ := strings.CutPrefix(s, SSH2)
	return after

}

// Меняю заголовок окна у клиента
func SetConsoleTitle(s string) string {
	return fmt.Sprintf("%c]0;%s%c", ansiterm.ANSI_ESCAPE_PRIMARY, s, ansiterm.ANSI_BEL)
}

// Как запустить клиента
func use(hp string) (s string) {
	h, p, _ := net.SplitHostPort(hp)
	if p == PORT {
		p = ""
	}
	if h != ALL {
		return fmt.Sprintf("`ssh %s -o UserKnownHostsFile=%s`", strings.Trim(userName()+"@"+net.JoinHostPort(h, p), " :"), UserKnownHostsFile)
	}
	s = ""
	for _, h := range Ips {
		s += fmt.Sprintf("\n\t`ssh %s -o UserKnownHostsFile=%s`", strings.Trim(userName()+"@"+net.JoinHostPort(h, p), " :"), UserKnownHostsFile)
	}
	return
}

// call ca() and return on `Service has been discontinued`
func watch(ctx context.Context, ca context.CancelFunc, dest string) {
	if strings.HasPrefix(dest, ":") {
		dest = ALL + dest
	}
	old := -1
	ste_ := ""
	t := time.NewTicker(TOW)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			ste := ""
			new := netSt(func(s *netstat.SockTabEntry) bool {
				ok := s.State == netstat.Listen && s.LocalAddr.String() == dest
				if ok {
					ste += fmt.Sprintln("\t", s.LocalAddr, s.State)
				}
				return ok
			})
			if new == 0 {
				lt.Print("The service has been stopped - Служба остановлена\n\t", dest)
				if ca != nil {
					ca()
				}
				return
			}
			if old != new {
				if new > old {
					lt.Print("The service is running - Служба работает\n", ste)
				}
				ste_ = ste
				old = new
			}
			if ste_ != ste {
				lt.Print("The service has been changed - Служба сменилась\n", ste)
				ste_ = ste
			}
		case <-ctx.Done():
			Println("watch", dest, "done")
			return
		}
	}
}

// Что там с портами imagename
func established(ctx context.Context, imagename string) {
	old := 0
	ste_ := ""
	t := time.NewTicker(TOW)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			ste := ""
			new := netSt(func(s *netstat.SockTabEntry) bool {
				ok := s.Process != nil && s.Process.Name == imagename && s.State == netstat.Established
				if ok {
					ste += fmt.Sprintln("\t", s.LocalAddr, s.RemoteAddr, s.State)
				}
				return ok
			})
			if old != new {
				switch {
				case new == 0:
					lt.Println(imagename, "There are no connections - Нет подключений")
				case old > new:
					lt.Print(imagename, " Connections have decreased - Подключений уменьшилось\n", ste)
				default:
					lt.Print(imagename, " Connections have increased - Подключений увеличилось\n", ste)
				}
				ste_ = ste
				old = new
			}
			if ste_ != ste {
				lt.Print(imagename, " Сonnections have changed - Подключения изменились\n", ste)
				ste_ = ste
			}
		case <-ctx.Done():
			Println("established", imagename, "done")
			return
		}
	}
}

// func(s *netstat.SockTabEntry) bool {return s.State == a}
func netSt(accept netstat.AcceptFn) int {
	tabs, err := netstat.TCPSocks(accept)
	if err != nil {
		return 0
	}
	return len(tabs)
}

// logging sessions
func SessionRequestCallback(s gl.Session, requestType string) bool {
	if s == nil {
		return false
	}
	log.Println(s.RemoteAddr(), requestType, s.Command())
	return true
}

// is autorized
func Authorized(key gl.PublicKey, authorized []ssh.PublicKey) bool {
	for _, k := range authorized {
		if gl.KeysEqual(key, k) {
			Println("Authorized")
			return true
		}
	}
	return false
}
