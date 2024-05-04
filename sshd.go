package main

import (
	"context"
	"crypto/rand"
	"fmt"
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

// Сервер sshd.
// hp хост:порт,
// imag имя в сертификате,
// signer ключ ЦС,
// authorizedKeys замки разрешённых пользователей,
// CertCheck имя разрешённого пользователя в сертификате.
func server(h, p, imag, use string, signer ssh.Signer) { //, authorizedKeys []gl.PublicKey

	authorizedKeys := FileToAuthorized(filepath.Join(SshUserDir, "authorized_keys"), signer.PublicKey())

	ctxRWE, caRW := context.WithCancel(context.Background())
	defer caRW()

	ForwardedTCPHandler := &gl.ForwardedTCPHandler{}

	server := gl.Server{
		Addr: net.JoinHostPort(h, p),
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
		SessionRequestCallback: winssh.SessionRequestCallback,
		// IdleTimeout:            -time.Second * 100, // send `keepalive` every 100 seconds
		// MaxTimeout:             -time.Second * 300, // сlosing the session after 300 seconds with no response
		Version: winssh.Banner(imag, Ver),
	}

	// next for server key
	// server.AddHostKey(Signer)
	server.AddHostKey(certSigner(signer, signer, imag)) //selfsigned ca
	// before for server key

	// next for client keys
	publicKeyOption := gl.PublicKeyAuth(func(ctx gl.Context, key gl.PublicKey) bool {
		Println("User", ctx.User(), "from", ctx.RemoteAddr())
		ok := winssh.Authorized(key, authorizedKeys)
		s := "was not"
		if ok {
			s = "is"
		}
		Println(s, "authorised by key", FingerprintSHA256(key))
		if ok {
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
		if !gl.KeysEqual(cert.SignatureKey, signer.PublicKey()) {
			Println(fmt.Errorf("ssh: certificate signed by unrecognized authority %s", FingerprintSHA256(cert.SignatureKey)))
			return false
		}
		certCheck := &ssh.CertChecker{}
		if err := certCheck.CheckCert(imag, cert); err != nil { //ctx.User()
			Println(err)
			return false
		}
		//  cert.Permissions
		Println("is authorized by certificate", FingerprintSHA256(cert.SignatureKey))
		return true

	})

	server.SetOption(publicKeyOption)
	// before for client keys

	gl.Handle(func(s gl.Session) {
		defer s.Exit(0)
		clientVersion := s.Context().ClientVersion()
		ltf.Println(clientVersion)
		if len(s.Command()) == 2 && s.Command()[0] == imag && s.Command()[1] == RESET {
			caRW()
		}
		winssh.ShellOrExec(s)
	})

	li.Printf("%s daemon waiting on - сервер ожидает на %s\n", imag, server.Addr)
	li.Println("to connect use - чтоб подключится используй", use)

	go func() {
		watch(ctxRWE, caRW, server.Addr)
		ltf.Println("local done")
		server.Close()
	}()
	go established(ctxRWE, server.Addr)
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
func SetConsoleTitle(s gl.Session) {
	clientVersion := s.Context().ClientVersion()
	if s.RawCommand() == "" && !strings.Contains(clientVersion, OSSH) {
		// Not for OpenSSH_for_Windows
		time.AfterFunc(time.Millisecond*333, func() {
			title := fmt.Sprintf("%c]0;%s%c", ansiterm.ANSI_ESCAPE_PRIMARY, CutSSH2(clientVersion)+"@"+CutSSH2(s.Context().ServerVersion()), ansiterm.ANSI_BEL)
			s.Write([]byte(title))
		})
	}
}

// call ca() and return on `Service has been stopped`
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
			new, ste := netSt(func(s *netstat.SockTabEntry) bool {
				return s.State == netstat.Listen && s.LocalAddr.String() == dest
			})
			if new == 0 {
				ltf.Print("The service has been stopped - Служба остановлена\n\t", dest)
				if ca != nil {
					ca()
				}
				return
			}
			if old != new {
				if new > old {
					ltf.Print("The service is running - Служба работает\n", ste)
				}
				ste_ = ste
				old = new
			}
			if ste_ != ste {
				ltf.Print("The service has been changed - Служба сменилась\n", ste)
				ste_ = ste
			}
		case <-ctx.Done():
			Println("watch", dest, "done")
			return
		}
	}
}

// Что там с подключениями к dest
func established(ctx context.Context, dest string) {
	old := 0
	ste_ := ""
	t := time.NewTicker(TOW)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			new, ste := netSt(func(s *netstat.SockTabEntry) bool {
				return s.State == netstat.Established && s.LocalAddr.String() == dest
			})
			if old != new {
				switch {
				case new == 0:
					ltf.Println(dest, "There are no connections - Нет подключений")
				case old > new:
					ltf.Print(dest, " Connections have decreased - Подключений уменьшилось\n", ste)
				default:
					ltf.Print(dest, " Connections have increased - Подключений увеличилось\n", ste)
				}
				ste_ = ste
				old = new
			}
			if ste_ != ste {
				ltf.Print(dest, " Сonnections have changed - Подключения изменились\n", ste)
				ste_ = ste
			}
		case <-ctx.Done():
			Println("established", dest, "done")
			return
		}
	}
}

// Согласно фильтру accept возвращает количество i и список s
func netSt(accept netstat.AcceptFn) (i int, s string) {
	tabs, err := netstat.TCPSocks(accept)
	if err != nil {
		return
	}
	for _, tab := range tabs {
		s += "\t" + tab.String() + "\n"
	}
	i = len(tabs)
	return
}
