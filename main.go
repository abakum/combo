package main

/*
git clone https://github.com/abakum/combo
go mod init github.com/abakum/combo

go get internal/tool
go mod tidy
*/

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/abakum/embed-encrypt/encryptedfs"
	"github.com/abakum/menu"
	"github.com/abakum/pageant"

	version "github.com/abakum/version/lib"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sys/windows/registry"
)

var (
	_ = encryptedfs.ENC
	_ = version.Ver
)

//go:generate go run github.com/abakum/version
//go:generate go run cmd/main.go
//go:generate go run github.com/abakum/embed-encrypt
//go:generate go list -f '{{.EmbedFiles}}'

const (
	PORT     = "22"
	ALL      = "0.0.0.0"
	LH       = "127.0.0.1"
	FILEMODE = 0644
	DIRMODE  = 0755
	TOR      = time.Second * 15 //reconnect TO
	TOW      = time.Second * 5  //watch TO
	SSH2     = "SSH-2.0-"
	OSSH     = "OpenSSH_for_Windows"
	CGIR     = "-r"
)

//encrypted:embed internal/ca
var CA []byte // Ключ ЦС

//go:embed VERSION
var Ver string

var (
	Image,
	Imag,
	UserKnownHostsFile,
	_ string

	Ips            []string
	Signer         gl.Signer
	AuthorizedKeys []ssh.PublicKey
	CertCheck      *ssh.CertChecker
)

func main() {
	var (
		err error
		h   bool
	)

	Exe, err := os.Executable()
	Fatal(err)
	Image = filepath.Base(Exe)
	Imag = strings.Split(Image, ".")[0]

	Ips = interfaces()
	Println(runtime.GOOS, runtime.GOARCH, Imag, Ver, Ips)
	FatalOr("not connected - нет сети", len(Ips) == 0)

	key, err := x509.ParsePKCS8PrivateKey(CA)
	Fatal(err)

	Signer, err = ssh.NewSignerFromKey(key)
	Fatal(err)

	AuthorizedKeys = append(AuthorizedKeys, Signer.PublicKey())

	var Signers []ssh.Signer
	Signers, UserKnownHostsFile = getSigners(Signer, Imag, Imag)
	if len(Signers) < 3 {
		Fatal(fmt.Errorf("no keys from agent - не получены ключи от агента %v", err))
	}

	HostKeyFallback, err := knownhosts.New(filepath.Join(UserHomeDirs(".ssh"), "known_hosts"))
	if err != nil {
		Println(err)
	}
	CertCheck = &ssh.CertChecker{
		IsHostAuthority: func(p ssh.PublicKey, addr string) bool {
			return gl.KeysEqual(p, Signer.PublicKey())
		},
		HostKeyFallback: HostKeyFallback,
	}

	flag.BoolVar(&h, "h", h, fmt.Sprintf("show `help` for usage - показать использование параметров\nexample - пример `%s -h`", Image))
	flag.Parse()

	if h {
		fmt.Printf("Version %s of `%s [host[:port]] `\n", Ver, Image)
		flag.PrintDefaults()
		return
	}

	SetColor()

	Hp := flag.Arg(0)

	Hp = net.JoinHostPort(SplitHostPort(Hp, LH, PORT))

	defer closer.Close()
	closer.Bind(cleanup)

	for {
		server(Hp)
		winssh.KidsDone(os.Getpid())
		time.Sleep(TOR)
	}
}

func interfaces() (ips []string) {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifac := range ifaces {
			addrs, err := ifac.Addrs()
			if err != nil || ifac.Flags&net.FlagUp == 0 || ifac.Flags&net.FlagRunning == 0 || ifac.Flags&net.FlagLoopback != 0 {
				continue
			}
			for _, addr := range addrs {
				if strings.Contains(addr.String(), ":") {
					continue
				}
				ips = append(ips, strings.Split(addr.String(), "/")[0])
			}
		}
		slices.Reverse(ips)
	}
	return
}

func cleanup() {
	menu.PressAnyKey("Press any key - Нажмите любую клавишу", TOW)
	winssh.AllDone(os.Getpid())
}

func FingerprintSHA256(pubKey ssh.PublicKey) string {
	return pubKey.Type() + " " + ssh.FingerprintSHA256(pubKey)
}

// Возвращаем сигнеров от агента, и сертификаты от агента и самоподписанный сертификат ЦС.
// Пишем ветку реестра SshHostCAs для putty клиента и файл UserKnownHostsFile для ssh клиента чтоб они доверяли хосту по сертификату от ЦС caSigner.
// Если новый ключ ЦС (.ssh/ca.pub) или новый ключ от агента пишем сертификат в файл для ssh клиента и ссылку на него в реестр для putty клиента чтоб хост с ngrokSSH им доверял.
// Если новый ключ ЦС пишем конфиги и сертифкаты для sshd от OpenSSH чтоб sshd доверял клиентам ngrokSSH, putty, ssh.
func getSigners(caSigner ssh.Signer, id string, user string) (signers []ssh.Signer, userKnownHostsFile string) {
	// разрешения для сертификата пользователя
	var permits = make(map[string]string)
	for _, permit := range []string{
		"X11-forwarding",
		"agent-forwarding",
		"port-forwarding",
		"pty",
		"user-rc",
	} {
		permits["permit-"+permit] = ""
	}

	ss := []ssh.Signer{caSigner}
	// agent
	rw, err := NewConn()
	if err == nil {
		defer rw.Close()
		ea := agent.NewClient(rw)
		eas, err := ea.Signers()
		if err == nil {
			ss = append(ss, eas...)
		}
	}
	// в ss ключ ЦС caSigner и ключи от агента
	if len(ss) < 2 {
		Println(fmt.Errorf("no keys from agent - не получены ключи от агента %v", err))
	}
	sshUserDir := UserHomeDirs(".ssh")
	userKnownHostsFile = filepath.Join(sshUserDir, "known_ca")
	newCA := false
	for i, idSigner := range ss {
		signers = append(signers, idSigner)

		pub := idSigner.PublicKey()

		pref := "ca"
		if i > 0 {
			t := strings.TrimPrefix(pub.Type(), "ssh-")
			if strings.HasPrefix(t, "ecdsa") {
				t = "ecdsa"
			}
			pref = "id_" + t
		}

		data := ssh.MarshalAuthorizedKey(pub)
		name := filepath.Join(sshUserDir, pref+".pub")
		old, err := os.ReadFile(name)
		newPub := err != nil || !bytes.Equal(data, old)
		if i == 0 {
			newCA = newPub
		}
		if newPub {
			Println(name, os.WriteFile(name, data, FILEMODE))
			if i == 0 { // ca.pub know_ca idSigner is caSigner
				bb := bytes.NewBufferString("@cert-authority * ")
				bb.Write(data)
				// пишем файл UserKnownHostsFile для ssh клиента чтоб он доверял хосту по сертификату ЦС caSigner
				Println(userKnownHostsFile, os.WriteFile(userKnownHostsFile, bb.Bytes(), FILEMODE))
				// for putty ...they_verify_me_by_certificate
				// пишем ветку реестра SshHostCAs для putty клиента чтоб он доверял хосту по сертификату ЦС caSigner
				rk, _, err := registry.CreateKey(registry.CURRENT_USER,
					`SOFTWARE\SimonTatham\PuTTY\SshHostCAs\`+Imag,
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
		}
		mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner),
			[]string{caSigner.PublicKey().Type()})
		if err != nil {
			continue
		}
		//ssh-keygen -s ca -I id -n user -V always:forever ~\.ssh\id_*.pub
		certificate := ssh.Certificate{
			Key:             idSigner.PublicKey(),
			CertType:        ssh.UserCert,
			KeyId:           id,
			ValidBefore:     ssh.CertTimeInfinity,
			ValidPrincipals: []string{user},
			Permissions:     ssh.Permissions{Extensions: permits},
		}
		if certificate.SignCert(rand.Reader, mas) != nil {
			continue
		}

		certSigner, err := ssh.NewCertSigner(&certificate, idSigner)
		if err != nil {
			continue
		}
		// добавляем сертификат в слайс результата signers
		signers = append(signers, certSigner)

		if newCA || newPub {
			//если новый ключ ЦС или новый ключ от агента пишем сертификат в файл для ssh клиента и ссылку на него в реестр для putty клиента
			name = filepath.Join(sshUserDir, pref+"-cert.pub")
			err = os.WriteFile(name,
				ssh.MarshalAuthorizedKey(&certificate),
				FILEMODE)
			Println(name, err)
			if i == 1 {
				// пишем ссылку на один сертификат (первый) в ветку реестра ngrokSSH для putty клиента
				if err == nil {
					// for I_verify_them_by_certificate_they_verify_me_by_certificate
					// PuTTY -load ngrokSSH user@host
					forPutty(`SOFTWARE\SimonTatham\PuTTY\Sessions\`+Imag, name)
				}
				// PuTTY user@host
				forPutty(`SOFTWARE\SimonTatham\PuTTY\Sessions\Default%20Settings`, "")
			}
		}
	}
	return
}

// net.SplitHostPort со значениями по умолчанию
func SplitHostPort(hp, host, port string) (h, p string) {
	hp = strings.ReplaceAll(hp, "*", ALL)
	h, p, err := net.SplitHostPort(hp)
	if err == nil {
		if p == "" {
			p = port
		}
		if h == "" {
			h = host
		}
		return h, p
	}
	_, err = strconv.Atoi(hp)
	if err == nil {
		return host, hp
	}
	if hp == "" {
		hp = host
	}
	return hp, port
}

// Упрямый вариант
func UserHomeDirs(dirs ...string) (s string) {
	var err error
	s, err = os.UserHomeDir()
	if err != nil {
		s, err = os.UserConfigDir()
		if err != nil {
			s, _ = os.MkdirTemp("", "UserDir")
		}
	}
	dirs = append([]string{s}, dirs...)
	s = filepath.Join(dirs...)
	os.MkdirAll(s, 0700)
	return
}

// Пишем сертификат name в ветку реестра для putty клиента
func forPutty(key, name string) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER, key, registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		Println(err)
	}
	defer rk.Close()
	if name != "" {
		rk.SetStringValue("DetachedCertificate", name)
	}
	// Для удобства
	rk.SetDWordValue("WarnOnClose", 0)
	rk.SetDWordValue("FullScreenOnAltEnter", 1)
}

// Подключаемся к агенту
func NewConn() (sock net.Conn, err error) {
	const (
		PIPE         = `\\.\pipe\`
		sshAgentPipe = "openssh-ssh-agent"
	)
	// Get env "SSH_AUTH_SOCK" and connect.
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	emptySockPath := len(sockPath) == 0

	if emptySockPath {
		sock, err = pageant.NewConn()
	}

	if err != nil && !emptySockPath {
		// `sc query afunix` for some versions of Windows
		sock, err = net.Dial("unix", sockPath)
	}

	if err != nil {
		if emptySockPath {
			sockPath = sshAgentPipe
		}
		if !strings.HasPrefix(sockPath, PIPE) {
			sockPath = PIPE + sockPath
		}
		sock, err = winio.DialPipe(sockPath, nil)
	}
	return sock, err

}
