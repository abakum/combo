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

func main() {
	var (
		h bool
	)

	Exe, err := os.Executable()
	Fatal(err)
	image := filepath.Base(Exe)
	imag := strings.Split(image, ".")[0]

	ips := ints()
	Println(runtime.GOOS, runtime.GOARCH, imag, Ver, ips)
	FatalOr("not connected - нет сети", len(ips) == 0)

	key, err := x509.ParsePKCS8PrivateKey(CA)
	Fatal(err)

	signer, err := ssh.NewSignerFromKey(key)
	Fatal(err)

	authorizedKeys := FileToAuthorized(filepath.Join(UserHomeDirs(".ssh"), "authorized_keys"), signer.PublicKey())
	getSigners(signer, imag, imag)

	hostKeyFallback, err := knownhosts.New(filepath.Join(UserHomeDirs(".ssh"), "known_hosts"))
	if err != nil {
		Println(err)
	}
	certCheck := &ssh.CertChecker{
		IsHostAuthority: func(p ssh.PublicKey, addr string) bool {
			return gl.KeysEqual(p, signer.PublicKey())
		},
		HostKeyFallback: hostKeyFallback,
	}

	flag.BoolVar(&h, "h", h, fmt.Sprintf("show `help` for usage - показать использование параметров\nexample - пример `%s -h`", image))
	flag.Parse()

	if h {
		fmt.Printf("Version %s of `%s [host[:port]] `\n", Ver, image)
		flag.PrintDefaults()
		return
	}

	SetColor()

	hp := flag.Arg(0)

	hp = net.JoinHostPort(SplitHostPort(hp, LH, PORT))

	defer closer.Close()
	closer.Bind(cleanup)

	for {
		server(hp, imag, image, use(hp, imag, ips...), signer, authorizedKeys, certCheck)
		winssh.KidsDone(os.Getpid())
		time.Sleep(TOR)
	}
}

func ints() (ips []string) {
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

// Время модификации
func ModTime(name string) (unix int64) {
	info, err := os.Stat(name)
	if err == nil {
		unix = info.ModTime().Unix()
	}
	return
}

// Возвращаем сигнеров от агента, и сертификаты от агента и самоподписанный сертификат ЦС.
// Пишем ветку реестра SshHostCAs для putty клиента и файл UserKnownHostsFile для ssh клиента чтоб они доверяли хосту по сертификату от ЦС caSigner.
// Если новый ключ ЦС (.ssh/ca.pub) или новый ключ от агента пишем сертификат в файл для ssh клиента и ссылку на него в реестр для putty клиента чтоб хост с ngrokSSH им доверял.
// Если новый ключ ЦС пишем конфиги и сертифкаты для sshd от OpenSSH чтоб sshd доверял клиентам putty, ssh.
func getSigners(caSigner ssh.Signer, id string, principals ...string) (signers []ssh.Signer, userKnownHostsFile string) {
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
	userKnownHostsFile = filepath.Join(sshUserDir, id)
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
		var mtCA int64
		if i == 0 { // CA
			newCA = newPub
		}
		if newPub {
			Println(name, os.WriteFile(name, data, FILEMODE))
			if i == 0 { // ca.pub  idSigner is caSigner
				bb := bytes.NewBufferString("@cert-authority * ")
				bb.Write(data)
				// пишем файл UserKnownHostsFile для ssh клиента чтоб он доверял хосту по сертификату ЦС caSigner
				Println(userKnownHostsFile, os.WriteFile(userKnownHostsFile, bb.Bytes(), FILEMODE))
				// for putty ...they_verify_me_by_certificate
				// пишем ветку реестра SshHostCAs для putty клиента чтоб он доверял хосту по сертификату ЦС caSigner
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
		}
		mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner),
			[]string{caSigner.PublicKey().Type()})
		if err != nil {
			continue
		}
		//ssh-keygen -s ca -I id -n user -V forever ~\.ssh\id_*.pub
		certificate := ssh.Certificate{
			Key:             idSigner.PublicKey(),
			CertType:        ssh.UserCert,
			KeyId:           id,
			ValidBefore:     ssh.CertTimeInfinity,
			ValidPrincipals: principals,
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

		if i == 0 { // CA
			mtCA = ModTime(name)
		}

		//если новый ключ ЦС или новый ключ от агента пишем сертификат в файл для ssh клиента и ссылку на него в реестр для putty клиента
		name = filepath.Join(sshUserDir, pref+"-cert.pub")
		if newCA || newPub || mtCA > ModTime(name) {
			err = os.WriteFile(name,
				ssh.MarshalAuthorizedKey(&certificate),
				FILEMODE)
			Println(name, err)
			if i == 1 {
				// пишем ссылку на один сертификат (первый) в ветку реестра ngrokSSH для putty клиента
				if err == nil {
					// for I_verify_them_by_certificate_they_verify_me_by_certificate
					// PuTTY -load ngrokSSH user@host
					forPutty(`SOFTWARE\SimonTatham\PuTTY\Sessions\`+id, name)
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

// Пишем сертификат value в ветку реестра для putty клиента
func forPutty(key, value string) {
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

func useLine(h, p, imag string) string {
	return fmt.Sprintf(
		"\n\t`ssh -o UserKnownHostsFile=~/.ssh/%s %s@%s%s`"+
			"\n\t`PuTTY -load %s %s@%s%s`",
		imag, userName(), h, pp("p", p, p == PORT),
		imag, userName(), h, pp("P", p, p == PORT),
	)
}

// Как запускать клиентов
func use(hp, imag string, ips ...string) (s string) {
	h, p, _ := net.SplitHostPort(hp)
	s = useLine(h, p, imag)
	if h != ALL {
		return
	}
	s = ""
	for _, h := range ips {
		s += useLine(h, p, imag)
	}
	return
}

// Читаю name и добавляю замки из in в authorized
func FileToAuthorized(name string, in ...ssh.PublicKey) (authorized []ssh.PublicKey) {
	authorizedKeysMap := map[string]ssh.PublicKey{}
	for _, pubKey := range in {
		authorizedKeysMap[string(pubKey.Marshal())] = pubKey
	}
	authorizedKeysBytes, err := os.ReadFile(name)
	if err == nil {
		for len(authorizedKeysBytes) > 0 {
			pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
			if err == nil {
				authorizedKeysMap[string(pubKey.Marshal())] = pubKey
				authorizedKeysBytes = rest
			}
		}
	}
	for _, pubKey := range authorizedKeysMap {
		authorized = append(authorized, pubKey)
	}
	return
}

// Если empty то пусто иначе -key val
func pp(key, val string, empty bool) string {
	if empty {
		return ""
	}
	return " -" + key + strings.TrimRight(" "+val, " ")
}
