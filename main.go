package main

/*
git clone https://github.com/abakum/combo
go mod init github.com/abakum/combo

Для VScode через ssh копируем internal и *.enc на хост с sshd
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
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/abakum/embed-encrypt/encryptedfs"
	"github.com/abakum/menu"
	"github.com/abakum/pageant"
	"github.com/abakum/winssh"
	"github.com/freman/putty_hosts"
	"github.com/kevinburke/ssh_config"

	version "github.com/abakum/version/lib"
	gl "github.com/gliderlabs/ssh"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

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
	RESET    = "-r"
	SERVEO   = "serveo"
	SNET     = "serveo.net"
	EQ       = "="
)

var (
	_    = encryptedfs.ENC
	_    = version.Ver
	Keys = []string{
		"UserName",
		"HostName",
		"PortNumber",
		"AgentFwd",
		"ProxyHost",

		"Protocol",
		"WarnOnClose",
		"FullScreenOnAltEnter",
		"TerminalType",
		"ProxyMethod",
		"ProxyUsername",
		"ProxyPort",
	}
	Defs = []string{
		winssh.UserName(), //0
		LH,                //1
		PORT,              //2
		"0",               //3
		"",                //4

		"ssh",            //5
		"0",              //6
		"1",              //7
		"xterm-256color", //8
		"0",              //9
		"",               //10
		PORT,             //11
	}
	ProxyI = 9
)

//go:generate go run github.com/abakum/version
//go:generate go run cmd/main.go
//go:generate go run github.com/abakum/embed-encrypt
//go:generate go list -f '{{.EmbedFiles}}'

//encrypted:embed internal/ca
var CA []byte // Ключ ЦС

//go:embed VERSION
var Ver string

func main() {
	var (
		help bool
	)
	SetColor()
	exe, err := os.Executable()
	Fatal(err)
	imag := strings.Split(filepath.Base(exe), ".")[0]

	ips := ints()
	Println(runtime.GOOS, runtime.GOARCH, exe, Ver, ips)
	FatalOr("not connected - нет сети", len(ips) == 0)

	key, err := x509.ParsePKCS8PrivateKey(CA)
	Fatal(err)

	signer, err := ssh.NewSignerFromKey(key)
	Fatal(err)

	// Signers для клиента
	signers, _ := getSigners(signer, imag, imag)

	flag.BoolVar(&help, "h", help, fmt.Sprintf(
		"show `help` for usage - показать использование параметров\n"+
			"example - пример `%s :2222` как 127.0.0.1:2222\n"+
			"`%s *` как 0.0.0.0:22\n"+
			"`%s` как 127.0.0.1:22\n"+
			"`%s _` как первый интерфейс например 192.168.0.1:22\n",
		imag,
		imag,
		imag,
		imag,
	))
	// для клиента
	clientOpt(imag)
	flag.Parse()

	if help {
		fmt.Printf("Version %s of `%s [user@][host][:port] `\n", Ver, imag)
		flag.PrintDefaults()
		return
	}

	u, h, p := uhp(flag.Arg(0), LH, PORT, ips...)
	s := use(u, h, p, imag, ips...)
	if strings.Contains(flag.Arg(0), "@") {
		if strings.HasPrefix(flag.Arg(0), "@") {
			session := strings.TrimPrefix(flag.Arg(0), "@")
			if session != "" {
				u, h, p, err = uhpSession(session)
				Fatal(err)
				s = use(u, h, p, imag, ips...)
			}
		}
		Println(s)
		client(u, h, p, imag, signers)
		return
	}

	defer closer.Close()
	closer.Bind(cleanup)

	for {
		server(h, p, imag, s, signer) //, authorizedKeys
		winssh.KidsDone(os.Getpid())
		time.Sleep(TOR)
	}
}

func uhp(uhp, dh, dp string, ips ...string) (u, h, p string) {
	ss := strings.Split(uhp, "@")
	u = winssh.UserName()
	hp := uhp
	if len(ss) > 1 {
		if ss[0] != "" {
			u = ss[0]
		}
		hp = ss[1]
	}
	h, p = SplitHostPort(hp, dh, dp)
	if h == "_" && len(ips) > 0 {
		h = ips[0]
	}
	return
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
	if runtime.GOOS == "windows" {
		menu.PressAnyKey("Press any key - Нажмите любую клавишу", TOW)
	}
	winssh.KidsDone(os.Getpid())
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
	rw, err := pageant.NewConn()
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
	sshUserDir := winssh.UserHomeDirs(".ssh")
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
				// пишем SshHostCAs для putty клиента чтоб он доверял хосту по сертификату ЦС caSigner
				// PuttyHostCA(id, strings.TrimSpace(strings.TrimPrefix(string(data), pub.Type())))
				PuttyConf(filepath.Join(SshHostCAs, id), EQ, map[string]string{
					"PublicKey":       strings.TrimSpace(strings.TrimPrefix(string(data), pub.Type())),
					"Validity":        "*",
					"PermitRSASHA1":   "0",
					"PermitRSASHA256": "1",
					"PermitRSASHA512": "1",
				})
			}
		}
		mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner),
			[]string{caSigner.PublicKey().Type()})
		if err != nil {
			Println(err)
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
			Println(err)
			continue
		}

		certSigner, err := ssh.NewCertSigner(&certificate, idSigner)
		if err != nil {
			Println(err)
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
				// пишем ссылку на один сертификат (первый) в ветку реестра id для putty клиента
				if err == nil {
					// for I_verify_them_by_certificate_they_verify_me_by_certificate
					// PuTTY -load id user@host
					// Пишем сертификат value для putty клиента
					// PuttySessionCert(id, name)
					PuttyConf(filepath.Join(Sessions, id), EQ, map[string]string{"DetachedCertificate": name})
					// PuttySessionCert(SERVEO, name)
					PuttyConf(filepath.Join(Sessions, SERVEO), EQ, map[string]string{"DetachedCertificate": name})
				}
				// PuTTY
				PuttySession("Default%20Settings", Keys, Defs)
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

func useLine(load, u, h, p string) string {
	return fmt.Sprintf(
		"\n\t`%s %s@%s:%s`"+
			"\n\t`ssh -o UserKnownHostsFile=~/.ssh/%s %s@%s%s`"+
			"\n\t`putty -load %s %s@%s%s`",
		load, u, h, p,
		load, u, h, pp("p", p, p == PORT),
		load, u, h, pp("P", p, p == PORT),
	)
}
func useLineShort(load string) string {
	return fmt.Sprintf(
		"\n\t`ssh %s`"+
			"\n\t`putty @%s`"+
			"\n\t`plink -load %s -no-antispoof`",
		load,
		load,
		load,
	)
}

func uhpSession(alias string) (u, h, p string, err error) {
	name := path.Join(winssh.UserHomeDirs(".ssh"), "config")
	bs, err := os.ReadFile(name)
	if err != nil {
		return
	}
	cfg, err := ssh_config.DecodeBytes(bs)
	if err != nil {
		return
	}
	u, err = cfg.Get(alias, "user")
	if err != nil {
		return
	}
	if u == "" {
		u = winssh.UserName()
	}

	h, err = cfg.Get(alias, "hostname")
	if err != nil {
		return
	}
	if h == "" {
		p = LH
	}

	p, err = cfg.Get(alias, "port")
	if err != nil {
		return
	}
	if p == "" {
		p = PORT
	}
	return
}

func SshToPutty() (err error) {
	name := path.Join(winssh.UserHomeDirs(".ssh"), "config")
	bs, err := os.ReadFile(name)
	if err != nil {
		return
	}
	cfg, err := ssh_config.DecodeBytes(bs)
	if err != nil {
		return
	}
	for _, host := range cfg.Hosts {
		for _, pattern := range host.Patterns {
			s := pattern.String()
			if s != "*" && !strings.Contains(s, ".") {
				session := strings.ReplaceAll(s, "?", "7")
				session = strings.ReplaceAll(session, "*", "8")
				err = PuttySession(session, Keys, Defs,
					ssh_config.Get(s, "User"),
					ssh_config.Get(s, "HostName"),
					ssh_config.Get(s, "Port"),
					yes(ssh_config.Get(s, "ForwardAgent")),
					ssh_config.Get(s, "ProxyJump"),
				)
				if err != nil {
					return
				}
			}
		}
	}
	return

}

func yes(s string) string {
	if strings.EqualFold(s, "yes") {
		return "1"
	}
	return "0"
}

// Пишем config для ssh клиента
func SshConfig(host string, kvm map[string]string) (err error) {
	name := path.Join(winssh.UserHomeDirs(".ssh"), "config")
	bs, err := os.ReadFile(name)
	if err != nil {
		return
	}
	s := ""
	i := 0
	old := ""
	for _, line := range strings.Split(strings.TrimSpace(string(bs)), "\n") {
		in := strings.ToLower(strings.TrimSpace(line))
		kv := strings.Split(in, " ")
		if kv[0] == "host" {
			if len(kv) > 1 && kv[1] == host {
				i++
			} else {
				if i == 1 {
					i++
				}
				s += fmt.Sprintln(strings.TrimSpace(line))
			}
			continue
		}
		if i == 1 {
			if in == "" {
				continue
			}
			found := false
		kvmFor:
			for k := range kvm {
				if strings.EqualFold(k, kv[0]) {
					found = true
					break kvmFor
				}
			}
			if !found {
				old += fmt.Sprintln("", strings.TrimSpace(line))
			}
		} else {
			s += fmt.Sprintln(line)
		}
	}
	s = fmt.Sprintln(strings.TrimSpace(s))
	s += fmt.Sprintln()
	s += fmt.Sprintln("Host", host)
	for k, v := range kvm {
		s += fmt.Sprintln("", k, v)
	}
	s += old
	f, err := os.Create(name)
	if err != nil {
		return
	}
	defer f.Close()
	_, err = f.WriteString(s)
	if err != nil {
		return
	}
	err = f.Chmod(FILEMODE)
	return
}

// Пишем HostName serveo.net UserKnownHostsFile для ssh клиента
func ServeoNet(host string) (err error) {
	//	PuttyHostKeys("rsa2@22:"+host, "0x10001,0xf1606a92295c09a500f5174608873f9b77996997b61eb0a8edae7d500f546341c4a3ef6e2525d0b096fe09f0f70bb8516d94003c01b1908eeeea59d30df6285d1ef45c59fd2d4a367e6f3c18931682c9dab82670ab6ef2c93f02c56aa57535d70ecd8d8d54bb97e427d8f154c7ae9b38f4b9ced10a4669abeaadb93ec135830fd30792535f275cd216940091242748d4988bf336277857ecfd06d91eddb14bcda2ff9480d2a97389fdf8bab956672a8eaa362a11721cfd0db1e0cba608daa8626ad8abe2b77428c21a9990ae0aefb000eb90b16637437e98f0652b97d3be45f6f362d081691641895bd2a5ad7cc8e252334808cf6415118546fc9d94a23eece3")
	s := host + " ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDxYGqSKVwJpQD1F0YIhz+bd5lpl7YesKjtrn1QD1RjQcSj724lJdCwlv4J8PcLuFFtlAA8AbGQju7qWdMN9ihdHvRcWf0tSjZ+bzwYkxaCydq4JnCrbvLJPwLFaqV1NdcOzY2NVLuX5CfY8VTHrps49LnO0QpGaavqrbk+wTWDD9MHklNfJ1zSFpQAkSQnSNSYi/M2J3hX7P0G2R7dsUvNov+UgNKpc4n9+Lq5Vmcqjqo2KhFyHP0NseDLpgjaqGJq2Kvit3QowhqZkK4K77AA65CxZjdDfpjwZSuX075F9vNi0IFpFkGJW9KlrXzI4lIzSAjPZBURhUb8nZSiPuzj\n"
	k, v, err := putty_hosts.ToPutty(s)
	if err != nil {
		Println(err)
	} else {
		PuttyConf(filepath.Join(SshHostKeys), " ", map[string]string{k: v})
	}
	name := path.Join(winssh.UserHomeDirs(".ssh"), SERVEO)
	err = os.WriteFile(name, []byte(s), FILEMODE)
	if err != nil {
		return
	}
	return SshConfig(host, map[string]string{"UserKnownHostsFile": "~/.ssh/" + SERVEO})
}

// Как запускать клиентов
func use(u, h, p, load string, ips ...string) (s string) {
	if h == ALL {
		for _, ip := range ips {
			h = ip
			s += useLine(load, u, h, p)
		}
	} else {
		s += useLine(load, u, h, p)
	}
	s += useLineShort(load)

	kvm := map[string]string{
		"User":               u,
		"HostName":           h,
		"UserKnownHostsFile": "~/.ssh/" + load,
	}
	if p != PORT {
		kvm["Port"] = p
	}
	Println("comboSession", SshConfig(load, kvm))

	kvm = map[string]string{
		"User":               u,
		"HostName":           SERVEO,
		"UserKnownHostsFile": "~/.ssh/" + load,
		"ProxyJump":          SNET,
	}
	Println("serveoSession", SshConfig(SERVEO, kvm))

	Println("SshToPutty", SshToPutty())
	Println("serveoNet", ServeoNet(SNET))
	return
}

// Читаю name и добавляю замки из in в authorized
func FileToAuthorized(name string, in ...ssh.PublicKey) (authorized []gl.PublicKey) {
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
