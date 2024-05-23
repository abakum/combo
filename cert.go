package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type HostsCerts map[string]string

// Ищем сертификаты хостов в KnownHosts файлах
func caKeys(files ...string) HostsCerts {
	hostCerts := make(HostsCerts)
	const CertAuthority = "cert-authority"
	var (
		marker string
		hosts  []string
		pubKey ssh.PublicKey
	)
	for _, file := range files {
		rest, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if !bytes.Contains(rest, []byte("@"+CertAuthority+" ")) {
			continue
		}
	parse:
		for {
			marker, hosts, pubKey, _, rest, err = ssh.ParseKnownHosts(rest)
			if err != nil {
				if err == io.EOF {
					break parse
				}
				continue parse
			}
			if marker != CertAuthority {
				continue parse
			}
			csHosts := strings.Join(hosts, ",")
			debug("@%s %s %s", marker, csHosts, ssh.FingerprintSHA256(pubKey))
			hostCerts[ssh.FingerprintSHA256(pubKey)] = csHosts
		}
	}
	return hostCerts
}

// Если найдены сертификаты хостов то возвращаем ssh.CertChecker.CheckHostKey иначе cb
func caKeysCallback(cb ssh.HostKeyCallback, hostCerts HostsCerts) ssh.HostKeyCallback {
	if len(hostCerts) == 0 {
		return cb
	}
	certCheck := &ssh.CertChecker{
		IsHostAuthority: func(p ssh.PublicKey, addr string) bool {
			fingerprint := ssh.FingerprintSHA256(p)
			hosts, ok := hostCerts[fingerprint]
			if ok {
				if hosts != "*" {
					h, _, err := net.SplitHostPort(addr)
					ok = false
					if err == nil {
						for _, host := range strings.Split(hosts, ",") {
							if h != host {
								continue
							}
							ok = true
							break
						}
					}
				}
			}
			s := ""
			if !ok {
				s = "not "
			}
			debug("host %s %sknown by certificate %s", addr, s, fingerprint)
			return ok
		},
		HostKeyFallback: cb,
	}
	return certCheck.CheckHostKey
}

type StringsSet map[string]struct{}

var type2pub = map[string]string{
	ssh.KeyAlgoRSA:        "id_rsa",
	ssh.KeyAlgoDSA:        "id_dsa",
	ssh.KeyAlgoECDSA256:   "id_ecdsa",
	ssh.KeyAlgoSKECDSA256: "id_ecdsa-sk",
	ssh.KeyAlgoECDSA384:   "id_ecdsa",
	ssh.KeyAlgoECDSA521:   "id_ecdsa",
	ssh.KeyAlgoED25519:    "id_ed25519",
	ssh.KeyAlgoSKED25519:  "id_ecdsa-sk",
}

// Добавляем в слайс pubKeySigners подписыватели сертификатами и в набор StringsSet отпечаток замка
//
// IdentityFile + "-cert" or IdentityFile + "-cert.pub" or CertificateFile
// Используем в addPubKeySigners
func addCertSigner(args *sshArgs, param *sshParam, signer *sshSigner, fingerprints StringsSet, pubKeySigners []ssh.Signer) (StringsSet, []ssh.Signer) {
	t, ok := type2pub[signer.pubKey.Type()]
	if !ok {
		return fingerprints, pubKeySigners
	}
	path := filepath.Join(userHomeDir, ".ssh", t+"-cert")

	paths := []string{}
	certificateFiles := getAllOptionConfig(args, "CertificateFile")
	if len(certificateFiles) == 0 {
		paths = []string{path, path + ".pub"}
	} else {
		// Для командной строки Windows используй одиночные кавычки для файлов с пробелами и двойные для параметров
		// combo -o "CertificateFile '~/.ssh/_ id_rsa-cert.pub'"
		for _, path := range certificateFiles {
			path = expandEnv(path)
			expanded, err := expandTokens(path, args, param, "%CdhijkLlnpru")
			if err != nil {
				warning("expand CertificateFile [%s] failed: %v", path, err)
				continue
			}
			paths = append(paths, resolveHomeDir(expanded))
		}
	}
	for _, path := range paths {
		if !isFileExist(path) {
			continue
		}
		pubKeyBytes, err := os.ReadFile(path)
		if err != nil {
			warning("%v", err)
			continue
		}
		// todo Несколько замков
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
		if err != nil {
			warning("%v", err)
			continue
		}
		fingerprint := ssh.FingerprintSHA256(pubKey)
		if _, ok := fingerprints[fingerprint]; ok {
			continue
		}
		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			continue
		}
		if cert.CertType != ssh.UserCert {
			continue
		}
		if !bytes.Equal(signer.pubKey.Marshal(), cert.Key.Marshal()) {
			continue
		}
		certSigner, err := ssh.NewCertSigner(cert, signer)
		if err != nil {
			warning("%v", err)
			continue
		}
		debug("will attempt key: %s %s %s", path, pubKey.Type(), fingerprint)
		fingerprints[fingerprint] = struct{}{}
		pubKeySigners = append(pubKeySigners, certSigner)
	}
	return fingerprints, pubKeySigners
}

// Если переменные окружения найдены тогда заменяем
func expandEnv(s string) string {
	if !strings.Contains(s, "$") || strings.Count(s, "${") != strings.Count(s, "}") {
		return s
	}
	LookupEnv := func(key string) string {
		if value, ok := os.LookupEnv(key); ok {
			return value
		}
		// Не найдена переменная окружения
		if strings.Contains(s, "${") {
			return fmt.Sprintf("${%s}", key)
		}
		return fmt.Sprintf("$%s", key)
	}
	return os.Expand(s, LookupEnv)
}

func unquote(s string) string {
	u, err := strconv.Unquote(s)
	if err != nil {
		return s
	}
	return u
	// ss, err := splitCommandLine(s)
	// if err != nil || len(ss) == 0 {
	// 	return s
	// }
	// return ss[0]
}
