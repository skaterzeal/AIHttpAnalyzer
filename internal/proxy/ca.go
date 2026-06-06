// Package proxy provides a live MITM proxy that analyzes responses as they flow
// through, emitting findings in real time. It is the "watch traffic live" mode
// alongside the batch (Burp/file/stdin) ingestion paths.
package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// EnsureCA loads the MITM CA from certPath/keyPath, generating a fresh, unique
// CA on first use. A per-install CA matters for a security tool: we never ship a
// shared private key, and the operator explicitly trusts only their own CA.
func EnsureCA(certPath, keyPath string) (tls.Certificate, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		return tls.LoadX509KeyPair(certPath, keyPath)
	}
	return generateCA(certPath, keyPath)
}

// DefaultCAPaths returns the default CA cert/key locations under the user config
// dir, falling back to the working directory.
func DefaultCAPaths() (certPath, keyPath string) {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	base := filepath.Join(dir, "httpanalyzer")
	return filepath.Join(base, "ca-cert.pem"), filepath.Join(base, "ca-key.pem")
}

func generateCA(certPath, keyPath string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "httpanalyzer MITM CA",
			Organization: []string{"httpanalyzer"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	fmt.Fprintf(os.Stderr, "generated MITM CA: %s (trust this cert in your browser/Burp)\n", certPath)
	return tls.X509KeyPair(certPEM, keyPEM)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
