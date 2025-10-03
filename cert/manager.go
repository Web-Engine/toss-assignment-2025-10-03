package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Manager struct {
	once     sync.Once
	rootCert *x509.Certificate
	rootKey  crypto.Signer

	LeafTTL time.Duration
}

func NewCertManager(rootCertPath, rootKeyPath string) (*Manager, error) {
	cert, key, err := load(rootCertPath, rootKeyPath)
	if err != nil {
		return nil, err
	}

	return &Manager{
		rootCert: cert,
		rootKey:  key,
		LeafTTL:  90 * 24 * time.Hour,
	}, nil
}

func (m *Manager) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := info.ServerName

	cert, err := m.issueLeaf(name)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func load(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return nil, nil, fmt.Errorf("read root pem: %w", err)
	}

	certBlock, certPEM := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, errors.New("no CERTIFICATE certBlock in rootCA.pem")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse root certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, nil, fmt.Errorf("read root key: %w", err)
	}

	keyBlock, keyPEM := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("no private key certBlock in rootCA.key")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse root key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("root key is not a crypto.Signer")
	}

	return cert, signer, nil
}

func (m *Manager) issueLeaf(serverName string) (*tls.Certificate, error) {
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(m.LeafTTL)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         serverName,
			Organization:       []string{"Toss VPN"},
			OrganizationalUnit: []string{"Wein Cho"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if serverName != "" {
		template.DNSNames = []string{serverName}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, m.rootCert, &leafKey.PublicKey, m.rootKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, fmt.Errorf("marshal leaf key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("x509 key pair: %w", err)
	}

	if leaf, err := x509.ParseCertificate(derBytes); err == nil {
		tlsCert.Leaf = leaf
	}
	return &tlsCert, nil
}
