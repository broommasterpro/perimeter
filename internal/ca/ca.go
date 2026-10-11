package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"
)

type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	Now  func() time.Time // Tests can advance time without sleeping.
}

func serial() (*big.Int, error) {
	// Random positive serials avoid coordinating a counter across restarts.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	limit.Sub(limit, big.NewInt(1))
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

func New(name string) (*CA, error) {
	if name == "" {
		return nil, errors.New("CA name is empty")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, Now: time.Now}, nil
}

func (c *CA) Issue(user, group string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	if user == "" || group == "" {
		return nil, nil, errors.New("user and group must be nonempty")
	}
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	if ttl < time.Second {
		return nil, nil, errors.New("TTL must be at least one second")
	}
	// X.509 timestamps have whole-second precision.
	now := c.Now().UTC().Truncate(time.Second)
	end := now.Add(ttl).Truncate(time.Second)
	if now.Before(c.Cert.NotBefore) || !now.Before(c.Cert.NotAfter) || end.After(c.Cert.NotAfter) {
		return nil, nil, errors.New("requested lifetime is outside CA validity")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: user, OrganizationalUnit: []string{group}},
		NotBefore:             now,
		NotAfter:              end,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func decodePEM(data []byte, kind string) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, errors.New("expected one PEM block of type " + kind)
	}
	return block.Bytes, nil
}

func (c *CA) Verify(certPEM []byte, at time.Time) (user, group string, err error) {
	if at.IsZero() {
		return "", "", errors.New("verification time is required")
	}
	der, err := decodePEM(certPEM, "CERTIFICATE")
	if err != nil {
		return "", "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", err
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.Cert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: at,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return "", "", err
	}
	// An absent or unrestricted EKU can pass general X.509 verification.
	if cert.IsCA || cert.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(cert.UnknownExtKeyUsage) != 0 {
		return "", "", errors.New("certificate must be client-auth only")
	}
	if cert.Subject.CommonName == "" || len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] == "" {
		return "", "", errors.New("certificate must contain a user and exactly one nonempty group")
	}
	return cert.Subject.CommonName, cert.Subject.OrganizationalUnit[0], nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) (err error) {
	// Exclusive creation refuses existing files, including symlinks.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if err = f.Chmod(mode); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

func (c *CA) Save(certPath, keyPath string) error {
	if certPath == keyPath {
		return errors.New("certificate and key paths must differ")
	}
	keyDER, err := x509.MarshalECPrivateKey(c.Key)
	if err != nil {
		return err
	}
	if err := writeNewFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return writeNewFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw}), 0o644)
}

func Load(certPath, keyPath string) (*CA, error) {
	cb, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	certDER, err := decodePEM(cb, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	keyDER, err := decodePEM(kb, "EC PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("CA certificate and P-256 private key do not match")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
		string(cert.RawIssuer) != string(cert.RawSubject) {
		return nil, errors.New("certificate is not a self-issued CA")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, Now: time.Now}, nil
}

func (c *CA) IssueServer(ip string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	address := net.ParseIP(ip)
	if address == nil {
		return nil, nil, errors.New("invalid server IP address")
	}
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	if ttl < time.Second {
		return nil, nil, errors.New("TTL must be at least one second")
	}
	now := c.Now().UTC().Truncate(time.Second)
	end := now.Add(ttl).Truncate(time.Second)
	if now.Before(c.Cert.NotBefore) || !now.Before(c.Cert.NotAfter) || end.After(c.Cert.NotAfter) {
		return nil, nil, errors.New("requested lifetime is outside CA validity")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "perimeter-proxy"},
		IPAddresses:           []net.IP{address},
		NotBefore:             now,
		NotAfter:              end,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func (c *CA) IssueConnector(id string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	if id == "" {
		return nil, nil, errors.New("empty connector ID")
	}
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	if ttl < time.Second {
		return nil, nil, errors.New("TTL must be at least one second")
	}
	now := c.Now().UTC().Truncate(time.Second)
	end := now.Add(ttl).Truncate(time.Second)
	if now.Before(c.Cert.NotBefore) || !now.Before(c.Cert.NotAfter) || end.After(c.Cert.NotAfter) {
		return nil, nil, errors.New("requested lifetime is outside CA validity")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{{Scheme: "perimeter", Host: "connector", Path: "/" + id}}, NotBefore: now, NotAfter: end, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}
