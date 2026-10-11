package ca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"
	"time"
)

func newTestCA(t *testing.T) *CA {
	t.Helper()
	c, err := New("perimeter-root")
	if err != nil {
		t.Fatal(err)
	}
	start := c.Cert.NotBefore.Add(time.Hour)
	c.Now = func() time.Time { return start }
	return c
}

func issueTestCert(t *testing.T, c *CA, ttl time.Duration) []byte {
	t.Helper()
	cert, key, err := c.Issue("aisha", "finance", ttl)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := decodePEM(key, "EC PRIVATE KEY")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	der, err := decodePEM(cert, "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !privateKey.PublicKey.Equal(parsed.PublicKey) || privateKey.PublicKey.Equal(&c.Key.PublicKey) {
		t.Fatal("client key must match its certificate and differ from the CA key")
	}
	return cert
}

func TestValidity(t *testing.T) {
	c := newTestCA(t)
	cert := issueTestCert(t, c, 10*time.Minute)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		wantOK bool
	}{
		{"minute5", 5 * time.Minute, true},
		{"minute11", 11 * time.Minute, false},
		{"beforeIssue", -time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, group, err := c.Verify(cert, c.Now().Add(tc.offset))
			if tc.wantOK {
				if err != nil {
					t.Fatal(err)
				}
				if user != "aisha" || group != "finance" {
					t.Fatalf("got %q %q", user, group)
				}
			} else {
				var invalid x509.CertificateInvalidError
				if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
					t.Fatalf("expected validity error, got %v", err)
				}
			}
		})
	}
}

func TestTamper(t *testing.T) {
	c := newTestCA(t)
	der, err := decodePEM(issueTestCert(t, c, 0), "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := 0; i+len("finance") <= len(der); i++ {
		if string(der[i:i+len("finance")]) == "finance" {
			copy(der[i:i+len("finance")], "sysadmn")
			found = true
			break
		}
	}
	if !found {
		t.Fatal("group not found")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("tampered certificate must still parse: %v", err)
	}
	if len(parsed.Subject.OrganizationalUnit) != 1 || parsed.Subject.OrganizationalUnit[0] != "sysadmn" {
		t.Fatal("group edit was not preserved")
	}
	err = parsed.CheckSignatureFrom(c.Cert)
	if err == nil {
		t.Fatal("tampered signature accepted")
	}
	t.Logf("parse succeeded; direct signature check: %v", err)
	forged := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	_, _, err = c.Verify(forged, c.Now().Add(time.Minute))
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected chain signature rejection, got %v", err)
	}
	t.Logf("Verify: %v", err)
}

func TestForeignCA(t *testing.T) {
	real, fake := newTestCA(t), newTestCA(t)
	cert := issueTestCert(t, fake, 0)
	if _, _, err := real.Verify(cert, fake.Now().Add(time.Minute)); err == nil {
		t.Fatal("same-name foreign CA accepted")
	}
}

func TestSaveLoad(t *testing.T) {
	c := newTestCA(t)
	dir := t.TempDir()
	cp, kp := dir+"/ca.crt", dir+"/ca.key"
	if err := c.Save(cp, kp); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(kp)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions: %o", info.Mode().Perm())
	}
	loaded, err := Load(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Now = c.Now
	cert := issueTestCert(t, loaded, 0)
	if _, _, err := c.Verify(cert, c.Now().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(cp, kp); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected overwrite refusal: %v", err)
	}
	other := newTestCA(t)
	if err := other.Save(dir+"/other.crt", dir+"/other.key"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cp, dir+"/other.key"); err == nil {
		t.Fatal("mismatched key accepted")
	}
}

func TestDefaultAndInputs(t *testing.T) {
	c := newTestCA(t)
	der, err := decodePEM(issueTestCert(t, c, 0), "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.NotAfter.Sub(cert.NotBefore) != 10*time.Minute {
		t.Fatal("incorrect default TTL")
	}
	for _, ttl := range []time.Duration{-time.Minute, time.Nanosecond} {
		if _, _, err := c.Issue("aisha", "finance", ttl); err == nil {
			t.Fatal("invalid TTL accepted")
		}
	}
	if _, _, err := c.Issue("", "finance", 0); err == nil {
		t.Fatal("empty user accepted")
	}
	if _, _, err := c.Issue("aisha", "", 0); err == nil {
		t.Fatal("empty group accepted")
	}
	if _, _, err := c.Verify([]byte("garbage"), c.Now()); err == nil {
		t.Fatal("bad PEM accepted")
	}
	if _, _, err := c.Verify(issueTestCert(t, c, 0), time.Time{}); err == nil {
		t.Fatal("zero time accepted")
	}
	c.Now = func() time.Time { return c.Cert.NotAfter.Add(-time.Minute) }
	if _, _, err := c.Issue("aisha", "finance", 0); err == nil {
		t.Fatal("lifetime beyond CA accepted")
	}
}

func TestClientUsage(t *testing.T) {
	c := newTestCA(t)
	der, err := decodePEM(issueTestCert(t, c, 0), "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		usage []x509.ExtKeyUsage
	}{
		{"server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{"missing", nil},
		{"unrestricted", []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		{"mixed", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			cert.ExtKeyUsage = tc.usage
			signed, err := x509.CreateCertificate(rand.Reader, cert, c.Cert, cert.PublicKey, c.Key)
			if err != nil {
				t.Fatal(err)
			}
			data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed})
			if _, _, err := c.Verify(data, c.Now()); err == nil {
				t.Fatal("non-client-only certificate accepted")
			}
		})
	}
}

func TestIssueServer(t *testing.T) {
	c := newTestCA(t)
	certPEM, keyPEM, err := c.IssueServer("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	der, err := decodePEM(certPEM, "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := decodePEM(keyPEM, "EC PRIVATE KEY")
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("server key mismatch")
	}
	if cert.IsCA || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("incorrect server usage")
	}
	if cert.NotAfter.Sub(cert.NotBefore) != 10*time.Minute {
		t.Fatal("incorrect default TTL")
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1", CurrentTime: c.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("127.0.0.2"); err == nil {
		t.Fatal("wrong IP accepted")
	}
	if _, _, err := c.Verify(certPEM, c.Now()); err == nil {
		t.Fatal("server certificate accepted as client")
	}
	if _, _, err := c.IssueServer("not-an-ip", 0); err == nil {
		t.Fatal("invalid IP accepted")
	}
	if _, _, err := c.IssueServer("127.0.0.1", -time.Minute); err == nil {
		t.Fatal("negative TTL accepted")
	}
}

func TestIssueConnector(t *testing.T) {
	c := newTestCA(t)
	data, key, err := c.IssueConnector("dc-mumbai-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	der, err := decodePEM(data, "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "dc-mumbai-1" || len(cert.Subject.OrganizationalUnit) != 0 || len(cert.URIs) != 1 || cert.URIs[0].String() != "perimeter://connector/dc-mumbai-1" || len(key) == 0 {
		t.Fatal("incorrect connector identity")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("incorrect connector usage")
	}
	if err := cert.CheckSignatureFrom(c.Cert); err != nil {
		t.Fatal(err)
	}
}
