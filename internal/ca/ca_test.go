package ca

import (
	"bytes"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"
)

func newTestCA(t *testing.T, start time.Time) *CA {
	t.Helper()
	c, err := New("perimeter-root")
	if err != nil {
		t.Fatal(err)
	}
	c.Now = func() time.Time { return start }
	return c
}

func TestIssueAndVerify(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	c := newTestCA(t, start)
	certPEM, _, err := c.Issue("aisha", "finance", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	user, group, err := c.Verify(certPEM, start.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("5 min should be accepted: %v", err)
	}
	if user != "aisha" || group != "finance" {
		t.Fatalf("got %s %s", user, group)
	}
}

func TestExpired(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	c := newTestCA(t, start)
	certPEM, _, _ := c.Issue("aisha", "finance", 10*time.Minute)
	if _, _, err := c.Verify(certPEM, start.Add(11*time.Minute)); err == nil {
		t.Fatal("11 min should be rejected")
	}
}

func TestNotYetValid(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	c := newTestCA(t, start)
	certPEM, _, _ := c.Issue("aisha", "finance", 10*time.Minute)
	if _, _, err := c.Verify(certPEM, start.Add(-time.Hour)); err == nil {
		t.Fatal("before issue time should be rejected")
	}
}

func TestTamper(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	c := newTestCA(t, start)
	certPEM, _, _ := c.Issue("aisha", "finance", 10*time.Minute)
	block, _ := pem.Decode(certPEM)
	if !bytes.Contains(block.Bytes, []byte("finance")) {
		t.Fatal("group not found in cert bytes")
	}
	block.Bytes = bytes.Replace(block.Bytes, []byte("finance"), []byte("sysadmn"), 1)
	forged := pem.EncodeToMemory(block)
	if _, _, err := c.Verify(forged, start.Add(time.Minute)); err == nil {
		t.Fatal("tampered cert should be rejected")
	}
}

func TestForeignCA(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	real := newTestCA(t, start)
	fake := newTestCA(t, start)
	certPEM, _, _ := fake.Issue("aisha", "finance", 10*time.Minute)
	if _, _, err := real.Verify(certPEM, start.Add(time.Minute)); err == nil {
		t.Fatal("cert from a different CA should be rejected")
	}
}

func TestSaveLoad(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	c := newTestCA(t, start)
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := c.Save(cp, kp); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Now = func() time.Time { return start }
	certPEM, _, err := loaded.Issue("bob", "engineering", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Verify(certPEM, start.Add(30*time.Second)); err != nil {
		t.Fatalf("original CA should accept cert from reloaded CA: %v", err)
	}
}
