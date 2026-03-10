package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateSelfSignedCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func writeCertFiles(t *testing.T, dir, certName, keyName string, certPEM, keyPEM []byte) (string, string) {
	t.Helper()
	certPath := filepath.Join(dir, certName)
	keyPath := filepath.Join(dir, keyName)
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestNewCertReloader(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedCert(t, "initial.example.com")
	certPath, keyPath := writeCertFiles(t, dir, "cert.pem", "key.pem", certPEM, keyPEM)

	reloader, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	cert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subject.CommonName != "initial.example.com" {
		t.Fatalf("expected CN=initial.example.com, got %s", parsed.Subject.CommonName)
	}
}

func TestNewCertReloaderInvalidFiles(t *testing.T) {
	_, err := NewCertReloader("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent files")
	}
}

func TestCertReloaderReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedCert(t, "original.example.com")
	certPath, keyPath := writeCertFiles(t, dir, "cert.pem", "key.pem", certPEM, keyPEM)

	reloader, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	// Advance file mod time so the reloader detects a change
	newCertPEM, newKeyPEM := generateSelfSignedCert(t, "renewed.example.com")
	if err := os.WriteFile(certPath, newCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, newKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(certPath, future, future)
	_ = os.Chtimes(keyPath, future, future)

	reloader.tryReload()

	cert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subject.CommonName != "renewed.example.com" {
		t.Fatalf("expected CN=renewed.example.com after reload, got %s", parsed.Subject.CommonName)
	}
}

func TestCertReloaderNoReloadWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedCert(t, "stable.example.com")
	certPath, keyPath := writeCertFiles(t, dir, "cert.pem", "key.pem", certPEM, keyPEM)

	reloader, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	certBefore, _ := reloader.GetCertificate(nil)
	reloader.tryReload()
	certAfter, _ := reloader.GetCertificate(nil)

	// Same pointer means no reload happened
	if certBefore != certAfter {
		t.Fatal("expected same certificate pointer when files are unchanged")
	}
}

func TestCertReloaderStartRespectsContext(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedCert(t, "ctx.example.com")
	certPath, keyPath := writeCertFiles(t, dir, "cert.pem", "key.pem", certPEM, keyPEM)

	reloader, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reloader.Start(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestGetCertificateIsConcurrentSafe(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedCert(t, "concurrent.example.com")
	certPath, keyPath := writeCertFiles(t, dir, "cert.pem", "key.pem", certPEM, keyPEM)

	reloader, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	// Concurrently read and reload
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			reloader.tryReload()
		}
	}()

	for i := 0; i < 100; i++ {
		cert, err := reloader.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatalf("concurrent GetCertificate: %v", err)
		}
		if cert == nil {
			t.Fatal("concurrent GetCertificate returned nil")
		}
	}
	<-done
}

func TestCertReloaderTLSHandshake(t *testing.T) {
	dir := t.TempDir()

	// Start with original cert
	certPEM, keyPEM := generateSelfSignedCert(t, "original.example.com")
	certPath, keyPath := writeCertFiles(t, dir, "cert.pem", "key.pem", certPEM, keyPEM)

	reloader, err := NewCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	// Start a real TLS listener using the reloader
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, &tls.Config{
		GetCertificate: reloader.GetCertificate,
	})
	defer tlsLn.Close()

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			// Keep connection alive long enough for client to read peer certs
			go func(c net.Conn) {
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				c.Close()
			}(conn)
		}
	}()

	addr := ln.Addr().String()

	// Verify original cert is served
	cn := tlsHandshakeCN(t, addr)
	if cn != "original.example.com" {
		t.Fatalf("expected CN=original.example.com, got %s", cn)
	}

	// Swap cert files on disk and trigger reload
	newCertPEM, newKeyPEM := generateSelfSignedCert(t, "renewed.example.com")
	if err := os.WriteFile(certPath, newCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, newKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(certPath, future, future)
	_ = os.Chtimes(keyPath, future, future)

	reloader.tryReload()

	// Verify renewed cert is now served
	cn = tlsHandshakeCN(t, addr)
	if cn != "renewed.example.com" {
		t.Fatalf("expected CN=renewed.example.com after reload, got %s", cn)
	}
}

// tlsHandshakeCN performs a real TLS handshake and returns the peer certificate's CN.
func tlsHandshakeCN(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("no peer certificates")
	}
	return certs[0].Subject.CommonName
}

func TestCertCheckIntervalEnv(t *testing.T) {
	// Default
	interval := certCheckInterval()
	if interval != defaultCertCheckInterval {
		t.Fatalf("expected default %s, got %s", defaultCertCheckInterval, interval)
	}

	// Valid override
	t.Setenv("CERT_CHECK_INTERVAL", "30m")
	interval = certCheckInterval()
	if interval != 30*time.Minute {
		t.Fatalf("expected 30m, got %s", interval)
	}

	// Invalid falls back to default
	t.Setenv("CERT_CHECK_INTERVAL", "notaduration")
	interval = certCheckInterval()
	if interval != defaultCertCheckInterval {
		t.Fatalf("expected default %s for invalid env, got %s", defaultCertCheckInterval, interval)
	}
}
