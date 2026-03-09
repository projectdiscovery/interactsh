package acme

import (
	"context"
	"crypto/tls"
	"os"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
)

const defaultCertCheckInterval = 1 * time.Hour

func certCheckInterval() time.Duration {
	if v := os.Getenv("CERT_CHECK_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		gologger.Warning().Msgf("Invalid CERT_CHECK_INTERVAL %q, using default %s", v, defaultCertCheckInterval)
	}
	return defaultCertCheckInterval
}

// CertReloader watches a certificate/key file pair and reloads when files change on disk.
type CertReloader struct {
	certPath string
	keyPath  string
	cert     atomic.Pointer[tls.Certificate]
	modTime time.Time
}

// NewCertReloader loads the initial certificate and returns a reloader.
func NewCertReloader(certPath, keyPath string) (*CertReloader, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	modTime, _ := latestModTime(certPath, keyPath)

	r := &CertReloader{
		certPath: certPath,
		keyPath:  keyPath,
		modTime:  modTime,
	}
	r.cert.Store(&cert)
	return r, nil
}

// GetCertificate returns the current certificate. Safe for concurrent use.
func (r *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cert.Load(), nil
}

// Start polls for certificate file changes and reloads when detected.
// Blocks until ctx is cancelled.
// The check interval is configurable via the CERT_CHECK_INTERVAL env variable (e.g. "30m", "2h").
func (r *CertReloader) Start(ctx context.Context) {
	interval := certCheckInterval()
	gologger.Info().Msgf("Certificate reload check interval: %s", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tryReload()
		}
	}
}

func (r *CertReloader) tryReload() {
	mt, err := latestModTime(r.certPath, r.keyPath)
	if err != nil {
		gologger.Warning().Msgf("Could not stat certificate files: %s", err)
		return
	}
	if !mt.After(r.modTime) {
		return
	}

	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		gologger.Warning().Msgf("Could not reload certificate: %s", err)
		return
	}

	r.cert.Store(&cert)
	r.modTime = mt
	gologger.Info().Msgf("Reloaded TLS certificate from %s", r.certPath)
}

// latestModTime returns the most recent modification time of the two files.
func latestModTime(certPath, keyPath string) (time.Time, error) {
	certInfo, err := os.Stat(certPath)
	if err != nil {
		return time.Time{}, err
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return time.Time{}, err
	}
	if keyInfo.ModTime().After(certInfo.ModTime()) {
		return keyInfo.ModTime(), nil
	}
	return certInfo.ModTime(), nil
}
