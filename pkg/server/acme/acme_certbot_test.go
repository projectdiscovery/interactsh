package acme

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeRecords returns a single-element libdns record slice for use in DNS provider tests.
func makeRecords(name, rtype, data string) []libdns.Record {
	return []libdns.Record{libdns.RR{Name: name, Type: rtype, Data: data}}
}

// createFakeCert writes the three stub files that certmagic uses to track a certificate
// (cert, private key, metadata) so that certAlreadyExists returns true for domain.
func createFakeCert(t *testing.T, dir string, issuer certmagic.Issuer, domain string) {
	t.Helper()
	issuerKey := issuer.IssuerKey()
	for _, key := range []string{
		certmagic.StorageKeys.SiteCert(issuerKey, domain),
		certmagic.StorageKeys.SitePrivateKey(issuerKey, domain),
		certmagic.StorageKeys.SiteMeta(issuerKey, domain),
	} {
		p := filepath.Join(dir, filepath.FromSlash(key))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
		require.NoError(t, os.WriteFile(p, []byte("fake"), 0o600))
	}
}

// TestCertAlreadyExists verifies that certAlreadyExists correctly reports
// presence/absence of the three files certmagic uses to track a certificate.
func TestCertAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	cfg := &certmagic.Config{Storage: storage}
	issuer := &certmagic.ACMEIssuer{CA: certmagic.LetsEncryptStagingCA}
	domain := "*.example.com"

	t.Run("returns false when no cert files exist", func(t *testing.T) {
		assert.False(t, certAlreadyExists(cfg, issuer, domain))
	})

	t.Run("returns false when only cert file exists", func(t *testing.T) {
		issuerKey := issuer.IssuerKey()
		certKey := certmagic.StorageKeys.SiteCert(issuerKey, domain)
		certPath := filepath.Join(dir, filepath.FromSlash(certKey))
		require.NoError(t, os.MkdirAll(filepath.Dir(certPath), 0o700))
		require.NoError(t, os.WriteFile(certPath, []byte("fake-cert"), 0o600))

		assert.False(t, certAlreadyExists(cfg, issuer, domain))
	})

	t.Run("returns true when all three cert files exist", func(t *testing.T) {
		createFakeCert(t, dir, issuer, domain)
		assert.True(t, certAlreadyExists(cfg, issuer, domain))
	})
}

// TestExtractCaddyPaths verifies that ExtractCaddyPaths returns non-empty paths
// for a FileStorage backend.
func TestExtractCaddyPaths(t *testing.T) {
	dir := t.TempDir()
	cfg := &certmagic.Config{Storage: &certmagic.FileStorage{Path: dir}}
	issuer := &certmagic.ACMEIssuer{CA: certmagic.LetsEncryptStagingCA}

	certPath, keyPath, err := ExtractCaddyPaths(cfg, issuer, "example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, certPath)
	assert.NotEmpty(t, keyPath)
	assert.Contains(t, certPath, dir)
	assert.Contains(t, keyPath, dir)
}

// TestProvider covers the DNS record store used for DNS-01 ACME challenges.
func TestProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("AppendRecords adds records to a new zone", func(t *testing.T) {
		p := NewProvider()
		appended, err := p.AppendRecords(ctx, "example.com.", makeRecords("example.com.", "TXT", "token1"))
		require.NoError(t, err)
		assert.Len(t, appended, 1)
	})

	t.Run("AppendRecords to ACME challenge zone replaces existing record", func(t *testing.T) {
		p := NewProvider()
		zone := "_acme-challenge.example.com."

		_, err := p.AppendRecords(ctx, zone, makeRecords(zone, "TXT", "token1"))
		require.NoError(t, err)

		// A second challenge token must replace the first (RFC 8555 §8.4)
		result, err := p.AppendRecords(ctx, zone, makeRecords(zone, "TXT", "token2"))
		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, "token2", result[0].RR().Data)
	})

	t.Run("GetRecords errors on unknown zone", func(t *testing.T) {
		p := NewProvider()
		_, err := p.GetRecords(ctx, "unknown.example.com.")
		assert.Error(t, err)
	})

	t.Run("DeleteRecords removes matching records", func(t *testing.T) {
		p := NewProvider()
		zone := "example.com."
		recs := makeRecords(zone, "TXT", "token1")

		_, err := p.AppendRecords(ctx, zone, recs)
		require.NoError(t, err)

		deleted, err := p.DeleteRecords(ctx, zone, recs)
		require.NoError(t, err)
		assert.Len(t, deleted, 1)

		remaining, err := p.GetRecords(ctx, zone)
		require.NoError(t, err)
		assert.Empty(t, remaining)
	})
}

// TestObtainApexCertIfMissing validates the core behaviour of the fix:
//   - When the apex cert is absent, the obtain function is called.
//   - When the apex cert already exists, the obtain function is skipped.
//
// This prevents the regression where ManageSync was the sole mechanism for apex
// cert issuance and silently failed with "order pending, authorizations
// remaining" from Let's Encrypt when both the wildcard and apex DNS-01
// challenges share the same _acme-challenge TXT record.
func TestObtainApexCertIfMissing(t *testing.T) {
	issuer := &certmagic.ACMEIssuer{CA: certmagic.LetsEncryptStagingCA}

	t.Run("calls obtain when apex cert is absent", func(t *testing.T) {
		cfg := &certmagic.Config{Storage: &certmagic.FileStorage{Path: t.TempDir()}}

		called := false
		obtainApexCertIfMissing(cfg, issuer, "example.com", func(_ context.Context, _ string) error {
			called = true
			return nil
		})
		assert.True(t, called, "obtain must be called when the apex cert does not yet exist")
	})

	t.Run("skips obtain when apex cert already exists", func(t *testing.T) {
		dir := t.TempDir()
		cfg := &certmagic.Config{Storage: &certmagic.FileStorage{Path: dir}}
		createFakeCert(t, dir, issuer, "example.com")

		called := false
		obtainApexCertIfMissing(cfg, issuer, "example.com", func(_ context.Context, _ string) error {
			called = true
			return nil
		})
		assert.False(t, called, "obtain must be skipped when apex cert already exists")
	})
}
