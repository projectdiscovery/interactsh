package acme

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/projectdiscovery/gologger"
	"go.uber.org/zap"
)

// HandleWildcardCertificates handles ACME wildcard cert generation with DNS
// challenge using certmagic library from caddyserver.
func HandleWildcardCertificates(domain, email string, store *Provider, debug bool) (*tls.Config, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = email
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSProvider: store,
		Resolvers: []string{
			"8.8.8.8:53",
			"8.8.4.4:53",
			"1.1.1.1:53",
			"1.0.0.1:53",
		},
	}
	originalDomain := strings.TrimPrefix(domain, "*.")

	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	if debug {
		certmagic.DefaultACME.Logger = logger
	}
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.DisableTLSALPNChallenge = true

	cfg := certmagic.NewDefault()
	if debug {
		cfg.Logger = logger
	}

	var creating bool
	if !certAlreadyExists(cfg, &certmagic.DefaultACME, domain) {
		creating = true
		gologger.Info().Msgf("Requesting SSL Certificate for:  [%s, %s]", domain, strings.TrimPrefix(domain, "*."))
	} else {
		gologger.Info().Msgf("Loading existing SSL Certificate for:  [%s, %s]", domain, strings.TrimPrefix(domain, "*."))
	}

	// this obtains certificates or renews them if necessary
	if syncerr := cfg.ObtainCertSync(context.Background(), domain); syncerr != nil {
		return nil, syncerr
	}
	go func() {
		syncerr := cfg.ManageAsync(context.Background(), []string{domain, originalDomain})
		if syncerr != nil {
			gologger.Error().Msgf("Could not manageasync certmagic certs: %s", err)
		}
	}()

	config := cfg.TLSConfig()
	config.ServerName = originalDomain
	config.NextProtos = []string{"h2", "http/1.1"}

	if creating {
		home, _ := os.UserHomeDir()
		gologger.Info().Msgf("Successfully Created SSL Certificate at: %s", filepath.Join(filepath.Join(home, ".local", "share"), "certmagic"))
	}
	return config, nil
}

// certAlreadyExists returns true if a cert already exists
func certAlreadyExists(cfg *certmagic.Config, issuer certmagic.Issuer, domain string) bool {
	issuerKey := issuer.IssuerKey()
	certKey := certmagic.StorageKeys.SiteCert(issuerKey, domain)
	keyKey := certmagic.StorageKeys.SitePrivateKey(issuerKey, domain)
	metaKey := certmagic.StorageKeys.SiteMeta(issuerKey, domain)
	return cfg.Storage.Exists(certKey) &&
		cfg.Storage.Exists(keyKey) &&
		cfg.Storage.Exists(metaKey)
}
