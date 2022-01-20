package acme

import (
	"context"
	"crypto/tls"
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
	return config, nil
}
