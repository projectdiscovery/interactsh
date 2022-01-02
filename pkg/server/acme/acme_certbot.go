package acme

import (
	"context"
	"crypto/tls"

	"github.com/caddyserver/certmagic"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// HandleWildcardCertificates handles ACME wildcard cert generation with DNS
// challenge using certmagic library from caddyserver.
func HandleWildcardCertificates(domain, email string, store *Provider) (*tls.Config, error) {
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
	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	certmagic.DefaultACME.Logger = logger
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.DisableTLSALPNChallenge = true

	cfg := certmagic.NewDefault()
	cfg.Logger = logger

	// this obtains certificates or renews them if necessary
	if syncerr := cfg.ObtainCertSync(context.Background(), domain); syncerr != nil {
		return nil, syncerr
	}
	syncerr := cfg.ManageAsync(context.Background(), []string{domain})
	if syncerr != nil {
		return nil, errors.Wrap(syncerr, "could not get certificates")
	}
	return cfg.TLSConfig(), nil
}
