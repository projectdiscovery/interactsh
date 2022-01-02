package acme

import (
	"context"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// HandleWildcardCertificates handles ACME wildcard cert generation with DNS
// challenge using certmagic library from caddyserver.
func HandleWildcardCertificates(domain, email string, store *Provider) error {
	logger, err := zap.NewProduction()
	if err != nil {
		return err
	}

	configTemplate := certmagic.NewDefault()
	//	configTemplate.Logger = logger
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return configTemplate, nil
		},
	})
	config := certmagic.New(cache, *configTemplate)
	myACME := certmagic.NewACMEManager(config, certmagic.ACMEManager{
		CA:     certmagic.LetsEncryptProductionCA,
		Email:  email,
		Agreed: true,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSProvider: store,
			Resolvers: []string{
				"8.8.8.8:53",
				"8.8.4.4:53",
				"1.1.1.1:53",
				"1.0.0.1:53",
			},
		},
		Logger:                  logger,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
	})
	config.Issuers = append(config.Issuers, myACME)

	domains := strings.Split(domain, ",")

	// this obtains certificates or renews them if necessary
	syncerr := config.ManageAsync(context.Background(), domains)
	if syncerr != nil {
		return errors.Wrap(syncerr, "could not get certificates")
	}
	return nil
}
