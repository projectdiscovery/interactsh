package server

import (
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"git.mills.io/prologic/smtpd"
	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// SMTPServer is a smtp server instance that listens both
// TLS and Non-TLS based servers.
type SMTPServer struct {
	options     *Options
	smtpServer  smtpd.Server
	smtpsServer smtpd.Server
}

// NewSMTPServer returns a new TLS & Non-TLS SMTP server.
func NewSMTPServer(options *Options) (*SMTPServer, error) {
	server := &SMTPServer{options: options}

	authHandler := func(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error) {
		return true, nil
	}
	rcptHandler := func(remoteAddr net.Addr, from string, to string) bool {
		return true
	}
	server.smtpServer = smtpd.Server{
		Addr:        formatAddress(options.ListenIP, options.SmtpPort),
		AuthHandler: authHandler,
		HandlerRcpt: rcptHandler,
		Hostname:    options.Domains[0],
		Appname:     "interactsh",
		Handler:     smtpd.Handler(server.defaultHandler),
	}
	server.smtpsServer = smtpd.Server{
		Addr:        formatAddress(options.ListenIP, options.SmtpsPort),
		AuthHandler: authHandler,
		HandlerRcpt: rcptHandler,
		Hostname:    options.Domains[0],
		Appname:     "interactsh",
		Handler:     smtpd.Handler(server.defaultHandler),
	}
	return server, nil
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *SMTPServer) ListenAndServe(tlsConfig *tls.Config, smtpAlive, smtpsAlive chan bool) {
	go func() {
		if tlsConfig == nil {
			return
		}
		srv := &smtpd.Server{Addr: formatAddress(h.options.ListenIP, h.options.SmtpAutoTLSPort), Handler: h.defaultHandler, Appname: "interactsh", Hostname: h.options.Domains[0]}
		srv.TLSConfig = tlsConfig

		smtpsAlive <- true
		err := srv.ListenAndServe()
		if err != nil {
			gologger.Error().Msgf("Could not serve smtp with tls on port %d: %s\n", h.options.SmtpAutoTLSPort, err)
			smtpsAlive <- false
		}
	}()

	smtpAlive <- true
	go func() {
		if err := h.smtpServer.ListenAndServe(); err != nil {
			smtpAlive <- false
			gologger.Error().Msgf("Could not serve smtp on port %d: %s\n", h.options.SmtpPort, err)
		}
	}()
	if err := h.smtpsServer.ListenAndServe(); err != nil {
		gologger.Error().Msgf("Could not serve smtp on port %d: %s\n", h.options.SmtpsPort, err)
		smtpAlive <- false
	}
}

// defaultHandler is a handler for default collaborator requests
func (h *SMTPServer) defaultHandler(remoteAddr net.Addr, from string, to []string, data []byte) error {
	atomic.AddUint64(&h.options.Stats.Smtp, 1)

	dataString := string(data)
	gologger.Debug().Msgf("New SMTP request: %s %s %s %s\n", remoteAddr, from, to, dataString)

	host, _, _ := net.SplitHostPort(remoteAddr.String())

	if h.options.RootTLD {
		for _, addr := range to {
			for _, domain := range h.options.Domains {
				if !stringsutil.HasSuffixI(addr, domain) {
					continue
				}
				address := addr[strings.LastIndex(addr, "@"):]
				h.options.storeRootTLDInteraction(&Interaction{
					Protocol:      "smtp",
					UniqueID:      address,
					FullId:        address,
					RawRequest:    dataString,
					SMTPFrom:      from,
					RemoteAddress: host,
					Timestamp:     time.Now(),
				}, domain)
			}
		}
	}

	// Each matched correlation id is stored independently; previously the loop
	// captured a single uniqueID/fullID and stored it once after the loop, so
	// later false-positive labels could overwrite the legitimate match and
	// the interaction would be persisted under an unregistered id (issue #1362).
	for _, addr := range to {
		if len(addr) <= h.options.GetIdLength() || !strings.Contains(addr, "@") {
			continue
		}
		parts := strings.Split(addr[strings.LastIndex(addr, "@")+1:], ".")
		for i, part := range parts {
			normalizedPart := strings.ToLower(part)
			if !h.options.isCorrelationID(normalizedPart) {
				continue
			}
			fullID := part
			if i+1 <= len(parts) {
				fullID = strings.Join(parts[:i+1], ".")
			}
			h.options.storeInteraction(&Interaction{
				Protocol:      "smtp",
				UniqueID:      normalizedPart,
				FullId:        fullID,
				RawRequest:    dataString,
				SMTPFrom:      from,
				RemoteAddress: host,
				Timestamp:     time.Now(),
			}, normalizedPart[:h.options.CorrelationIdLength])
		}
	}
	return nil
}
