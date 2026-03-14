package server

import (
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"git.mills.io/prologic/smtpd"
	jsoniter "github.com/json-iterator/go"
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

func (h *SMTPServer) storeInteraction(matchedChunk, fullID, dataString, from, remoteAddr string) {
	if len(matchedChunk) < h.options.CorrelationIdLength {
		return
	}
	correlationID := matchedChunk[:h.options.CorrelationIdLength]
	interaction := &Interaction{
		Protocol:      "smtp",
		UniqueID:      correlationID,
		FullId:        fullID,
		RawRequest:    dataString,
		SMTPFrom:      from,
		RemoteAddress: remoteAddr,
		Timestamp:     time.Now(),
	}
	data, err := jsoniter.Marshal(interaction)
	if err != nil {
		gologger.Warning().Msgf("Could not encode smtp interaction: %s\n", err)
	} else {
		gologger.Debug().Msgf("%s\n", string(data))
		if err := h.options.Storage.AddInteraction(correlationID, data); err != nil {
			gologger.Warning().Msgf("Could not store smtp interaction: %s\n", err)
		}
	}
}

// defaultHandler is a handler for default collaborator requests
func (h *SMTPServer) defaultHandler(remoteAddr net.Addr, from string, to []string, data []byte) error {
	atomic.AddUint64(&h.options.Stats.Smtp, 1)

	dataString := string(data)
	gologger.Debug().Msgf("New SMTP request: %s %s %s %s\n", remoteAddr, from, to, dataString)

	// if root-tld is enabled stores any interaction towards the main domain
	for _, addr := range to {
		if h.options.RootTLD {
			for _, domain := range h.options.Domains {
				if stringsutil.HasSuffixI(addr, domain) {
					ID := domain
					host, _, _ := net.SplitHostPort(remoteAddr.String())
					address := addr[strings.LastIndex(addr, "@"):]
					interaction := &Interaction{
						Protocol:      "smtp",
						UniqueID:      address,
						FullId:        address,
						RawRequest:    dataString,
						SMTPFrom:      from,
						RemoteAddress: host,
						Timestamp:     time.Now(),
					}
					data, err := jsoniter.Marshal(interaction)
					if err != nil {
						gologger.Warning().Msgf("Could not encode root tld SMTP interaction: %s\n", err)
					} else {
						gologger.Debug().Msgf("Root TLD SMTP Interaction: \n%s\n", string(data))
						if err := h.options.Storage.AddInteractionWithId(ID, data); err != nil {
							gologger.Warning().Msgf("Could not store root tld smtp interaction: %s\n", err)
						}
					}
				}
			}
		}
	}

	for _, addr := range to {
		if len(addr) > h.options.getMinIdLength() && strings.Contains(addr, "@") {
			host, _, _ := net.SplitHostPort(remoteAddr.String())
			parts := strings.Split(addr[strings.LastIndex(addr, "@")+1:], ".")
			var matched bool
			// match corrID+nonce in same label (higher confidence)
			for i, part := range parts {
				for partChunk := range stringsutil.SlideWithLength(part, h.options.getMinIdLength()) {
					normalizedPartChunk := strings.ToLower(partChunk)
					if h.options.isCorrelationID(normalizedPartChunk) {
						fullID := strings.Join(parts[:i+1], ".")
						h.storeInteraction(normalizedPartChunk, fullID, dataString, from, host)
						matched = true
					}
				}
			}
			// match bare corrID (no nonce, possibly split corrID and nonce in different subdomain parts)
			if !matched {
				for i, part := range parts {
					normalizedPart := strings.ToLower(part)
					if len(normalizedPart) == h.options.CorrelationIdLength && h.options.isCorrelationID(normalizedPart) {
						fullID := strings.Join(parts[:i+1], ".")
						h.storeInteraction(normalizedPart, fullID, dataString, from, host)
					}
				}
			}
		}
	}
	return nil
}
