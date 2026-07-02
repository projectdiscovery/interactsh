package server

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// SMTPServer is a smtp server instance that listens both
// TLS and Non-TLS based servers.
type SMTPServer struct {
	options           *Options
	backend           *interactshBackend
	smtpServer        *smtp.Server
	smtpsServer       *smtp.Server
	smtpAutoTLSServer *smtp.Server
}

// NewSMTPServer returns a new TLS & Non-TLS SMTP server.
func NewSMTPServer(options *Options) (*SMTPServer, error) {
	server := &SMTPServer{options: options}
	server.backend = &interactshBackend{srv: server}

	newEmersionServer := func(addr string, tlsConfig *tls.Config) *smtp.Server {
		s := smtp.NewServer(server.backend)
		s.Addr = addr
		s.Domain = options.Domains[0]
		s.AllowInsecureAuth = true
		s.TLSConfig = tlsConfig
		return s
	}

	server.smtpServer = newEmersionServer(formatAddress(options.ListenIP, options.SmtpPort), nil)
	server.smtpsServer = newEmersionServer(formatAddress(options.ListenIP, options.SmtpsPort), nil)
	server.smtpAutoTLSServer = newEmersionServer(formatAddress(options.ListenIP, options.SmtpAutoTLSPort), nil)
	return server, nil
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *SMTPServer) ListenAndServe(tlsConfig *tls.Config, smtpAlive, smtpsAlive chan bool) {
	if tlsConfig != nil {
		h.smtpAutoTLSServer.TLSConfig = tlsConfig
		go func() {
			smtpsAlive <- true
			if err := h.smtpAutoTLSServer.ListenAndServeTLS(); err != nil {
				gologger.Error().Msgf("Could not serve smtp with tls on port %d: %s\n", h.options.SmtpAutoTLSPort, err)
				smtpsAlive <- false
			}
		}()
	}

	smtpAlive <- true
	go func() {
		if err := h.smtpServer.ListenAndServe(); err != nil {
			smtpAlive <- false
			gologger.Error().Msgf("Could not serve smtp on port %d: %s\n", h.options.SmtpPort, err)
		}
	}()
	if err := h.smtpsServer.ListenAndServe(); err != nil {
		gologger.Error().Msgf("Could not serve smtp on port %d: %s\n", h.options.SmtpsPort, err)
		smtpsAlive <- false
	}
}

// defaultHandler is kept for unit tests that exercise storage without
// standing up a TCP listener.
func (h *SMTPServer) defaultHandler(remoteAddr net.Addr, from string, to []string, data []byte) error {
	return h.deliverSMTP(remoteAddr, from, to, data)
}

// storeSMTPRecipients persists SMTP interactions for correlation ids found
// in the recipient addresses.
func (h *SMTPServer) storeSMTPRecipients(remoteAddr net.Addr, from, rawRequest string, recipients []string) {
	host, _, _ := net.SplitHostPort(remoteAddr.String())

	if h.options.RootTLD {
		for _, addr := range recipients {
			for _, domain := range h.options.Domains {
				if !stringsutil.HasSuffixI(addr, domain) {
					continue
				}
				address := addr[strings.LastIndex(addr, "@"):]
				h.options.storeRootTLDInteraction(&Interaction{
					Protocol:      "smtp",
					UniqueID:      address,
					FullId:        address,
					RawRequest:    rawRequest,
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
	for _, addr := range recipients {
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
				RawRequest:    rawRequest,
				SMTPFrom:      from,
				RemoteAddress: host,
				Timestamp:     time.Now(),
			}, normalizedPart[:h.options.CorrelationIdLength])
		}
	}
}
