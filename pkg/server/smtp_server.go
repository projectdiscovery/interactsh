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

const (
	// smtpMaxRecipients limits RCPT commands per message.
	smtpMaxRecipients = 50
	// smtpTimeout limits how long a read or a write may block.
	smtpTimeout = 5 * time.Minute
)

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
		// MaxMessageBytes is not set: go-smtp would reject a message whose
		// MAIL SIZE is too large before RCPT, and the interaction would be
		// lost. Data truncates the message instead.
		s.MaxRecipients = smtpMaxRecipients
		s.ReadTimeout = smtpTimeout
		s.WriteTimeout = smtpTimeout
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

	// A message is stored once per bucket, however many RCPT lines name it:
	// one body with N recipients must not be kept N times.
	if h.options.RootTLD {
		storedDomains := make(map[string]struct{})
		for _, addr := range recipients {
			for _, domain := range h.options.Domains {
				if !stringsutil.HasSuffixI(addr, domain) {
					continue
				}
				if _, ok := storedDomains[domain]; ok {
					continue
				}
				storedDomains[domain] = struct{}{}
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
	// A repeated unique id is skipped. Other unique ids of a correlation id
	// that already has the message are kept without the raw message.
	storedUniqueIDs := make(map[string]struct{})
	storedCorrelationIDs := make(map[string]struct{})
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
			if _, ok := storedUniqueIDs[normalizedPart]; ok {
				continue
			}
			storedUniqueIDs[normalizedPart] = struct{}{}
			correlationID := normalizedPart[:h.options.CorrelationIdLength]
			raw := rawRequest
			if _, ok := storedCorrelationIDs[correlationID]; ok {
				raw = ""
			}
			storedCorrelationIDs[correlationID] = struct{}{}
			fullID := part
			if i+1 <= len(parts) {
				fullID = strings.Join(parts[:i+1], ".")
			}
			h.options.storeInteraction(&Interaction{
				Protocol:      "smtp",
				UniqueID:      normalizedPart,
				FullId:        fullID,
				RawRequest:    raw,
				SMTPFrom:      from,
				RemoteAddress: host,
				Timestamp:     time.Now(),
			}, correlationID)
		}
	}
}
