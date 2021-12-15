package server

import (
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"git.mills.io/prologic/smtpd"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
)

// SMTPServer is a smtp server instance that listens both
// TLS and Non-TLS based servers.
type SMTPServer struct {
	options       *Options
	port25server  smtpd.Server
	port587server smtpd.Server
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
	server.port25server = smtpd.Server{
		Addr:        options.ListenIP + ":25",
		AuthHandler: authHandler,
		HandlerRcpt: rcptHandler,
		Hostname:    options.Domain,
		Appname:     "interactsh",
		Handler:     smtpd.Handler(server.defaultHandler),
	}
	server.port587server = smtpd.Server{
		Addr:        options.ListenIP + ":587",
		AuthHandler: authHandler,
		HandlerRcpt: rcptHandler,
		Hostname:    options.Domain,
		Appname:     "interactsh",
		Handler:     smtpd.Handler(server.defaultHandler),
	}
	return server, nil
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *SMTPServer) ListenAndServe(autoTLS *acme.AutoTLS, smtpAlive, smtpsAlive chan bool) {
	go func() {
		if autoTLS == nil {
			return
		}
		srv := &smtpd.Server{Addr: h.options.ListenIP + ":465", Handler: h.defaultHandler, Appname: "interactsh", Hostname: h.options.Domain}
		srv.TLSConfig = &tls.Config{}
		srv.TLSConfig.GetCertificate = autoTLS.GetCertificateFunc()

		smtpsAlive <- true
		err := srv.ListenAndServe()
		if err != nil {
			smtpsAlive <- false
			gologger.Error().Msgf("Could not serve smtp with tls on port 465: %s\n", err)
		}
	}()

	smtpAlive <- true
	go func() {
		if err := h.port25server.ListenAndServe(); err != nil {
			smtpAlive <- false
			gologger.Error().Msgf("Could not serve smtp on port 25: %s\n", err)
		}
	}()
	if err := h.port587server.ListenAndServe(); err != nil {
		smtpAlive <- false
		gologger.Error().Msgf("Could not serve smtp on port 587: %s\n", err)
	}
}

// defaultHandler is a handler for default collaborator requests
func (h *SMTPServer) defaultHandler(remoteAddr net.Addr, from string, to []string, data []byte) error {
	var uniqueID, fullID string

	dataString := string(data)
	gologger.Debug().Msgf("New SMTP request: %s %s %s %s\n", remoteAddr, from, to, dataString)

	// if root-tld is enabled stores any interaction towards the main domain
	for _, addr := range to {
		if h.options.RootTLD && strings.HasSuffix(addr, h.options.Domain) {
			ID := h.options.Domain
			host, _, _ := net.SplitHostPort(remoteAddr.String())
			address := addr[strings.Index(addr, "@"):]
			interaction := &Interaction{
				Protocol:      "smtp",
				UniqueID:      address,
				FullId:        address,
				RawRequest:    dataString,
				SMTPFrom:      from,
				RemoteAddress: host,
				Timestamp:     time.Now(),
			}
			buffer := &bytes.Buffer{}
			if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
				gologger.Warning().Msgf("Could not encode root tld SMTP interaction: %s\n", err)
			} else {
				gologger.Debug().Msgf("Root TLD SMTP Interaction: \n%s\n", buffer.String())
				if err := h.options.Storage.AddInteractionWithId(ID, buffer.Bytes()); err != nil {
					gologger.Warning().Msgf("Could not store root tld smtp interaction: %s\n", err)
				}
			}
		}
	}

	for _, addr := range to {
		if len(addr) > 33 && strings.Contains(addr, "@") {
			parts := strings.Split(addr[strings.Index(addr, "@")+1:], ".")
			for i, part := range parts {
				if len(part) == 33 {
					uniqueID = part
					fullID = part
					if i+1 <= len(parts) {
						fullID = strings.Join(parts[:i+1], ".")
					}
				}
			}
		}
	}
	if uniqueID != "" {
		host, _, _ := net.SplitHostPort(remoteAddr.String())

		correlationID := uniqueID[:20]
		interaction := &Interaction{
			Protocol:      "smtp",
			UniqueID:      uniqueID,
			FullId:        fullID,
			RawRequest:    dataString,
			SMTPFrom:      from,
			RemoteAddress: host,
			Timestamp:     time.Now(),
		}
		buffer := &bytes.Buffer{}
		if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
			gologger.Warning().Msgf("Could not encode smtp interaction: %s\n", err)
		} else {
			gologger.Debug().Msgf("%s\n", buffer.String())
			if err := h.options.Storage.AddInteraction(correlationID, buffer.Bytes()); err != nil {
				gologger.Warning().Msgf("Could not store smtp interaction: %s\n", err)
			}
		}
	}
	return nil
}
