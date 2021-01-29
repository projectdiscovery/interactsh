package server

import (
	"bytes"
	"fmt"
	"net"
	"net/mail"

	"github.com/projectdiscovery/gologger"
	"github.com/prologic/smtpd"
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
		Addr:        "0.0.0.0:25",
		AuthHandler: authHandler,
		HandlerRcpt: rcptHandler,
		Hostname:    options.Domain,
		Appname:     "interactsh",
		Handler:     smtpd.Handler(server.defaultHandler),
	}
	server.port587server = smtpd.Server{
		Addr:        "0.0.0.0:487",
		AuthHandler: authHandler,
		HandlerRcpt: rcptHandler,
		Hostname:    options.Domain,
		Appname:     "interactsh",
		Handler:     smtpd.Handler(server.defaultHandler),
	}
	return server, nil
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *SMTPServer) ListenAndServe() {
	if h.options.CACert != "" && h.options.CAKey != "" {
		go func() {
			err := smtpd.ListenAndServeTLS("0.0.0.0:465", h.options.CACert, h.options.CAKey, h.defaultHandler, "interactsh", h.options.Domain)
			if err != nil {
				gologger.Error().Msgf("Could not serve smtp with tls on port 465: %s\n", err)
			}
		}()
	}
	go func() {
		if err := h.port25server.ListenAndServe(); err != nil {
			gologger.Error().Msgf("Could not serve smtp on port 25: %s\n", err)
		}
		if err := h.port587server.ListenAndServe(); err != nil {
			gologger.Error().Msgf("Could not serve smtp on port 587: %s\n", err)
		}
	}()
}

// defaultHandler is a handler for default collaborator requests
func (h *SMTPServer) defaultHandler(remoteAddr net.Addr, from string, to []string, data []byte) error {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		gologger.Warning().Msgf("Could not read SMTP message: %s\n", err)
	}
	fmt.Printf("%v %v %v %v %v\n", msg, remoteAddr, from, to, string(data))
	//reflection := URLReflection()
	return nil
}
