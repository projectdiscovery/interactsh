package server

import (
	"log"

	ldap "github.com/Mzack9999/ldapserver"
	"github.com/lor00x/goldap/message"
	"github.com/projectdiscovery/gologger"
)

func init() {
	ldap.Logger = ldap.DiscardingLogger
}

// LDAPServer is a ldap server instance
type LDAPServer struct {
	options *Options
	server  *ldap.Server
}

// NewLDAPServer returns a new LDAP server.
func NewLDAPServer(options *Options) (*LDAPServer, error) {
	ldapserver := &LDAPServer{options: options}
	routes := ldap.NewRouteMux()
	routes.Bind(ldapserver.defaultHandler)
	server := ldap.NewServer()
	server.Handle(routes)
	ldapserver.server = server

	return ldapserver, nil
}

// ListenAndServe listens on ldap ports for the server.
func (h *LDAPServer) ListenAndServe() {
	defer func() {
		if err := recover(); err != nil {
			log.Println("idiot panic occurred:", err)
		}
	}()
	if err := h.server.ListenAndServe(h.options.ListenIP + ":10389"); err != nil {
		gologger.Error().Msgf("Could not serve ldap on port 10389: %s\n", err)
	}
}

// defaultHandler is a handler for default collaborator requests
func (h *LDAPServer) defaultHandler(w ldap.ResponseWriter, m *ldap.Message) {
	switch m.ProtocolOp().(type) {
	case message.BindRequest:
		r := m.GetBindRequest()
		gologger.Debug().Msgf("New LDAP request: %s %s %s\n", m.Client.Addr(), r.Name(), r.Authentication())
		w.Write(ldap.NewBindResponse(ldap.LDAPResultSuccess))
	default:
		// ignore
	}
}
