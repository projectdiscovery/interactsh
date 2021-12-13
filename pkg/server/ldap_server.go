package server

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	ldap "github.com/Mzack9999/ldapserver"
	jsoniter "github.com/json-iterator/go"
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
	ldap.Logger = ldapserver
	routes := ldap.NewRouteMux()
	routes.Bind(ldapserver.defaultHandler)
	server := ldap.NewServer()
	err := server.Handle(routes)
	if err != nil {
		return nil, err
	}
	ldapserver.server = server

	return ldapserver, nil
}

// ListenAndServe listens on ldap ports for the server.
func (h *LDAPServer) ListenAndServe() {
	defer func() {
		// recover from panic within the third party library
		if err := recover(); err != nil {
			gologger.Error().Msgf("%s\n", err)
		}
	}()
	if err := h.server.ListenAndServe(h.options.ListenIP + ":10389"); err != nil {
		gologger.Error().Msgf("Could not serve ldap on port 10389: %s\n", err)
	}
}

// defaultHandler is a handler for default collaborator requests
func (h *LDAPServer) defaultHandler(w ldap.ResponseWriter, m *ldap.Message) {
	w.Write(ldap.NewBindResponse(ldap.LDAPResultSuccess))
}

func (h *LDAPServer) Close() error {
	return h.server.Listener.Close()
}

func (ldapServer *LDAPServer) Fatal(v ...interface{}) {
	//nolint
	ldapServer.handleLog("%v", v...) //nolint
}
func (ldapServer *LDAPServer) Fatalf(format string, v ...interface{}) {
	ldapServer.handleLog(format, v...)
}
func (ldapServer *LDAPServer) Fatalln(v ...interface{}) {
	ldapServer.handleLog("%v", v...) //nolint
}
func (ldapServer *LDAPServer) Panic(v ...interface{}) {
	ldapServer.handleLog("%v", v...) //nolint
}
func (ldapServer *LDAPServer) Panicf(format string, v ...interface{}) {
	ldapServer.handleLog(format, v...)
}
func (ldapServer *LDAPServer) Panicln(v ...interface{}) {
	ldapServer.handleLog("%v", v...) //nolint
}
func (ldapServer *LDAPServer) Print(v ...interface{}) {
	ldapServer.handleLog("%v", v...) //nolint
}
func (ldapServer *LDAPServer) Printf(format string, v ...interface{}) {
	ldapServer.handleLog(format, v...)
}
func (ldapServer *LDAPServer) Println(v ...interface{}) {
	ldapServer.handleLog("%v", v...) //nolint
}

func (ldapServer *LDAPServer) handleLog(f string, v ...interface{}) {
	var data strings.Builder
	if f != "" {
		data.WriteString(fmt.Sprintf(f, v...))
	} else {
		for _, vv := range v {
			data.WriteString(fmt.Sprint(vv))
		}
	}

	// Correlation id doesn't apply here, we skip encryption
	interaction := &Interaction{
		Protocol:   "ldap",
		RawRequest: data.String(),
		Timestamp:  time.Now(),
	}
	buffer := &bytes.Buffer{}
	if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
		gologger.Warning().Msgf("Could not encode ldap interaction: %s\n", err)
	} else {
		gologger.Debug().Msgf("LDAP Interaction: \n%s\n", buffer.String())
		if err := ldapServer.options.Storage.AddInteractionWithId(ldapServer.options.Token, buffer.Bytes()); err != nil {
			gologger.Warning().Msgf("Could not store ldap interaction: %s\n", err)
		}
	}
}
