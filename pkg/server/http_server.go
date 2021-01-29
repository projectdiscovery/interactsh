package server

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/handlers"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
)

// HTTPServer is a http server instance that listens both
// TLS and Non-TLS based servers.
type HTTPServer struct {
	options      *Options
	tlsserver    http.Server
	nontlsserver http.Server
}

// NewHTTPServer returns a new TLS & Non-TLS HTTP server.
func NewHTTPServer(options *Options) (*HTTPServer, error) {
	server := &HTTPServer{options: options}

	router := &http.ServeMux{}
	router.Handle("/", handlers.CombinedLoggingHandler(os.Stderr, http.HandlerFunc(server.defaultHandler)))
	router.Handle("/register", handlers.CombinedLoggingHandler(os.Stderr, http.HandlerFunc(server.registerHandler)))
	router.Handle("/deregister", handlers.CombinedLoggingHandler(os.Stderr, http.HandlerFunc(server.deregisterHandler)))
	router.Handle("/poll", handlers.CombinedLoggingHandler(os.Stderr, http.HandlerFunc(server.pollHandler)))
	server.tlsserver = http.Server{Addr: "0.0.0.0:443", Handler: handlers.CompressHandler(router)}
	server.nontlsserver = http.Server{Addr: "0.0.0.0:80", Handler: handlers.CompressHandler(router)}
	return server, nil
}

// ListenAndServe listens on http and/or https ports for the server.
func (h *HTTPServer) ListenAndServe() {
	if h.options.CACert != "" && h.options.CAKey != "" {
		go func() {
			if err := h.tlsserver.ListenAndServeTLS(h.options.CACert, h.options.CAKey); err != nil {
				gologger.Error().Msgf("Could not serve http on tls: %s\n", err)
			}
		}()
	}
	go func() {
		if err := h.nontlsserver.ListenAndServe(); err != nil {
			gologger.Error().Msgf("Could not serve http: %s\n", err)
		}
	}()
}

// defaultHandler is a handler for default collaborator requests
func (h *HTTPServer) defaultHandler(w http.ResponseWriter, req *http.Request) {
	reflection := URLReflection(req.URL.Hostname())

	if strings.EqualFold(req.URL.Path, "/robots.txt") {
		fmt.Fprintf(w, "User-agent: *\nDisallow: / # %s", reflection)
	} else if strings.HasSuffix(req.URL.Path, ".json") {
		fmt.Fprintf(w, "{\"data\":\"%s\"}", reflection)
		w.Header().Set("Content-Type", "application/json")
	} else if strings.HasSuffix(req.URL.Path, ".xml") {
		fmt.Fprintf(w, "<data>%s</data>", reflection)
		w.Header().Set("Content-Type", "application/xml")
	} else {
		fmt.Fprintf(w, "%s", reflection)
	}
}

// RegisterRequest is a request for client registration to interactsh server.
type RegisterRequest struct {
	// PublicKey is the public RSA Key of the client.
	PublicKey []byte `json:"public-key"`
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// registerHandler is a handler for client register requests
func (h *HTTPServer) registerHandler(w http.ResponseWriter, req *http.Request) {
	r := &RegisterRequest{}
	if err := jsoniter.NewDecoder(req.Body).Decode(r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Warning().Msgf("Could not decode json body: %s\n", err)
		return
	}
	if err := h.options.Storage.SetIDPublicKey(r.CorrelationID, r.PublicKey); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Warning().Msgf("Could not set id and public key for %s: %s\n", r.CorrelationID, err)
		return
	}
	gologger.Info().Msgf("Registered correlationID %s for key\n", r.CorrelationID)
}

// DeregisterRequest is a request for client deregistration to interactsh server.
type DeregisterRequest struct {
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// deregisterHandler is a handler for client deregister requests
func (h *HTTPServer) deregisterHandler(w http.ResponseWriter, req *http.Request) {
	r := &DeregisterRequest{}
	if err := jsoniter.NewDecoder(req.Body).Decode(r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Warning().Msgf("Could not decode json body: %s\n", err)
		return
	}
	if err := h.options.Storage.RemoveID(r.CorrelationID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Warning().Msgf("Could not remove id for %s: %s\n", r.CorrelationID, err)
		return
	}
	gologger.Info().Msgf("Deregistered correlationID %s for key\n", r.CorrelationID)
}

// PollResponse is the response for a polling request
type PollResponse struct {
	Data [][]byte `json:"data"`
}

// pollHandler is a handler for client poll requests
func (h *HTTPServer) pollHandler(w http.ResponseWriter, req *http.Request) {
	ID := req.URL.Query().Get("id")
	if ID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	data, err := h.options.Storage.GetInteractions(ID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Warning().Msgf("Could not get interactions for %s: %s\n", ID, err)
		return
	}
	response := &PollResponse{Data: data}
	if err := jsoniter.NewEncoder(w).Encode(response); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Warning().Msgf("Could not encode interactions for %s: %s\n", ID, err)
		return
	}
	gologger.Info().Msgf("Polled %d interactions for %s correlationID\n", len(data), ID)
}
