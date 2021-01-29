package server

import (
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/julienschmidt/httprouter"
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

	router := httprouter.New()
	router.POST("/register", server.registerHandler)
	router.POST("/deregister", server.deregisterHandler)
	router.GET("/poll", server.pollHandler)
	router.GET("/*", server.defaultHandler)
	return server, nil
}

// defaultHandler is a handler for default collaborator requests
func (h *HTTPServer) defaultHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	reflection := URLReflection(req.URL.Hostname())

	if strings.EqualFold(req.URL.Path, "/robots.txt") {
		fmt.Fprintf(w, "User-agent: *\nDisallow: / # %s", reflection)
	} else if strings.HasSuffix(req.URL.Path, ".json") {
		fmt.Fprintf(w, "{\"data\":\"%s\"}", reflection)
	} else if strings.HasSuffix(req.URL.Path, ".xml") {
		fmt.Fprintf(w, "<data>%s</data>", reflection)
	} else {
		fmt.Fprintf(w, "%s", reflection)
	}
	w.WriteHeader(http.StatusOK)
}

// RegisterRequest is a request for client registration to interactsh server.
type RegisterRequest struct {
	// PublicKey is the public RSA Key of the client.
	PublicKey []byte `json:"public-key"`
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// registerHandler is a handler for client register requests
func (h *HTTPServer) registerHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	r := &RegisterRequest{}
	if err := jsoniter.NewDecoder(req.Body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := h.options.Storage.SetIDPublicKey(r.CorrelationID, r.PublicKey); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// DeregisterRequest is a request for client deregistration to interactsh server.
type DeregisterRequest struct {
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// deregisterHandler is a handler for client deregister requests
func (h *HTTPServer) deregisterHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	r := &DeregisterRequest{}
	if err := jsoniter.NewDecoder(req.Body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := h.options.Storage.RemoveID(r.CorrelationID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// PollResponse is the response for a polling request
type PollResponse struct {
	Data [][]byte `json:"data"`
}

// pollHandler is a handler for client poll requests
func (h *HTTPServer) pollHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	ID := req.URL.Query().Get("id")
	if ID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	data, err := h.options.Storage.GetInteractions(ID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	response := &PollResponse{Data: data}
	if err := jsoniter.NewEncoder(w).Encode(response); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
