package server

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// HTTPServer is a http server instance that listens both
// TLS and Non-TLS based servers.
type HTTPServer struct {
	options      *Options
	domain       string
	tlsserver    http.Server
	nontlsserver http.Server
}

// NewHTTPServer returns a new TLS & Non-TLS HTTP server.
func NewHTTPServer(options *Options) (*HTTPServer, error) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	server := &HTTPServer{options: options, domain: strings.TrimSuffix(options.Domain, ".")}

	router := &http.ServeMux{}
	router.Handle("/", server.logger(http.HandlerFunc(server.defaultHandler)))
	router.Handle("/register", http.HandlerFunc(server.registerHandler))
	router.Handle("/deregister", http.HandlerFunc(server.deregisterHandler))
	router.Handle("/poll", http.HandlerFunc(server.pollHandler))

	server.tlsserver = http.Server{Addr: "0.0.0.0:443", Handler: router}
	server.nontlsserver = http.Server{Addr: "0.0.0.0:80", Handler: router}
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
	if err := h.nontlsserver.ListenAndServe(); err != nil {
		gologger.Error().Msgf("Could not serve http: %s\n", err)
	}
}

func (h *HTTPServer) logger(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, _ := httputil.DumpRequest(r, true)

		gologger.Debug().Msgf("New HTTP request: %s\n", string(req))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)

		resp, _ := httputil.DumpResponse(rec.Result(), true)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		data := rec.Body.Bytes()

		w.WriteHeader(rec.Result().StatusCode)
		w.Write(data)

		var uniqueID string
		parts := strings.Split(r.Host, ".")
		for _, part := range parts {
			if len(part) == 33 {
				uniqueID = part
			}
		}
		if uniqueID != "" {
			correlationID := uniqueID[:20]

			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			interaction := &Interaction{
				Protocol:      "http",
				UniqueID:      uniqueID,
				RawRequest:    string(req),
				RawResponse:   string(resp),
				RemoteAddress: host,
			}
			buffer := &bytes.Buffer{}
			if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
				gologger.Warning().Msgf("Could not encode http interaction: %s\n", err)
			} else {
				gologger.Debug().Msgf("HTTP Interaction: \n%s\n", string(buffer.Bytes()))
				if err := h.options.Storage.AddInteraction(correlationID, buffer.Bytes()); err != nil {
					gologger.Warning().Msgf("Could not store http interaction: %s\n", err)
				}
			}
		}
	}
}

// defaultHandler is a handler for default collaborator requests
func (h *HTTPServer) defaultHandler(w http.ResponseWriter, req *http.Request) {
	reflection := URLReflection(req.Host)
	w.Header().Set("Server", h.domain)

	if strings.EqualFold(req.URL.Path, "/robots.txt") {
		fmt.Fprintf(w, "User-agent: *\nDisallow: / # %s", reflection)
	} else if strings.HasSuffix(req.URL.Path, ".json") {
		fmt.Fprintf(w, "{\"data\":\"%s\"}", reflection)
		w.Header().Set("Content-Type", "application/json")
	} else if strings.HasSuffix(req.URL.Path, ".xml") {
		fmt.Fprintf(w, "<data>%s</data>", reflection)
		w.Header().Set("Content-Type", "application/xml")
	} else {
		fmt.Fprintf(w, "<html><head></head><body>%s</body></html>", reflection)
	}
}

// RegisterRequest is a request for client registration to interactsh server.
type RegisterRequest struct {
	// PublicKey is the public RSA Key of the client.
	PublicKey []byte `json:"public-key"`
	// SecretKey is the secret-key for correlation ID registered for the client.
	SecretKey string `json:"secret-key"`
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// registerHandler is a handler for client register requests
func (h *HTTPServer) registerHandler(w http.ResponseWriter, req *http.Request) {
	CORSEnabledFunction(w, req)

	r := &RegisterRequest{}
	if err := jsoniter.NewDecoder(req.Body).Decode(r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Warning().Msgf("Could not decode json body: %s\n", err)
		return
	}
	if err := h.options.Storage.SetIDPublicKey(r.CorrelationID, r.SecretKey, r.PublicKey); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Warning().Msgf("Could not set id and public key for %s: %s\n", r.CorrelationID, err)
		return
	}
	gologger.Debug().Msgf("Registered correlationID %s for key\n", r.CorrelationID)
}

// DeregisterRequest is a request for client deregistration to interactsh server.
type DeregisterRequest struct {
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// deregisterHandler is a handler for client deregister requests
func (h *HTTPServer) deregisterHandler(w http.ResponseWriter, req *http.Request) {
	CORSEnabledFunction(w, req)

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
	gologger.Debug().Msgf("Deregistered correlationID %s for key\n", r.CorrelationID)
}

// PollResponse is the response for a polling request
type PollResponse struct {
	Data   []string `json:"data"`
	AESKey string   `json:"aes_key"`
}

// pollHandler is a handler for client poll requests
func (h *HTTPServer) pollHandler(w http.ResponseWriter, req *http.Request) {
	CORSEnabledFunction(w, req)

	ID := req.URL.Query().Get("id")
	if ID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	secret := req.URL.Query().Get("secret")
	if secret == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	data, aesKey, err := h.options.Storage.GetInteractions(ID, secret)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Warning().Msgf("Could not get interactions for %s: %s\n", ID, err)
		return
	}
	response := &PollResponse{Data: data, AESKey: aesKey}
	if err := jsoniter.NewEncoder(w).Encode(response); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		gologger.Warning().Msgf("Could not encode interactions for %s: %s\n", ID, err)
		return
	}
	gologger.Debug().Msgf("Polled %d interactions for %s correlationID\n", len(data), ID)
}

// CORSEnabledFunction is an example of setting CORS headers.
// For more information about CORS and CORS preflight requests, see
// https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request.
// Taken from https://github.com/GoogleCloudPlatform/golang-samples/blob/master/functions/http/cors.go
func CORSEnabledFunction(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers for the preflight request
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8090")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8090")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}
