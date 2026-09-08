package server

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// HTTPServer is a http server instance that listens both
// TLS and Non-TLS based servers.
type HTTPServer struct {
	options         *Options
	tlsserver       http.Server
	nontlsserver    http.Server
	customBanner    string
	defaultResponse string
	staticHandler   http.Handler

	// dynamic API doc endpoints
	dynamicEndpoints map[string]dynamicEndpoint
	dynMu            sync.RWMutex
}

type dynamicEndpoint struct {
	Body        []byte
	ContentType string
	LastUpdated time.Time
}

type noopLogger struct {
}

func (l *noopLogger) Write(p []byte) (n int, err error) {
	return 0, nil
}

// disableDirectoryListing disables directory listing on http.FileServer
func disableDirectoryListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewHTTPServer returns a new TLS & Non-TLS HTTP server.
func NewHTTPServer(options *Options) (*HTTPServer, error) {
	server := &HTTPServer{options: options}

	// If a static directory is specified, also serve it.
	if options.HTTPDirectory != "" {
		abs, _ := filepath.Abs(options.HTTPDirectory)
		gologger.Info().Msgf("Loading directory (%s) to serve from : %s/s/", abs, strings.Join(options.Domains, ","))
		server.staticHandler = http.StripPrefix("/s/", disableDirectoryListing(http.FileServer(http.Dir(options.HTTPDirectory))))
	}
	// If custom index, read the custom index file and serve it.
	// Supports {DOMAIN} placeholders.
	if options.HTTPIndex != "" {
		abs, _ := filepath.Abs(options.HTTPIndex)
		gologger.Info().Msgf("Using custom server index: %s", abs)
		if data, err := os.ReadFile(options.HTTPIndex); err == nil {
			server.customBanner = string(data)
		}
	}
	// If default response file is specified, read it and serve for all requests.
	// This takes priority over all other response options.
	// Supports {DOMAIN} placeholders.
	if options.DefaultHTTPResponseFile != "" {
		abs, _ := filepath.Abs(options.DefaultHTTPResponseFile)
		gologger.Info().Msgf("Using default HTTP response file for all requests: %s", abs)
		if data, err := os.ReadFile(options.DefaultHTTPResponseFile); err == nil {
			server.defaultResponse = string(data)
		}
	}
	router := &http.ServeMux{}

	server.dynamicEndpoints = make(map[string]dynamicEndpoint)
	router.Handle("/storerequest", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.storeHandler))))
	router.Handle("/apidocs/", server.corsMiddleware(http.HandlerFunc(server.apidocsHandler)))
	router.Handle("/", server.logger(server.corsMiddleware(http.HandlerFunc(server.defaultHandler))))
	router.Handle("/register", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.registerHandler))))
	router.Handle("/serve/", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.deregisterHandler))))
	router.Handle("/deregister", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.deregisterHandler))))
	router.Handle("/poll", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.pollHandler))))
	if server.options.EnableMetrics {
		router.Handle("/metrics", server.corsMiddleware(server.authMiddleware(http.HandlerFunc(server.metricsHandler))))
	}
	server.tlsserver = http.Server{Addr: formatAddress(options.ListenIP, options.HttpsPort), Handler: router, ErrorLog: log.New(&noopLogger{}, "", 0)}
	server.nontlsserver = http.Server{Addr: formatAddress(options.ListenIP, options.HttpPort), Handler: router, ErrorLog: log.New(&noopLogger{}, "", 0)}
	return server, nil
}

// ListenAndServe listens on http and/or https ports for the server.
func (h *HTTPServer) ListenAndServe(tlsConfig *tls.Config, httpAlive, httpsAlive chan bool) {
	go func() {
		if tlsConfig == nil {
			return
		}
		h.tlsserver.TLSConfig = tlsConfig

		httpsAlive <- true
		if err := h.tlsserver.ListenAndServeTLS("", ""); err != nil {
			gologger.Error().Msgf("Could not serve http on tls: %s\n", err)
			httpsAlive <- false
		}
	}()

	httpAlive <- true
	if err := h.nontlsserver.ListenAndServe(); err != nil {
		httpAlive <- false
		gologger.Error().Msgf("Could not serve http: %s\n", err)
	}
}

func (h *HTTPServer) logger(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, _ := httputil.DumpRequest(r, true)
		reqString := string(req)

		gologger.Debug().Msgf("New HTTP request: \n\n%s\n", reqString)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)

		resp, _ := httputil.DumpResponse(rec.Result(), true)
		respString := string(resp)

		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		data := rec.Body.Bytes()

		w.WriteHeader(rec.Result().StatusCode)
		_, _ = w.Write(data)

		var host string
		// Check if the client's ip should be taken from a custom header (eg reverse proxy)
		if originIP := r.Header.Get(h.options.OriginIPHeader); originIP != "" {
			host = originIP
		} else {
			host, _, _ = net.SplitHostPort(r.RemoteAddr)
		}

		// if root-tld is enabled stores any interaction towards the main domain
		if h.options.RootTLD {
			for _, domain := range h.options.Domains {
				if h.options.RootTLD && stringsutil.HasSuffixI(r.Host, domain) {
					ID := domain
					host, _, _ := net.SplitHostPort(r.RemoteAddr)
					interaction := &Interaction{
						Protocol:      httpProtocol(r),
						UniqueID:      r.Host,
						FullId:        r.Host,
						RawRequest:    reqString,
						RawResponse:   respString,
						RemoteAddress: host,
						Timestamp:     time.Now(),
					}
					data, err := jsoniter.Marshal(interaction)
					if err != nil {
						gologger.Warning().Msgf("Could not encode root tld http interaction: %s\n", err)
					} else {
						gologger.Debug().Msgf("Root TLD HTTP Interaction: \n%s\n", string(data))
						if err := h.options.Storage.AddInteractionWithId(ID, data); err != nil {
							gologger.Warning().Msgf("Could not store root tld http interaction: %s\n", err)
						}
					}
				}
			}
		}

		if h.options.ScanEverywhere {
			chunks := stringsutil.SplitAny(reqString, "\n\t\"'/")
			for _, chunk := range chunks {
				for part := range stringsutil.SlideWithLength(chunk, h.options.GetIdLength()) {
					normalizedPart := strings.ToLower(part)
					if h.options.isCorrelationID(normalizedPart) {
						fullID := chunk
						h.handleInteraction(r, normalizedPart, fullID, reqString, respString, host)
					}
				}
			}
		} else {
			url := r.Host + r.URL.String()
			gologger.Debug().Msgf("Scanning in url %s, host %s, urlhost: %s, path %s\n", url, r.Host, r.URL.Host, r.URL.Path)
			parts := stringsutil.SplitAny(url, ".\n\t/")
			for i, part := range parts {
				for partChunk := range stringsutil.SlideWithLength(part, h.options.GetIdLength()) {
					normalizedPartChunk := strings.ToLower(partChunk)
					if h.options.isCorrelationID(normalizedPartChunk) {
						fullID := part
						if i+1 <= len(parts) {
							fullID = strings.Join(parts[:i+1], ".")
						}
						h.handleInteraction(r, normalizedPartChunk, fullID, reqString, respString, host)
					}
				}
			}
		}
	}
}

func httpProtocol(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func (h *HTTPServer) handleInteraction(r *http.Request, uniqueID, fullID, reqString, respString, hostPort string) {
	correlationID := uniqueID[:h.options.CorrelationIdLength]

	interaction := &Interaction{
		Protocol:      httpProtocol(r),
		UniqueID:      uniqueID,
		FullId:        fullID,
		RawRequest:    reqString,
		RawResponse:   respString,
		RemoteAddress: hostPort,
		Timestamp:     time.Now(),
	}
	data, err := jsoniter.Marshal(interaction)
	if err != nil {
		gologger.Warning().Msgf("Could not encode http interaction: %s\n", err)
	} else {
		gologger.Debug().Msgf("HTTP Interaction: \n%s\n", string(data))

		if err := h.options.Storage.AddInteraction(correlationID, data); err != nil {
			gologger.Warning().Msgf("Could not store http interaction: %s\n", err)
		}
	}
}

const banner = `<h1> Interactsh Server </h1>

<a href='https://github.com/projectdiscovery/interactsh'><b>Interactsh</b></a> is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions.<br><br>

If you notice any interactions from <b>*.%s</b> in your logs, it's possible that someone (internal security engineers, pen-testers, bug-bounty hunters) has been testing your application.<br><br>

You should investigate the sites where these interactions were generated from, and if a vulnerability exists, examine the root cause and take the necessary steps to mitigate the issue.
`

func extractServerDomain(h *HTTPServer, req *http.Request) string {
	if h.options.HeaderServer != "" {
		return h.options.HeaderServer
	}

	var domain string
	// use first domain as default (todo: should be extracted from certificate)
	if len(h.options.Domains) > 0 {
		// attempts to extract the domain name from host header
		for _, configuredDomain := range h.options.Domains {
			if stringsutil.HasSuffixI(req.Host, configuredDomain) {
				domain = configuredDomain
				break
			}
		}
		// fallback to first domain in case of unknown host header
		if domain == "" {
			domain = h.options.Domains[0]
		}
	}
	return domain
}

// defaultHandler is a handler for default collaborator requests
func (h *HTTPServer) defaultHandler(w http.ResponseWriter, req *http.Request) {
	atomic.AddUint64(&h.options.Stats.Http, 1)

	domain := extractServerDomain(h, req)
	w.Header().Set("Server", domain)
	if !h.options.NoVersionHeader {
		w.Header().Set("X-Interactsh-Version", h.options.Version)
	}

	reflection := h.options.URLReflection(req.Host)

	// If default response is set, serve it for all requests (highest priority)
	if h.defaultResponse != "" {
		_, _ = fmt.Fprint(w, strings.ReplaceAll(h.defaultResponse, "{DOMAIN}", domain))
		return
	}

	if stringsutil.HasPrefixI(req.URL.Path, "/s/") && h.staticHandler != nil {
		if h.options.DynamicResp && len(req.URL.Query()) > 0 {
			values := req.URL.Query()
			if headers := values["header"]; len(headers) > 0 {
				for _, header := range headers {
					if headerParts := strings.SplitN(header, ":", 2); len(headerParts) == 2 {
						w.Header().Add(headerParts[0], headerParts[1])
					}
				}
			}
			if delay := values.Get("delay"); delay != "" {
				if parsed, err := strconv.Atoi(delay); err == nil {
					time.Sleep(time.Duration(parsed) * time.Second)
				}
			}
			if status := values.Get("status"); status != "" {
				if parsed, err := strconv.Atoi(status); err == nil {
					w.WriteHeader(parsed)
				}
			}
		}
		h.staticHandler.ServeHTTP(w, req)
	} else if req.URL.Path == "/" && reflection == "" {
		if h.customBanner != "" {
			_, _ = fmt.Fprint(w, strings.ReplaceAll(h.customBanner, "{DOMAIN}", domain))
		} else {
			_, _ = fmt.Fprintf(w, banner, domain)
		}
	} else if strings.EqualFold(req.URL.Path, "/robots.txt") {
		_, _ = fmt.Fprintf(w, "User-agent: *\nDisallow: / # %s", reflection)
	} else if stringsutil.HasSuffixI(req.URL.Path, ".json") {
		_, _ = fmt.Fprintf(w, "{\"data\":\"%s\"}", reflection)
		w.Header().Set("Content-Type", "application/json")
	} else if stringsutil.HasSuffixI(req.URL.Path, ".xml") {
		_, _ = fmt.Fprintf(w, "<data>%s</data>", reflection)
		w.Header().Set("Content-Type", "application/xml")
	} else {
		if h.options.DynamicResp && (len(req.URL.Query()) > 0 || stringsutil.HasPrefixI(req.URL.Path, "/b64_body:")) {
			writeResponseFromDynamicRequest(w, req)
			return
		}
		_, _ = fmt.Fprintf(w, "<html><head></head><body>%s</body></html>", reflection)
	}
}

// writeResponseFromDynamicRequest writes a response to http.ResponseWriter
// based on dynamic data from HTTP URL Query parameters.
//
// The following parameters are supported -
//
//	body (response body)
//	header (response header)
//	status (response status code)
//	delay (response time)
func writeResponseFromDynamicRequest(w http.ResponseWriter, req *http.Request) {
	values := req.URL.Query()

	if stringsutil.HasPrefixI(req.URL.Path, "/b64_body:") {
		firstindex := strings.Index(req.URL.Path, "/b64_body:")
		lastIndex := strings.LastIndex(req.URL.Path, "/")

		decodedBytes, _ := base64.StdEncoding.DecodeString(req.URL.Path[firstindex+10 : lastIndex])
		_, _ = w.Write(decodedBytes)

	}
	if headers := values["header"]; len(headers) > 0 {
		for _, header := range headers {
			if headerParts := strings.SplitN(header, ":", 2); len(headerParts) == 2 {
				w.Header().Add(headerParts[0], headerParts[1])
			}
		}
	}
	if delay := values.Get("delay"); delay != "" {
		parsed, _ := strconv.Atoi(delay)
		time.Sleep(time.Duration(parsed) * time.Second)
	}
	if status := values.Get("status"); status != "" {
		parsed, _ := strconv.Atoi(status)
		w.WriteHeader(parsed)
	}
	if body := values.Get("body"); body != "" {
		_, _ = w.Write([]byte(body))
	}

	if b64_body := values.Get("b64_body"); b64_body != "" {
		decodedBytes, _ := base64.StdEncoding.DecodeString(string([]byte(b64_body)))
		_, _ = w.Write(decodedBytes)
	}
}

// RegisterRequest is a request for client registration to interactsh server.
type RegisterRequest struct {
	// PublicKey is the public RSA Key of the client.
	PublicKey string `json:"public-key"`
	// SecretKey is the secret-key for correlation ID registered for the client.
	SecretKey string `json:"secret-key"`
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// registerHandler is a handler for client register requests
func (h *HTTPServer) registerHandler(w http.ResponseWriter, req *http.Request) {
	r := &RegisterRequest{}
	if err := jsoniter.NewDecoder(req.Body).Decode(r); err != nil {
		gologger.Warning().Msgf("Could not decode json body: %s\n", err)
		jsonError(w, fmt.Sprintf("could not decode json body: %s", err), http.StatusBadRequest)
		return
	}

	atomic.AddInt64(&h.options.Stats.Sessions, 1)

	if err := h.options.Storage.SetIDPublicKey(r.CorrelationID, r.SecretKey, r.PublicKey); err != nil {
		gologger.Warning().Msgf("Could not set id and public key for %s: %s\n", r.CorrelationID, err)
		jsonError(w, fmt.Sprintf("could not set id and public key: %s", err), http.StatusBadRequest)
		return
	}
	jsonMsg(w, "registration successful", http.StatusOK)
	gologger.Debug().Msgf("Registered correlationID %s for key\n", r.CorrelationID)
}

// DeregisterRequest is a request for client deregistration to interactsh server.
type DeregisterRequest struct {
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
	// SecretKey is the secretKey for the interactsh client.
	SecretKey string `json:"secret-key"`
}

// deregisterHandler is a handler for client deregister requests
func (h *HTTPServer) deregisterHandler(w http.ResponseWriter, req *http.Request) {
	atomic.AddInt64(&h.options.Stats.Sessions, -1)

	r := &DeregisterRequest{}
	if err := jsoniter.NewDecoder(req.Body).Decode(r); err != nil {
		gologger.Warning().Msgf("Could not decode json body: %s\n", err)
		jsonError(w, fmt.Sprintf("could not decode json body: %s", err), http.StatusBadRequest)
		return
	}

	if err := h.options.Storage.RemoveID(r.CorrelationID, r.SecretKey); err != nil {
		gologger.Warning().Msgf("Could not remove id for %s: %s\n", r.CorrelationID, err)
		jsonError(w, fmt.Sprintf("could not remove id: %s", err), http.StatusBadRequest)
		return
	}
	if h.options.RootTLD {
		for _, domain := range h.options.Domains {
			_ = h.options.Storage.RemoveConsumer(domain, r.CorrelationID)
		}
	}
	if h.options.Token != "" {
		_ = h.options.Storage.RemoveConsumer(h.options.Token, r.CorrelationID)
	}
	jsonMsg(w, "deregistration successful", http.StatusOK)
	gologger.Debug().Msgf("Deregistered correlationID %s for key\n", r.CorrelationID)
}

// PollResponse is the response for a polling request
type PollResponse struct {
	Data    []string `json:"data"`
	Extra   []string `json:"extra"`
	AESKey  string   `json:"aes_key"`
	TLDData []string `json:"tlddata,omitempty"`
}

// pollHandler is a handler for client poll requests
func (h *HTTPServer) pollHandler(w http.ResponseWriter, req *http.Request) {
	ID := req.URL.Query().Get("id")
	if ID == "" {
		jsonError(w, "no id specified for poll", http.StatusBadRequest)
		return
	}
	secret := req.URL.Query().Get("secret")
	if secret == "" {
		jsonError(w, "no secret specified for poll", http.StatusBadRequest)
		return
	}

	data, aesKey, err := h.options.Storage.GetInteractions(ID, secret)
	if err != nil {
		gologger.Warning().Msgf("Could not get interactions for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not get interactions: %s", err), http.StatusBadRequest)
		return
	}

	// At this point the client is authenticated, so we return also the data related to the auth token
	var tlddata, extradata []string
	if h.options.RootTLD {
		for _, domain := range h.options.Domains {
			interactions, _ := h.options.Storage.GetInteractionsWithIdForConsumer(domain, ID)
			// root domains interaction are not encrypted
			tlddata = append(tlddata, interactions...)
		}
	}
	if h.options.Token != "" {
		// auth token interactions are not encrypted
		extradata, _ = h.options.Storage.GetInteractionsWithIdForConsumer(h.options.Token, ID)
	}
	response := &PollResponse{Data: data, AESKey: aesKey, TLDData: tlddata, Extra: extradata}

	if err := jsoniter.NewEncoder(w).Encode(response); err != nil {
		gologger.Warning().Msgf("Could not encode interactions for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not encode interactions: %s", err), http.StatusBadRequest)
		return
	}
	gologger.Debug().Msgf("Polled %d interactions for %s correlationID\n", len(data), ID)
}

func (h *HTTPServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Set CORS headers for the preflight request
		if req.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", h.options.OriginURL)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", h.options.OriginURL)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		next.ServeHTTP(w, req)
	})
}

func jsonBody(w http.ResponseWriter, key, value string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = jsoniter.NewEncoder(w).Encode(map[string]interface{}{key: value})
}

func jsonError(w http.ResponseWriter, err string, code int) {
	jsonBody(w, "error", err, code)
}

func jsonMsg(w http.ResponseWriter, msg string, code int) {
	jsonBody(w, "message", msg, code)
}

func (h *HTTPServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !h.checkToken(req) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (h *HTTPServer) checkToken(req *http.Request) bool {
	return !h.options.Auth || h.options.Auth && h.options.Token == req.Header.Get("Authorization")
}

// metricsHandler is a handler for /metrics endpoint
func (h *HTTPServer) metricsHandler(w http.ResponseWriter, req *http.Request) {
	interactMetrics := h.options.Stats
	interactMetrics.Cache = GetCacheMetrics(h.options)
	interactMetrics.Cpu = GetCpuMetrics()
	interactMetrics.Memory = GetMemoryMetrics()
	interactMetrics.Network = GetNetworkMetrics()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = jsoniter.NewEncoder(w).Encode(interactMetrics)
}

// storeHandler is a handler for /storerequest endpoint
func (h *HTTPServer) storeHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type storeReq struct {
		Body        string `json:"body"`
		ContentType string `json:"content_type"`
		SubURL      string `json:"suburl"`
	}
	var sreq storeReq
	err := jsoniter.NewDecoder(req.Body).Decode(&sreq)
	if err != nil || sreq.SubURL == "" {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	h.dynMu.RLock()
	de, exists := h.dynamicEndpoints[sreq.SubURL]
	now := time.Now()
	if exists {
		if now.Sub(de.LastUpdated) < 24*time.Hour {
			jsonError(w, "suburl can only be updated every 24 hours", http.StatusTooManyRequests)
			h.dynMu.RUnlock()
			return
		}
	}
	h.dynMu.RUnlock()

	h.dynMu.Lock()
	h.dynamicEndpoints[sreq.SubURL] = dynamicEndpoint{
		Body:        []byte(sreq.Body),
		ContentType: sreq.ContentType,
		LastUpdated: now,
	}
	h.dynMu.Unlock()

	jsonMsg(w, "endpoint registered", http.StatusOK)
}

// apidocsHandler serves registered dynamic endpoints
func (h *HTTPServer) apidocsHandler(w http.ResponseWriter, req *http.Request) {
	// URL: /apidocs/{suburl}
	path := strings.TrimPrefix(req.URL.Path, "/apidocs/")
	if path == "" {
		jsonError(w, "no suburl provided", http.StatusNotFound)
		return
	}

	h.dynMu.RLock()
	de, ok := h.dynamicEndpoints[path]
	h.dynMu.RUnlock()
	if !ok {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if de.ContentType != "" {
		w.Header().Set("Content-Type", de.ContentType)
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(de.Body); err != nil {
      log.Printf("write error: %v", err)
  }
}
