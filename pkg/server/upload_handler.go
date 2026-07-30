package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/storage"
)

// Capabilities advertises optional server features to clients at registration.
// Clients use it to decide whether to attempt an upload at all, and which URLs
// are worth printing.
type Capabilities struct {
	Upload            bool  `json:"upload"`
	UploadMaxFileSize int64 `json:"upload-max-file-size,omitempty"`
	UploadMaxFiles    int   `json:"upload-max-files,omitempty"`
	FTP               bool  `json:"ftp"`
}

// RegisterResponse is the response to a client registration. The bare
// {"message": ...} shape older clients expect is preserved, so an old client
// against a new server simply ignores the extra key, and a new client against
// an old server sees a nil Capabilities.
type RegisterResponse struct {
	Message      string        `json:"message"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

// UploadFileRequest is a single file within an upload request.
type UploadFileRequest struct {
	Name string `json:"name"`
	Data string `json:"data"` // base64
}

// UploadRequest is a request to host files against a correlation ID.
type UploadRequest struct {
	CorrelationID string              `json:"correlation-id"`
	SecretKey     string              `json:"secret-key"`
	Files         []UploadFileRequest `json:"files"`
}

// UploadedFileResponse describes one hosted file. Paths rather than URLs: the
// server does not know which of its domains, or which scheme, the client will
// use to reference the file.
type UploadedFileResponse struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	HTTPPath string `json:"http-path"`
	FTPPath  string `json:"ftp-path"`
}

// UploadResponse is the response to a successful upload.
type UploadResponse struct {
	Message string                 `json:"message"`
	Files   []UploadedFileResponse `json:"files"`
}

// capabilities describes what this server offers.
func (h *HTTPServer) capabilities() *Capabilities {
	// FTP is advertised only when it can actually reach the hosted files. The
	// client uses this to decide whether an ftp:// URL is worth printing, and a
	// URL pointing into a directory the FTP server does not serve is worse than
	// no URL at all: the target follows it, gets a 550, and the operator reads
	// the silence as "not vulnerable".
	c := &Capabilities{FTP: h.options.Ftp && h.options.FTPServesUploads}
	// Advertised only when the storage backend can track uploads too, so the
	// server never announces a capability uploadHandler would refuse with 501.
	if store := h.options.UploadStore; store != nil && h.options.UploadStorage() != nil {
		c.Upload = true
		c.UploadMaxFileSize = store.MaxFileSize()
		c.UploadMaxFiles = store.MaxFiles()
	}
	return c
}

// maxUploadRequestBytes bounds the request body: every file at its size limit,
// base64 expanded, plus room for JSON framing.
func maxUploadRequestBytes(store *UploadStore) int64 {
	return int64(store.MaxFiles())*store.MaxFileSize()*4/3 + 8192
}

// uploadHandler stores files against a correlation ID for later hosting.
//
// Registered as its own route rather than under "/" so that it never passes
// through the logger middleware, which would otherwise dump the entire request
// body -- i.e. every uploaded file -- into an interaction record. It is
// registered even when uploads are disabled, precisely so that a request to a
// non-upload server gets a clean 501 instead of falling through to that path.
func (h *HTTPServer) uploadHandler(w http.ResponseWriter, req *http.Request) {
	// The token check lives here rather than in authMiddleware so that a request
	// failing it can be recorded first; see the route registration for why that
	// matters. Recording is deliberately limited to requests no legitimate client
	// could have sent: an authenticated upload is the operator's own traffic, and
	// filing it as an interaction would attribute their action to the target.
	if !h.checkToken(req) {
		h.recordUploadProbe(req, http.StatusUnauthorized, "")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	store := h.options.UploadStore
	uploadStorage := h.options.UploadStorage()
	// uploadStorage is nil when the configured storage backend cannot track
	// uploads (a shared backend such as Redis). Treated the same as uploads
	// being switched off, so the client sees the usual capability signal.
	if store == nil || uploadStorage == nil {
		// A client that has seen this server's capabilities does not send an
		// upload here at all, so this is a probe too.
		const message = "file upload is not enabled on this server"
		h.recordUploadProbe(req, http.StatusNotImplemented, message)
		jsonError(w, message, http.StatusNotImplemented)
		return
	}
	if req.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req.Body = http.MaxBytesReader(w, req.Body, maxUploadRequestBytes(store))

	r := &UploadRequest{}
	if err := json.NewDecoder(req.Body).Decode(r); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			jsonError(w, "upload request too large", http.StatusRequestEntityTooLarge)
			return
		}
		jsonError(w, fmt.Sprintf("could not decode json body: %s", err), http.StatusBadRequest)
		return
	}
	if len(r.Files) == 0 {
		jsonError(w, "no files provided", http.StatusBadRequest)
		return
	}
	if len(r.Files) > store.MaxFiles() {
		jsonError(w, fmt.Sprintf("too many files, limit is %d", store.MaxFiles()), http.StatusRequestEntityTooLarge)
		return
	}

	// Decode and validate everything before touching storage, so a malformed
	// request cannot leave a session half-populated.
	decoded := make([][]byte, len(r.Files))
	seen := make(map[string]struct{}, len(r.Files))
	for i, f := range r.Files {
		if !isSafeUploadName(f.Name) {
			jsonError(w, fmt.Sprintf("invalid file name %q", f.Name), http.StatusBadRequest)
			return
		}
		if _, dup := seen[f.Name]; dup {
			jsonError(w, fmt.Sprintf("duplicate file name %q", f.Name), http.StatusBadRequest)
			return
		}
		seen[f.Name] = struct{}{}

		data, err := base64.StdEncoding.DecodeString(f.Data)
		if err != nil {
			jsonError(w, fmt.Sprintf("could not decode data for %q: %s", f.Name, err), http.StatusBadRequest)
			return
		}
		if len(data) == 0 {
			jsonError(w, fmt.Sprintf("file %q is empty", f.Name), http.StatusBadRequest)
			return
		}
		if int64(len(data)) > store.MaxFileSize() {
			jsonError(w, fmt.Sprintf("file %q exceeds the %d byte limit", f.Name, store.MaxFileSize()), http.StatusRequestEntityTooLarge)
			return
		}
		decoded[i] = data
	}

	var (
		response  []UploadedFileResponse
		ftpPrefix = path.Join("/", uploadsDirName, r.CorrelationID)
	)

	// The disk writes happen inside UpdateUploads, i.e. under the correlation
	// ID's lock, so the per-session quota check and the commit are atomic with
	// respect to a concurrent upload for the same session.
	err := uploadStorage.UpdateUploads(r.CorrelationID, r.SecretKey, func(existing []storage.UploadedFile) ([]storage.UploadedFile, error) {
		updated := append([]storage.UploadedFile(nil), existing...)

		for i, f := range r.Files {
			var existingSize int64
			idx := -1
			for j, u := range updated {
				if u.Name == f.Name {
					existingSize, idx = u.Size, j
					break
				}
			}
			// Replacing a name reuses its slot rather than consuming a new one.
			if idx == -1 && len(updated) >= store.MaxFiles() {
				return nil, uploadErr(UploadErrTooManyFiles,
					"session already holds %d files, limit is %d", len(updated), store.MaxFiles())
			}

			size, sum, err := store.Save(r.CorrelationID, f.Name, decoded[i], existingSize)
			if err != nil {
				return nil, err
			}

			record := storage.UploadedFile{Name: f.Name, Size: size, SHA256: sum, Timestamp: time.Now()}
			if idx == -1 {
				updated = append(updated, record)
			} else {
				updated[idx] = record
			}
			response = append(response, UploadedFileResponse{
				Name:     f.Name,
				Size:     size,
				SHA256:   sum,
				HTTPPath: path.Join("/f", f.Name),
				FTPPath:  path.Join(ftpPrefix, f.Name),
			})
		}
		return updated, nil
	})

	if err != nil {
		h.writeUploadError(w, err)
		return
	}

	gologger.Debug().Msgf("Stored %d uploaded file(s) for %s\n", len(response), r.CorrelationID)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(&UploadResponse{Message: "upload successful", Files: response})
}

// serveUploadedFile serves a file hosted against the correlation id in the Host
// header, and records the fetch as an interaction.
//
// This runs on its own route, outside the logger middleware, and records the
// interaction itself. The logger buffers the whole response into a recorder and
// dumps the body into Interaction.RawResponse; for a hosted file that means
// every fetch retains a multiple of the file size in the session's interaction
// buffer, which has no cap in memory mode, and the retained copy is mangled by
// JSON escaping anyway. Recording explicitly keeps the evidence that the fetch
// happened -- which is the entire point for second-stage OOB verification --
// without the payload.
//
// Serving here rather than from defaultHandler also avoids being shadowed by
// -dhr, by the .json/.xml suffix branches, and by -dr header injection.
func (h *HTTPServer) serveUploadedFile(w http.ResponseWriter, req *http.Request) {
	// Every exit below is recorded, by one deferred call rather than a call per
	// return: a miss is the operator's evidence that the target fetched *some*
	// path -- the wrong name, or a file that has since expired -- and adding an
	// early return here must not be able to silently drop that again.
	rec := &hostedFetchRecorder{ResponseWriter: w}
	uniqueID, fullID := h.options.extractCorrelationID(req.Host)
	var meta *storage.UploadedFile
	defer func() { h.recordHostedFetch(req, uniqueID, fullID, meta, rec) }()

	store := h.options.UploadStore
	uploadStorage := h.options.UploadStorage()
	if store == nil || uploadStorage == nil {
		http.NotFound(rec, req)
		return
	}
	if uniqueID == "" {
		http.NotFound(rec, req)
		return
	}
	correlationID := uniqueID[:h.options.CorrelationIdLength]

	// Only the /f/ subtree is ours. CutPrefix rather than TrimPrefix so that a
	// path which does not carry the prefix is rejected instead of being read as
	// a file name; ServeMux redirects a bare /f to /f/ before we are reached.
	name, ok := strings.CutPrefix(req.URL.Path, "/f/")
	if !ok || !isSafeUploadName(name) {
		http.NotFound(rec, req)
		return
	}

	// Consult the metadata first: it makes a miss cheap, and means a file can
	// only be served to the session that actually owns it.
	files, ok := uploadStorage.ListUploads(correlationID)
	if !ok {
		http.NotFound(rec, req)
		return
	}
	for i := range files {
		if files[i].Name == name {
			meta = &files[i]
			break
		}
	}
	if meta == nil {
		http.NotFound(rec, req)
		return
	}

	f, fi, err := store.Open(correlationID, name)
	if err != nil {
		gologger.Debug().Msgf("Could not open uploaded file %s/%s: %s\n", correlationID, name, err)
		meta = nil // served nothing, so the record must not claim a hit
		http.NotFound(rec, req)
		return
	}
	defer f.Close()

	// Always octet-stream with an attachment disposition: DTD, XSLT and JNDI
	// consumers ignore content type entirely, so nothing is lost for the
	// intended use, while the server never renders client-supplied HTML or SVG
	// on its own domain.
	rec.Header().Set("Content-Type", "application/octet-stream")
	rec.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	rec.Header().Set("X-Content-Type-Options", "nosniff")
	if !h.options.NoVersionHeader {
		rec.Header().Set("X-Interactsh-Version", h.options.Version)
	}

	// ServeContent handles Range and conditional requests. The empty name
	// argument keeps it from re-deriving a content type from the extension.
	http.ServeContent(rec, req, "", fi.ModTime(), f)
}

// hostedFetchRecorder passes writes straight through to the real
// ResponseWriter while noting what the response actually was, so the stored
// interaction can state it rather than assume it. ServeContent answers a
// conditional request with 304 and a ranged one with 206, and a record that
// claimed 200 with the full length would be evidence of a delivery that never
// happened.
type hostedFetchRecorder struct {
	http.ResponseWriter
	status  int
	written int64
}

func (r *hostedFetchRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *hostedFetchRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.written += int64(n)
	return n, err
}

// statusCode reports the status sent, defaulting to 200 for a handler that
// wrote neither a header nor a body.
func (r *hostedFetchRecorder) statusCode() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

// recordHostedFetch stores an interaction for any request to the /f/ subtree,
// hit or miss, with the response body replaced by a summary.
//
// A miss matters as much as a hit: it is how the operator tells "the target
// never fetched the payload" from "the target fetched a name I am not hosting",
// or from a fetch that arrived after the file had expired. meta is nil for
// every miss, which is what selects the summary.
func (h *HTTPServer) recordHostedFetch(req *http.Request, uniqueID, fullID string, meta *storage.UploadedFile, rec *hostedFetchRecorder) {
	if uniqueID == "" {
		// Nothing to attribute it to: interactions are indexed by correlation id,
		// and handleInteraction slices one out of uniqueID unconditionally.
		return
	}
	// Counted where it is recorded, so /metrics and the interaction stream
	// cannot disagree about what arrived.
	atomic.AddUint64(&h.options.Stats.Http, 1)

	var host string
	if originIP := req.Header.Get(h.options.OriginIPHeader); originIP != "" {
		host = originIP
	} else {
		host, _, _ = net.SplitHostPort(req.RemoteAddr)
	}

	// Request dumped without its body: a file fetch is a GET, and an attacker
	// controlling the body must not be able to inflate the stored record.
	reqDump, _ := httputil.DumpRequest(req, false)

	status := rec.statusCode()
	var resp strings.Builder
	fmt.Fprintf(&resp, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if meta == nil {
		fmt.Fprintf(&resp, "\r\n[no hosted file for %q on this session]\n", req.URL.Path)
		h.handleInteraction(req, uniqueID, fullID, string(reqDump), resp.String(), host)
		return
	}
	fmt.Fprintf(&resp, "Content-Type: application/octet-stream\r\n")
	fmt.Fprintf(&resp, "Content-Disposition: attachment; filename=%q\r\n", meta.Name)
	fmt.Fprintf(&resp, "Content-Length: %d\r\n\r\n", rec.written)
	// The byte count is what ServeContent actually wrote, so a 304 records as
	// zero bytes and a 206 as the size of the range.
	fmt.Fprintf(&resp, "[body elided: %d of %d bytes of uploaded file %q, sha256 %s]\n",
		rec.written, meta.Size, meta.Name, meta.SHA256)

	h.handleInteraction(req, uniqueID, fullID, string(reqDump), resp.String(), host)
}

// recordUploadProbe records an interaction for a request to /upload that no
// legitimate client could have sent, so that a target poking at the endpoint
// reaches the operator's stream instead of vanishing behind a 401 or a 501.
//
// The request body is summarised rather than stored. It is attacker-controlled
// and may be megabytes -- persisting it is precisely what keeping /upload off the
// logger middleware avoids -- but its size is evidence worth keeping.
//
// status and body describe the reply the caller is about to send, so the stored
// record cannot drift from what the target actually received.
func (h *HTTPServer) recordUploadProbe(req *http.Request, status int, body string) {
	uniqueID, fullID := h.options.extractCorrelationID(req.Host)
	if uniqueID == "" {
		// Nothing to attribute it to: interactions are indexed by correlation id,
		// and handleInteraction slices one out of uniqueID unconditionally.
		return
	}
	atomic.AddUint64(&h.options.Stats.Http, 1)

	var host string
	if originIP := req.Header.Get(h.options.OriginIPHeader); originIP != "" {
		host = originIP
	} else {
		host, _, _ = net.SplitHostPort(req.RemoteAddr)
	}

	reqDump, _ := httputil.DumpRequest(req, false)
	reqString := string(reqDump)
	if req.ContentLength > 0 {
		reqString += fmt.Sprintf("[request body elided: %d bytes]\n", req.ContentLength)
	}

	var resp strings.Builder
	fmt.Fprintf(&resp, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if body != "" {
		// Mirrors jsonBody, which is what the caller writes.
		encoded, err := json.Marshal(map[string]interface{}{"error": body})
		if err != nil {
			return
		}
		fmt.Fprintf(&resp, "Content-Type: application/json; charset=utf-8\r\n")
		fmt.Fprintf(&resp, "X-Content-Type-Options: nosniff\r\n")
		fmt.Fprintf(&resp, "Content-Length: %d\r\n\r\n%s\n", len(encoded)+1, encoded)
	} else {
		resp.WriteString("\r\n")
	}

	h.handleInteraction(req, uniqueID, fullID, reqString, resp.String(), host)
}

// writeUploadError maps a failure to a status code the client can act on.
func (h *HTTPServer) writeUploadError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrCorrelationIdNotFound):
		jsonError(w, "unknown correlation-id", http.StatusNotFound)
		return
	case errors.Is(err, storage.ErrInvalidSecretKey):
		// Distinct from 400 so the client can tell "wrong session" apart from
		// "malformed request".
		jsonError(w, "invalid secret key for correlation-id", http.StatusForbidden)
		return
	}

	var ue *UploadError
	if errors.As(err, &ue) {
		switch ue.Kind {
		case UploadErrBadName:
			jsonError(w, ue.Error(), http.StatusBadRequest)
		case UploadErrTooLarge, UploadErrTooManyFiles:
			jsonError(w, ue.Error(), http.StatusRequestEntityTooLarge)
		case UploadErrOutOfSpace:
			jsonError(w, ue.Error(), http.StatusInsufficientStorage)
		default:
			jsonError(w, ue.Error(), http.StatusBadRequest)
		}
		return
	}

	gologger.Warning().Msgf("Could not store uploaded files: %s\n", err)
	jsonError(w, "could not store uploaded files", http.StatusInternalServerError)
}
