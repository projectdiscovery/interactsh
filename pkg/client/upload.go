package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/errkit"
)

// ErrUploadUnsupported is returned when the interactsh server does not offer
// file hosting, either because it was started without -upload or because it
// predates the feature.
//
// Declared with errors.New rather than errkit.New so that errors.Is stays exact:
// errkit compares errors by message, which makes a sentinel and anything whose
// message contains it match in both directions.
var ErrUploadUnsupported = errors.New("interactsh server does not support file upload")

// defaultMaxUploadFileSize bounds a local file when the server has not told us
// its limit, so a mistyped -file cannot try to push a huge file over the wire.
const defaultMaxUploadFileSize = 1 << 20

// uploadNameRe mirrors the server's allowlist, so an unusable name is rejected
// locally with a clear message instead of as a 400 from the server.
var uploadNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// UploadedFile describes a file hosted by the interactsh server.
type UploadedFile struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	HTTPPath string `json:"http-path"`
	FTPPath  string `json:"ftp-path"`
}

// UploadFiles uploads local files to the interactsh server this client
// registered with, to be hosted against its correlation ID.
//
// Only the registered server is targeted. A Client holds a single correlation
// ID, registered with whichever server answered first, so the other servers in
// -s have never seen it and would reject the upload. Posting blindly to them
// would also be actively harmful: a server without -upload has no route for the
// request, so it falls through to the catch-all handler that records whole
// requests as interactions, and the file would be stored there anyway.
func (c *Client) UploadFiles(paths []string) ([]UploadedFile, error) {
	c.busy.RLock()
	defer c.busy.RUnlock()

	if c.State.Load() == Closed {
		return nil, errkit.New("client is closed")
	}
	if c.serverURL == nil {
		return nil, errkit.New("client is not registered with any server")
	}

	// Fail closed when the server has told us it cannot host files.
	if caps := c.Capabilities(); caps != nil && !caps.Upload {
		return nil, ErrUploadUnsupported
	}

	// Uploads carry the file and the secret key, so they must never traverse
	// the plaintext fallback that registration is permitted to use.
	if c.serverURL.Scheme != "https" && !isLoopbackURL(c.serverURL.Host) {
		return nil, errkit.New("refusing to upload over plaintext http to " + c.serverURL.Host +
			"; use an https server url")
	}

	request, err := c.buildUploadRequest(paths)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, errkit.Wrap(err, "could not encode upload request")
	}

	ctx := context.WithValue(context.Background(), retryablehttp.RETRY_MAX, 0)
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, c.serverURL.String()+"/upload", bytes.NewReader(payload))
	if err != nil {
		return nil, errkit.Wrap(err, "could not create upload request")
	}
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Add("Authorization", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errkit.Wrap(err, "could not make upload request")
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotImplemented, http.StatusNotFound, http.StatusMethodNotAllowed:
		return nil, ErrUploadUnsupported
	case http.StatusUnauthorized:
		return nil, errkit.New("invalid token provided for interactsh server")
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("could not upload files (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}

	response := &server.UploadResponse{}
	if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
		return nil, errkit.Wrap(err, "could not decode upload response")
	}

	files := make([]UploadedFile, 0, len(response.Files))
	for _, f := range response.Files {
		files = append(files, UploadedFile{
			Name:     f.Name,
			Size:     f.Size,
			SHA256:   f.SHA256,
			HTTPPath: f.HTTPPath,
			FTPPath:  f.FTPPath,
		})
	}
	return files, nil
}

// buildUploadRequest reads and validates the local files before anything is
// sent, so a bad path or an oversize file fails immediately and clearly.
func (c *Client) buildUploadRequest(paths []string) (*server.UploadRequest, error) {
	maxFileSize, maxFiles := int64(defaultMaxUploadFileSize), 0
	if caps := c.Capabilities(); caps != nil {
		if caps.UploadMaxFileSize > 0 {
			maxFileSize = caps.UploadMaxFileSize
		}
		maxFiles = caps.UploadMaxFiles
	}
	if maxFiles > 0 && len(paths) > maxFiles {
		return nil, fmt.Errorf("%d files requested but the server accepts at most %d", len(paths), maxFiles)
	}

	request := &server.UploadRequest{CorrelationID: c.correlationID, SecretKey: c.secretKey}
	seen := make(map[string]string, len(paths))

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, errkit.Wrap(err, "could not read file "+p)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", p)
		}
		if info.Size() == 0 {
			return nil, fmt.Errorf("%s is empty", p)
		}
		if info.Size() > maxFileSize {
			return nil, fmt.Errorf("%s is %d bytes, the server accepts at most %d", p, info.Size(), maxFileSize)
		}

		name := filepath.Base(p)
		if !uploadNameRe.MatchString(name) || name == "." || name == ".." {
			return nil, fmt.Errorf("%s has a name the server will not accept; "+
				"use only letters, digits, dot, dash and underscore", p)
		}
		if previous, dup := seen[name]; dup {
			return nil, fmt.Errorf("%s and %s would both be hosted as %q", previous, p, name)
		}
		seen[name] = p

		data, err := os.ReadFile(p)
		if err != nil {
			return nil, errkit.Wrap(err, "could not read file "+p)
		}
		request.Files = append(request.Files, server.UploadFileRequest{
			Name: name,
			Data: base64.StdEncoding.EncodeToString(data),
		})
	}

	if len(request.Files) == 0 {
		return nil, errkit.New("no files to upload")
	}
	return request, nil
}

// FileURL returns the URL a target should fetch to retrieve a hosted file.
// payloadHost is any host produced by URL(); only its correlation ID prefix is
// significant to the server, so a single call to URL() serves every file.
func (c *Client) FileURL(payloadHost string, file UploadedFile) string {
	scheme := "https"
	if c.serverURL != nil && c.serverURL.Scheme != "" {
		scheme = c.serverURL.Scheme
	}
	return scheme + "://" + payloadHost + file.HTTPPath
}

// FTPFileURL returns the ftp:// URL for a hosted file. FTP has no host-based
// routing, so the correlation ID travels in the path instead.
//
// Any port on payloadHost is dropped: it belongs to the server's HTTP listener,
// which says nothing about where the FTP listener is bound, so carrying it over
// would produce a URL that cannot connect.
func (c *Client) FTPFileURL(payloadHost string, file UploadedFile) string {
	host := payloadHost
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return "ftp://" + host + file.FTPPath
}

// isLoopbackURL reports whether a host refers to the local machine, where a
// plaintext upload is not exposed to the network.
func isLoopbackURL(host string) bool {
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	switch strings.ToLower(name) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}
