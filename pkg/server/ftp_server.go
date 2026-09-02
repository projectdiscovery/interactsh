package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"encoding/json"

	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/gologger"
	ftpserver "goftp.io/server/v2"
	"goftp.io/server/v2/driver/file"
)

// FTPServer is a ftp server instance
type FTPServer struct {
	options    *Options
	ftpServer  *ftpserver.Server
	ftpsServer *ftpserver.Server
}

// NewFTPServer returns a new TLS & Non-TLS FTP server.
func NewFTPServer(options *Options) (*FTPServer, error) {
	server := &FTPServer{options: options}

	ftpFolder := options.FTPDirectory
	if ftpFolder == "" {
		var err error
		ftpFolder, err = os.MkdirTemp("", "")
		if err != nil {
			return nil, err
		}
	}

	driver, err := file.NewDriver(ftpFolder)
	if err != nil {
		return nil, err
	}

	nopDriver := NewNopDriver(driver)

	opt := &ftpserver.Options{
		Name:   "interactsh-ftp",
		Driver: nopDriver,
		Port:   options.FtpPort,
		Perm:   ftpserver.NewSimplePerm("root", "root"),
		Logger: server,
		Auth:   &NopAuth{},
	}

	// start ftp server
	ftpServer, err := ftpserver.NewServer(opt)
	if err != nil {
		return nil, err
	}
	server.ftpServer = ftpServer
	ftpServer.RegisterNotifer(server)

	if options.CertificatePath != "" && options.PrivateKeyPath != "" || len(options.CertFiles) > 0 {
		// attempt to retrieve certificates for the first domain automatically
		optsTls := &ftpserver.Options{
			Name:   "interactsh-ftp",
			Driver: nopDriver,
			Port:   options.FtpsPort,
			Perm:   ftpserver.NewSimplePerm("root", "root"),
			Logger: server,
			Auth:   &NopAuth{},
		}
		optsTls.TLS = true
		optsTls.Port = options.FtpsPort
		if len(options.CertFiles) > 0 {
			optsTls.CertFile = options.CertFiles[0].CertPath
			optsTls.KeyFile = options.CertFiles[0].PrivKeyPath
		} else {
			optsTls.CertFile = options.CertificatePath
			optsTls.KeyFile = options.PrivateKeyPath
		}

		// start ftp server
		ftpsServer, err := ftpserver.NewServer(optsTls)
		if err != nil {
			return nil, err
		}
		server.ftpsServer = ftpsServer
		ftpsServer.RegisterNotifer(server)
	}

	return server, nil
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *FTPServer) ListenAndServe(tlsConfig *tls.Config, ftpAlive chan bool, ftpsAlive chan bool) {
	go func() {
		if tlsConfig == nil {
			return
		}
		ftpsAlive <- true
		if err := h.ftpsServer.ListenAndServe(); err != nil {
			gologger.Error().Msgf("Could not serve ftp on tls: %s\n", err)
			ftpsAlive <- false
		}
	}()

	ftpAlive <- true
	if err := h.ftpServer.ListenAndServe(); err != nil {
		gologger.Error().Msgf("Could not serve ftp on port 21: %s\n", err)
		ftpAlive <- false
	}
}

func (h *FTPServer) Close() {
	_ = h.ftpServer.Shutdown()
	if h.ftpsServer != nil {
		_ = h.ftpsServer.Shutdown()
	}
}

func (h *FTPServer) recordInteraction(remoteAddress, data string) {
	h.recordInteractionForPath(remoteAddress, data, "")
}

// recordInteractionForPath records an FTP interaction, attributing it to the
// session that owns dstPath when the path points into a hosted-files directory.
//
// Interactions that cannot be attributed go, as before, to the shared token
// bucket, which pollHandler fans out to every authenticated client. That is
// fine for connection noise, but a fetch of a specific session's hosted file
// belongs to that session: otherwise it is reported to everyone and attributed
// to no one.
func (h *FTPServer) recordInteractionForPath(remoteAddress, data, dstPath string) {
	atomic.AddUint64(&h.options.Stats.Ftp, 1)

	if data == "" {
		return
	}
	interaction := &Interaction{
		RemoteAddress: remoteAddress,
		Protocol:      "ftp",
		RawRequest:    data,
		Timestamp:     time.Now(),
	}

	correlationID := h.correlationIDFromPath(dstPath)
	if correlationID != "" {
		interaction.UniqueID = correlationID
		interaction.FullId = correlationID
	}

	dataBytes, err := json.Marshal(interaction)
	if err != nil {
		gologger.Warning().Msgf("Could not encode ftp interaction: %s\n", err)
		return
	}
	gologger.Debug().Msgf("FTP Interaction: \n%s\n", string(dataBytes))

	if correlationID != "" {
		if err := h.options.Storage.AddInteraction(correlationID, dataBytes); err != nil {
			gologger.Warning().Msgf("Could not store ftp interaction: %s\n", err)
		}
		return
	}
	if err := h.options.Storage.AddInteractionWithId(h.options.Token, dataBytes); err != nil {
		gologger.Warning().Msgf("Could not store ftp interaction: %s\n", err)
	}
}

// correlationIDFromPath returns the correlation id owning an FTP path, or "" if
// the path does not name a live session with hosted files.
func (h *FTPServer) correlationIDFromPath(dstPath string) string {
	uploadStorage := h.options.UploadStorage()
	if dstPath == "" || h.options.UploadStore == nil || uploadStorage == nil {
		return ""
	}
	// Hosted files live at /<uploadsDirName>/<correlationID>/<name>, so the
	// correlation id is the second segment. Cleaning first means a traversal can
	// only ever resolve to the session it actually points at.
	rest, ok := strings.CutPrefix(ftpCleanPath(dstPath), "/"+uploadsDirName+"/")
	if !ok {
		return ""
	}
	segment, _, _ := strings.Cut(rest, "/")
	segment = strings.ToLower(segment)
	if len(segment) != h.options.CorrelationIdLength || !govalidator.IsAlphanumeric(segment) {
		return ""
	}
	if _, ok := uploadStorage.ListUploads(segment); !ok {
		return ""
	}
	return segment
}

func (h *FTPServer) Print(sessionID string, message interface{})              {}
func (h *FTPServer) Printf(sessionID string, format string, v ...interface{}) {}
func (h *FTPServer) PrintCommand(sessionID string, command string, params string) {
	h.Print(sessionID, fmt.Sprintf("%s %s", command, params))
}
func (h *FTPServer) PrintResponse(sessionID string, code int, message string) {
	h.Print(sessionID, fmt.Sprintf("%d %s", code, message))
}

func (h *FTPServer) BeforeLoginUser(ctx *ftpserver.Context, userName string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString(userName + " logging in")
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforePutFile(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("uploading " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeDeleteFile(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("deleting " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeChangeCurDir(ctx *ftpserver.Context, oldCurDir, newCurDir string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("changing directory from " + oldCurDir + " to " + newCurDir)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeCreateDir(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("creating directory " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeDeleteDir(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("deleting directory " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeDownloadFile(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("downloading file " + dstPath)
	h.recordInteractionForPath(ctx.Sess.RemoteAddr().String(), b.String(), dstPath)
}
func (h *FTPServer) AfterUserLogin(ctx *ftpserver.Context, userName, password string, passMatched bool, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("user " + userName + " logged in with password " + password)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterFilePut(ctx *ftpserver.Context, dstPath string, size int64, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("uploaded " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterFileDeleted(ctx *ftpserver.Context, dstPath string, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("deleted " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterFileDownloaded(ctx *ftpserver.Context, dstPath string, size int64, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("downloaded file " + dstPath)
	h.recordInteractionForPath(ctx.Sess.RemoteAddr().String(), b.String(), dstPath)
}
func (h *FTPServer) AfterCurDirChanged(ctx *ftpserver.Context, oldCurDir, newCurDir string, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("changed directory from " + oldCurDir + " to " + newCurDir)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterDirCreated(ctx *ftpserver.Context, dstPath string, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("created directory " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterDirDeleted(ctx *ftpserver.Context, dstPath string, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("delete directory " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}

type NopAuth struct{}

func (a *NopAuth) CheckPasswd(ctx *ftpserver.Context, name, pass string) (bool, error) {
	return true, nil
}

type NopDriver struct {
	driver ftpserver.Driver
}

func NewNopDriver(driver ftpserver.Driver) *NopDriver {
	return &NopDriver{driver: driver}
}

func (n *NopDriver) Stat(c *ftpserver.Context, s string) (os.FileInfo, error) {
	return n.driver.Stat(c, s)
}

// ListDir hides interactsh's own upload storage, and nothing else.
//
// NopAuth accepts any credentials, so an anonymous client must not be able to
// read off every correlation id that currently has uploaded files and then walk
// into each one. Two rules close that off: the uploads directory never lists its
// own contents, and it is filtered out of the root listing so that it cannot be
// discovered in the first place. A client that already knows its own correlation
// id can still list and RETR inside it.
//
// Only those two rules, deliberately: the root itself lists normally, because
// -ftp-dir is documented as serving the operator's own directory and a blanket
// refusal there would silently break that.
func (n *NopDriver) ListDir(c *ftpserver.Context, s string, f func(os.FileInfo) error) error {
	if isUploadsDir(s) {
		return nil
	}
	if isFTPRoot(s) {
		return n.driver.ListDir(c, s, func(info os.FileInfo) error {
			if info.Name() == uploadsDirName {
				return nil
			}
			return f(info)
		})
	}
	return n.driver.ListDir(c, s, f)
}

// isUploadsDir reports whether an FTP path refers to the uploads directory
// itself, which sits directly under the root.
func isUploadsDir(p string) bool {
	return ftpCleanPath(p) == "/"+uploadsDirName
}

// isFTPRoot reports whether an FTP path refers to the server root.
func isFTPRoot(p string) bool {
	switch ftpCleanPath(p) {
	case "/", ".", "":
		return true
	}
	return false
}

// ftpCleanPath resolves an FTP path to an absolute, traversal-free form. Every
// path decision in this file goes through it, so "/a/../b", "//b" and "/./b" can
// never be treated differently from "/b".
func ftpCleanPath(p string) string {
	return path.Clean("/" + strings.TrimPrefix(p, "/"))
}

func (n *NopDriver) DeleteDir(c *ftpserver.Context, s string) error {
	return nil
}

func (n *NopDriver) DeleteFile(c *ftpserver.Context, s string) error {
	return nil
}

func (n *NopDriver) Rename(c *ftpserver.Context, s1 string, s2 string) error {
	return nil
}

func (n *NopDriver) MakeDir(c *ftpserver.Context, s string) error {
	return nil
}

func (n *NopDriver) GetFile(c *ftpserver.Context, s1 string, k int64) (int64, io.ReadCloser, error) {
	return n.driver.GetFile(c, s1, k)
}

func (n *NopDriver) PutFile(c *ftpserver.Context, s string, r io.Reader, k int64) (int64, error) {
	return k, nil
}
