package server

import (
	"crypto/tls"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"encoding/json"

	"github.com/asaskevich/govalidator"
	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/afero"
)

// FTPServer is a ftp server instance
type FTPServer struct {
	options    *Options
	ftpServer  *ftpserver.FtpServer
	ftpsServer *ftpserver.FtpServer
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

	// BasePathFs confines paths with a string-prefix check, which a relative
	// root breaks: under ".", "/index.html" becomes "index.html" and fails
	// the check.
	root, err := filepath.Abs(ftpFolder)
	if err != nil {
		return nil, err
	}
	// The read-only layer refuses every write that ftpSession does not
	// already turn into a no-op.
	fs := afero.NewReadOnlyFs(afero.NewBasePathFs(afero.NewOsFs(), root))

	server.ftpServer = ftpserver.NewFtpServer(&ftpDriver{server: server, fs: fs, port: options.FtpPort})

	if options.CertificatePath != "" && options.PrivateKeyPath != "" || len(options.CertFiles) > 0 {
		// attempt to retrieve certificates for the first domain automatically
		certFile, keyFile := options.CertificatePath, options.PrivateKeyPath
		if len(options.CertFiles) > 0 {
			certFile, keyFile = options.CertFiles[0].CertPath, options.CertFiles[0].PrivKeyPath
		}
		server.ftpsServer = ftpserver.NewFtpServer(&ftpDriver{
			server: server,
			fs:     fs,
			port:   options.FtpsPort,
			// Loaded when FTPS starts listening, so that a bad key pair stops
			// FTPS alone, and loaded once, because every FEAT asks for it.
			tlsConfig: sync.OnceValues(func() (*tls.Config, error) {
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					return nil, err
				}
				return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"ftp"}}, nil
			}),
		})
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
	_ = h.ftpServer.Stop()
	if h.ftpsServer != nil {
		_ = h.ftpsServer.Stop()
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

// ftpDriver serves one FTP port. Any login succeeds: recording it is the point.
type ftpDriver struct {
	server *FTPServer
	fs     afero.Fs
	port   int
	// tlsConfig is set on the implicit-TLS port and nil on plain FTP.
	tlsConfig func() (*tls.Config, error)
}

// ftpserverlib finds these extensions by type assertion and silently does
// without any that is missing. Without ReadDir, it would list the uploads
// directory.
var (
	_ ftpserver.MainDriverExtensionUserVerifier   = (*ftpDriver)(nil)
	_ ftpserver.ClientDriverExtensionFileList     = (*ftpSession)(nil)
	_ ftpserver.ClientDriverExtentionFileTransfer = (*ftpSession)(nil)
	_ ftpserver.ClientDriverExtensionRemoveDir    = (*ftpSession)(nil)
)

var errFTPNoTLS = errors.New("TLS is not enabled on this port")

func (d *ftpDriver) GetSettings() (*ftpserver.Settings, error) {
	settings := &ftpserver.Settings{
		ListenAddr: formatAddress("", d.port),
		// Dialing active-mode data connections from port 20 needs a privilege
		// the server may not have.
		ActiveTransferPortNon20: true,
		// Hosted payloads must arrive byte for byte, whatever TYPE the client
		// asked for.
		DisableASCIIConversion: true,
		// Seconds a data connection may take to arrive: the 60 that clients
		// of interactsh have always had, rather than the default 30.
		ConnectionTimeout: 60,
	}
	if d.tlsConfig != nil {
		settings.TLSRequired = ftpserver.ImplicitEncryption
	}
	return settings, nil
}

func (d *ftpDriver) GetTLSConfig() (*tls.Config, error) {
	if d.tlsConfig == nil {
		return nil, errFTPNoTLS
	}
	return d.tlsConfig()
}

func (d *ftpDriver) ClientConnected(ftpserver.ClientContext) (string, error) {
	return "Welcome to the Go FTP Server", nil
}

func (d *ftpDriver) ClientDisconnected(ftpserver.ClientContext) {}

// PreAuthUser records the USER command.
func (d *ftpDriver) PreAuthUser(cc ftpserver.ClientContext, user string) error {
	d.server.recordInteraction(cc.RemoteAddr().String(), "USER "+user+"\n"+user+" logging in")
	return nil
}

func (d *ftpDriver) AuthUser(cc ftpserver.ClientContext, user, pass string) (ftpserver.ClientDriver, error) {
	d.server.recordInteraction(cc.RemoteAddr().String(), "PASS "+pass+"\nuser "+user+" logged in with password "+pass)
	return &ftpSession{Fs: d.fs, server: d.server, cc: cc}, nil
}

// ftpSession is the file system a logged-in client sees: the FTP root,
// read-only. MKD, RMD, DELE, RNTO, STOR and APPE report success without
// changing anything, so that the client carries on and its next commands are
// recorded too; every other write is refused.
type ftpSession struct {
	afero.Fs
	server *FTPServer
	cc     ftpserver.ClientContext
}

// record stores an interaction as "<command> <name>\n<event>". dstPath, set
// only for downloads, attributes it to the session owning that hosted file.
func (s *ftpSession) record(command, name, event, dstPath string) {
	data := command + " " + name + "\n" + event
	s.server.recordInteractionForPath(s.cc.RemoteAddr().String(), data, dstPath)
}

// Open and Stat are the only ways this driver reads the root, so they are
// where client paths are cleaned (see ftpCleanPath) and where their errors
// lose the on-disk path (see withClientPath). ReadDir and downloadFile do
// the same for errors from the files Open returns. The embedded OpenFile
// would read too, but ftpserverlib calls it only for drivers without
// GetHandle.
func (s *ftpSession) Open(name string) (afero.File, error) {
	f, err := s.Fs.Open(ftpCleanPath(name))
	return f, withClientPath(err, name)
}

// withClientPath puts the client's path in place of the on-disk one in a file
// system error. ftpserverlib quotes the error in its reply, and the on-disk
// path would tell any anonymous client where the FTP root is on the server.
func withClientPath(err error, name string) error {
	if pathErr, ok := errors.AsType[*os.PathError](err); ok {
		return &os.PathError{Op: pathErr.Op, Path: name, Err: pathErr.Err}
	}
	return err
}

// Stat also records CWD and CDUP, which ftpserverlib carries out as a Stat of
// the target with no driver call of their own. ftpserverlib waits for any
// transfer to finish before it runs either, so a Stat made while one of them
// is the last command is that command's.
//
// XCWD and CDUP are recorded as the CWD they stand for, CDUP as "CWD ..",
// which is how interactsh has always stored them.
func (s *ftpSession) Stat(name string) (os.FileInfo, error) {
	info, err := s.Fs.Stat(ftpCleanPath(name))
	if err != nil {
		return nil, withClientPath(err, name)
	}
	if info.IsDir() {
		event := "changing directory from " + s.cc.Path() + " to " + name
		switch s.cc.GetLastCommand() {
		case "CWD", "XCWD":
			s.record("CWD", name, event, "")
		case "CDUP":
			s.record("CWD", "..", event, "")
		}
	}
	return info, nil
}

// ReadDir hides interactsh's own upload storage, and nothing else.
//
// AuthUser accepts any credentials, so an anonymous client must not be able to
// read off every correlation id that currently has uploaded files and then walk
// into each one. Two rules close that off: the uploads directory never lists its
// own contents, and it is filtered out of the root listing so that it cannot be
// discovered in the first place. A client that already knows its own correlation
// id can still list and RETR inside it.
//
// Only those two rules, deliberately: the root itself lists normally, because
// -ftp-dir is documented as serving the operator's own directory and a blanket
// refusal there would silently break that.
func (s *ftpSession) ReadDir(name string) ([]os.FileInfo, error) {
	if isUploadsDir(name) {
		return nil, nil
	}
	entries, err := afero.ReadDir(s, name)
	if err != nil || !isFTPRoot(name) {
		return entries, withClientPath(err, name)
	}
	return slices.DeleteFunc(entries, func(info os.FileInfo) bool {
		return info.Name() == uploadsDirName
	}), nil
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
// path decision in this file goes through it, and so does every read of the
// root, so "/a/../b", "//b" and "/./b" can never be treated differently from
// "/b". On Windows "\" is a separator as well, but ftpserverlib cleans paths on
// "/" alone, so without this conversion "/x/..\.interactsh-user-uploads" would
// slip past isUploadsDir, and "/..\ftp2" would pass BasePathFs's prefix check
// for a root of "C:\ftp".
func ftpCleanPath(p string) string {
	return path.Clean("/" + strings.TrimPrefix(filepath.ToSlash(p), "/"))
}

func (s *ftpSession) RemoveDir(name string) error {
	s.record(s.cc.GetLastCommand(), name, "deleting directory "+name, "")
	return nil
}

func (s *ftpSession) Remove(name string) error {
	s.record(s.cc.GetLastCommand(), name, "deleting "+name, "")
	return nil
}

func (s *ftpSession) Rename(string, string) error {
	return nil
}

// Mkdir records MKD. XMKD, the only other command that calls it, is recorded
// as MKD too, which is how interactsh has always stored it.
func (s *ftpSession) Mkdir(name string, _ os.FileMode) error {
	s.record("MKD", name, "creating directory "+name, "")
	return nil
}

// GetHandle records RETR, STOR and APPE. Uploads are read and thrown away.
// The command is named from flags rather than GetLastCommand: a transfer runs
// on its own goroutine, and the client may have sent another command by then.
func (s *ftpSession) GetHandle(name string, flags int, _ int64) (ftpserver.FileTransfer, error) {
	if flags&os.O_WRONLY == 0 {
		s.record("RETR", name, "downloading file "+name, name)
		return s.openDownload(name)
	}
	command := "STOR"
	if flags&os.O_APPEND != 0 {
		command = "APPE"
	}
	s.record(command, name, "uploading "+name, "")
	return discardFile{}, nil
}

// openDownload opens a file for RETR. It refuses a directory itself, so that
// hiding the uploads directory never depends on the OS refusing to read one:
// where reading is allowed, its raw entries would list correlation ids.
func (s *ftpSession) openDownload(name string) (ftpserver.FileTransfer, error) {
	f, err := s.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && info.IsDir() {
		err = &os.PathError{Op: "open", Path: name, Err: syscall.EISDIR}
	}
	if err != nil {
		_ = f.Close()
		return nil, withClientPath(err, name)
	}
	return downloadFile{File: f, name: name}, nil
}

// downloadFile is a file being sent for RETR. Its Seek and Read errors give
// the client's path, as Open's do, because ftpserverlib quotes them in its
// replies. Seek, for one, fails after a negative REST.
type downloadFile struct {
	afero.File
	name string
}

func (f downloadFile) Seek(offset int64, whence int) (int64, error) {
	n, err := f.File.Seek(offset, whence)
	return n, withClientPath(err, f.name)
}

func (f downloadFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	return n, withClientPath(err, f.name)
}

// discardFile is where uploads go: it accepts whatever is sent and keeps none.
type discardFile struct{}

func (discardFile) Read([]byte) (int, error)                { return 0, io.EOF }
func (discardFile) Write(p []byte) (int, error)             { return len(p), nil }
func (discardFile) Seek(offset int64, _ int) (int64, error) { return offset, nil }
func (discardFile) Close() error                            { return nil }
