package server

import (
	"bytes"
	"fmt"
	"os"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	ftpserver "goftp.io/server/v2"
	"goftp.io/server/v2/driver/file"
)

// FTPServer is a ftp server instance
type FTPServer struct {
	options   *Options
	ftpServer *ftpserver.Server
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

	opt := &ftpserver.Options{
		Name:   "interactsh-ftp",
		Driver: driver,
		Port:   21,
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

	return server, nil
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *FTPServer) ListenAndServe(autoTLS *acme.AutoTLS) error {
	return h.ftpServer.ListenAndServe()
}

func (h *FTPServer) Close() {
	_ = h.ftpServer.Shutdown()
}

func (h *FTPServer) recordInteraction(remoteAddress, data string) {
	if data == "" {
		return
	}
	interaction := &Interaction{
		RemoteAddress: remoteAddress,
		Protocol:      "ftp",
		RawRequest:    data,
		Timestamp:     time.Now(),
	}
	buffer := &bytes.Buffer{}
	if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
		gologger.Warning().Msgf("Could not encode ftp interaction: %s\n", err)
	} else {
		gologger.Debug().Msgf("FTP Interaction: \n%s\n", buffer.String())
		if err := h.options.Storage.AddInteractionWithId(h.options.Token, buffer.Bytes()); err != nil {
			gologger.Warning().Msgf("Could not store ftp interaction: %s\n", err)
		}
	}
}

func (h *FTPServer) Print(sessionID string, message interface{}) {
	h.recordInteraction("", fmt.Sprintf("%s: %s", sessionID, message))
}
func (h *FTPServer) Printf(sessionID string, format string, v ...interface{}) {
	h.Print(sessionID, fmt.Sprintf(format, v...))
}
func (h *FTPServer) PrintCommand(sessionID string, command string, params string) {
	h.Print(sessionID, fmt.Sprintf("%s %s", command, params))
}
func (h *FTPServer) PrintResponse(sessionID string, code int, message string) {
	h.Print(sessionID, fmt.Sprintf("%d %s", code, message))
}

func (h *FTPServer) BeforeLoginUser(ctx *ftpserver.Context, userName string) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) BeforePutFile(ctx *ftpserver.Context, dstPath string) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) BeforeDeleteFile(ctx *ftpserver.Context, dstPath string) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) BeforeChangeCurDir(ctx *ftpserver.Context, oldCurDir, newCurDir string) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) BeforeCreateDir(ctx *ftpserver.Context, dstPath string) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) BeforeDeleteDir(ctx *ftpserver.Context, dstPath string) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) BeforeDownloadFile(ctx *ftpserver.Context, dstPath string) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) AfterUserLogin(ctx *ftpserver.Context, userName, password string, passMatched bool, err error) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) AfterFilePut(ctx *ftpserver.Context, dstPath string, size int64, err error) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) AfterFileDeleted(ctx *ftpserver.Context, dstPath string, err error) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) AfterFileDownloaded(ctx *ftpserver.Context, dstPath string, size int64, err error) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) AfterCurDirChanged(ctx *ftpserver.Context, oldCurDir, newCurDir string, err error) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) AfterDirCreated(ctx *ftpserver.Context, dstPath string, err error) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}
func (h *FTPServer) AfterDirDeleted(ctx *ftpserver.Context, dstPath string, err error) {
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), ctx.Cmd+ctx.Param)
}

type NopAuth struct{}

func (a *NopAuth) CheckPasswd(ctx *ftpserver.Context, name, pass string) (bool, error) {
	return true, nil
}
