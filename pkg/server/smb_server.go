package server

import (
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/interactsh/pkg/filewatcher"
	"github.com/projectdiscovery/stringsutil"
)

var smbMonitorList map[string]string = map[string]string{
	// search term : extract after
	"INFO: ": "INFO: ",
}

// SMBServer is a smb wrapper server instance
type SMBServer struct {
	options   *Options
	LogFile   string
	ipAddress net.IP
	cmd       *exec.Cmd
	tmpFile   string
}

// NewSMBServer returns a new SMB server.
func NewSMBServer(options *Options) (*SMBServer, error) {
	server := &SMBServer{
		options:   options,
		ipAddress: net.ParseIP(options.IPAddress),
	}
	return server, nil
}

// ListenAndServe listens on smb port
func (h *SMBServer) ListenAndServe() error {
	tmpFile, err := os.CreateTemp("", "")
	if err != nil {
		return err
	}
	h.tmpFile = tmpFile.Name()
	tmpFile.Close()
	// execute smb_server.py - only works with ./interactsh-server
	cmdLine := "python3 smb_server.py " + h.tmpFile
	args := strings.Fields(cmdLine)
	h.cmd = exec.Command(args[0], args[1:]...)
	err = h.cmd.Start()
	if err != nil {
		return err
	}

	// watch output file
	outputFile := h.tmpFile
	// wait until the file is created
	for !fileutil.FileExists(outputFile) {
		time.Sleep(1 * time.Second)
	}
	fw, err := filewatcher.New(filewatcher.Options{
		Interval: time.Duration(5 * time.Second),
		File:     outputFile,
	})
	if err != nil {
		return err
	}

	ch, err := fw.Watch()
	if err != nil {
		return err
	}

	// This fetches the content at each change.
	go func() {
		for data := range ch {
			for searchTerm, extractAfter := range smbMonitorList {
				if strings.Contains(data, searchTerm) {
					haystack := stringsutil.After(data, extractAfter)
					log.Println(haystack)
				}
			}
		}
	}()

	return h.cmd.Wait()
}

func (h *SMBServer) Close() {
	h.cmd.Process.Kill()
	if fileutil.FileExists(h.tmpFile) {
		os.RemoveAll(h.tmpFile)
	}
}
