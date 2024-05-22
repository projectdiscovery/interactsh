package server

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/filewatcher"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
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
func (h *SMBServer) ListenAndServe(smbAlive chan bool) error {
	smbAlive <- true
	defer func() {
		smbAlive <- false
	}()

	var err error
	h.tmpFile, err = fileutil.GetTempFileName()
	if err != nil {
		return err
	}

	pyFileName, err := fileutil.GetTempFileName()
	if err != nil {
		return err
	}
	pyFileName += ".py"

	if err := os.WriteFile(pyFileName, []byte(pySmbServer), os.ModePerm); err != nil {
		return err
	}

	smbPort := fmt.Sprint(h.options.SmbPort)
	h.cmd = exec.Command("python3", pyFileName, h.tmpFile, smbPort)
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
			atomic.AddUint64(&h.options.Stats.Smb, 1)
			for searchTerm, extractAfter := range smbMonitorList {
				if strings.Contains(data, searchTerm) {
					smbData, err := stringsutil.After(data, extractAfter)
					if err != nil {
						gologger.Warning().Msgf("Could not get smb interaction: %s\n", err)
						continue
					}

					// Correlation id doesn't apply here, we skip encryption
					interaction := &Interaction{
						Protocol:   "smb",
						RawRequest: smbData,
						Timestamp:  time.Now(),
					}
					buffer := &bytes.Buffer{}
					if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
						gologger.Warning().Msgf("Could not encode smb interaction: %s\n", err)
					} else {
						gologger.Debug().Msgf("SMB Interaction: \n%s\n", buffer.String())
						if err := h.options.Storage.AddInteractionWithId(h.options.Token, buffer.Bytes()); err != nil {
							gologger.Warning().Msgf("Could not store dns interaction: %s\n", err)
						}
					}
				}
			}
		}
	}()

	return h.cmd.Wait()
}

func (h *SMBServer) Close() {
	_ = h.cmd.Process.Kill()
	if fileutil.FileExists(h.tmpFile) {
		os.RemoveAll(h.tmpFile)
	}
}

var pySmbServer = `
import sys
from impacket import smbserver

def configure_shares(server):
    shares = ["IPC$", "ADMIN$", "C$", "PRINT$", "FAX$", "NETLOGON", "SYSVOL"]
    for share in shares:
        server.removeShare(share)

log_filename = "log.txt"
if len(sys.argv) >= 2:
    log_filename = sys.argv[1]
port = 445
if len(sys.argv) >= 3:
    port = int(sys.argv[2])

server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=port)
server.setSMB2Support(True)
configure_shares(server)
server.setSMBChallenge('')
server.setLogFile(log_filename)
server.start()
`
