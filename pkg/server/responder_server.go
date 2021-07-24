package server

import (
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/interactsh/pkg/filewatcher"
	"github.com/projectdiscovery/stringsutil"
)

var responderMonitorList map[string]string = map[string]string{
	// search term : extract after
	"NTLMv2-SSP Hash": "NTLMv2-SSP Hash     : ",
}

// ResponderServer is a Responder wrapper server instance
type ResponderServer struct {
	options   *Options
	LogFile   string
	ipAddress net.IP
	cmd       *exec.Cmd
	tmpFolder string
}

// NewResponderServer returns a new SMB server.
func NewResponderServer(options *Options) (*ResponderServer, error) {
	server := &ResponderServer{
		options:   options,
		ipAddress: net.ParseIP(options.IPAddress),
	}
	return server, nil
}

// ListenAndServe listens on various responder ports
func (h *ResponderServer) ListenAndServe() error {
	tmpFolder, err := os.MkdirTemp("", "")
	if err != nil {
		return err
	}
	h.tmpFolder = tmpFolder
	// execute dockerized responder
	cmdLine := "docker run -p 137:137/udp -p  138:138/udp -p 389:389 -p 1433:1433 -p 1434:1434/udp -p 135:135 -p 139:139 -p 445:445 -p 21:21 -p 3141:3141 -p 110:110 -p 3128:3128 -p 5355:5355/udp -v " + h.tmpFolder + ":/opt/Responder/logs --rm interactsh:latest"
	args := strings.Fields(cmdLine)
	h.cmd = exec.Command(args[0], args[1:]...)
	err = h.cmd.Start()
	if err != nil {
		return err
	}

	// watch output file
	outputFile := filepath.Join(h.tmpFolder, "Responder-Session.log")
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
			for searchTerm, extractAfter := range responderMonitorList {
				if strings.Contains(data, searchTerm) {
					haystack := stringsutil.After(data, extractAfter)
					log.Println(haystack)
				}
			}
		}
	}()

	return h.cmd.Wait()
}

func (h *ResponderServer) Close() {
	h.cmd.Process.Kill()
	if fileutil.FolderExists(h.tmpFolder) {
		os.RemoveAll(h.tmpFolder)
	}
}
