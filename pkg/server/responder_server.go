package server

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/filewatcher"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var responderMonitorList map[string]string = map[string]string{
	// search term : extract after
	"NTLMv2-SSP Hash": "NTLMv2-SSP Hash     : ",
}

// ResponderServer is a Responder wrapper server instance
type ResponderServer struct {
	options   *Options
	LogFile   string
	cmd       *exec.Cmd
	tmpFolder string
}

// NewResponderServer returns a new SMB server.
func NewResponderServer(options *Options) (*ResponderServer, error) {
	return &ResponderServer{options: options}, nil
}

// ListenAndServe listens on various responder ports
func (h *ResponderServer) ListenAndServe(responderAlive chan bool) error {
	responderAlive <- true
	defer func() {
		responderAlive <- false
	}()
	tmpFolder, err := os.MkdirTemp("", "interactsh-responder-")
	if err != nil {
		return err
	}
	h.tmpFolder = tmpFolder

	// interactsh always binds LDAP on LdapPort (default 389). Only publish
	// container 389 when LDAP was moved off that port (e.g. -ldap-port 10389).
	ports := "-p 137:137/udp -p 138:138/udp -p 1433:1433 -p 1434:1434/udp -p 135:135 -p 139:139 -p 445:445 -p 21:21 -p 3141:3141 -p 110:110 -p 3128:3128 -p 5355:5355/udp"
	if h.options.LdapPort != 389 {
		ports = "-p 137:137/udp -p 138:138/udp -p 389:389 -p 1433:1433 -p 1434:1434/udp -p 135:135 -p 139:139 -p 445:445 -p 21:21 -p 3141:3141 -p 110:110 -p 3128:3128 -p 5355:5355/udp"
	}
	cmdLine := "docker run " + ports + " -v " + h.tmpFolder + ":/opt/Responder/logs --rm interactsh:latest"
	args := strings.Fields(cmdLine)
	h.cmd = exec.Command(args[0], args[1:]...) //nolint:gosec
	h.cmd.Stdout = os.Stdout
	h.cmd.Stderr = os.Stderr
	err = h.cmd.Start()
	if err != nil {
		gologger.Error().Msgf("Could not start responder docker container: %s\n", err)
		return err
	}
	gologger.Info().Msgf("Responder container started (pid %d), waiting for session log...\n", h.cmd.Process.Pid)

	done := make(chan error, 1)
	go func() {
		done <- h.cmd.Wait()
	}()

	// watch output file
	outputFile := filepath.Join(h.tmpFolder, "Responder-Session.log")
	for !fileutil.FileExists(outputFile) {
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("responder container exited before creating %s: %w", outputFile, err)
			}
			return fmt.Errorf("responder container exited before creating %s", outputFile)
		case <-time.After(1 * time.Second):
		}
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
					responderData, err := stringsutil.After(data, extractAfter)
					if err != nil {
						gologger.Warning().Msgf("Could not get responder interaction: %s\n", err)
						continue
					}

					// Correlation id doesn't apply here, we skip encryption
					interaction := &Interaction{
						Protocol:   "responder",
						RawRequest: responderData,
						Timestamp:  time.Now(),
					}
					data, err := jsoniter.Marshal(interaction)
					if err != nil {
						gologger.Warning().Msgf("Could not encode responder interaction: %s\n", err)
					} else {
						gologger.Debug().Msgf("Responder Interaction: \n%s\n", string(data))
						if err := h.options.Storage.AddInteractionWithId(h.options.Token, data); err != nil {
							gologger.Warning().Msgf("Could not store dns interaction: %s\n", err)
						}
					}
				}
			}
		}
	}()

	return <-done
}

func (h *ResponderServer) Close() {
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
	}
	if fileutil.FolderExists(h.tmpFolder) {
		_ = os.RemoveAll(h.tmpFolder)
	}
}
