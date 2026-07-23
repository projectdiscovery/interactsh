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

// Patterns taken from Responder SaveToDb() output:
//   [SMB] NTLMv2-SSP Hash     : user::domain:...
// Also accept shorter variants written to per-client dump files.
var responderMonitorList = map[string]string{
	"NTLMv2-SSP Hash": "NTLMv2-SSP Hash     : ",
	"NTLMv1-SSP Hash": "NTLMv1-SSP Hash     : ",
	"NTLMv2 Hash":     "NTLMv2 Hash     : ",
	"NTLMv1 Hash":     "NTLMv1 Hash     : ",
}

// ResponderServer is a Responder wrapper server instance
type ResponderServer struct {
	options   *Options
	LogFile   string
	cmd       *exec.Cmd
	tmpFolder string
}

// NewResponderServer returns a new Responder server.
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

	out := make(chan string, 64)
	go h.watchFile(outputFile, out)
	// Responder always writes fullhash lines to per-client files under logs/,
	// even when SessionLog formatting changes.
	go h.watchHashDumpFiles(out)

	go func() {
		for data := range out {
			h.handleResponderLogLine(data)
		}
	}()

	return <-done
}

func (h *ResponderServer) watchFile(path string, out chan<- string) {
	fw, err := filewatcher.New(filewatcher.Options{
		Interval: 2 * time.Second,
		File:     path,
	})
	if err != nil {
		gologger.Warning().Msgf("Could not watch responder log %s: %s\n", path, err)
		return
	}
	ch, err := fw.Watch()
	if err != nil {
		gologger.Warning().Msgf("Could not start responder log watcher %s: %s\n", path, err)
		return
	}
	for data := range ch {
		out <- data
	}
}

func (h *ResponderServer) watchHashDumpFiles(out chan<- string) {
	seen := make(map[string]struct{})
	for {
		entries, err := os.ReadDir(h.tmpFolder)
		if err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if entry.IsDir() || !strings.HasSuffix(name, ".txt") {
					continue
				}
				// e.g. SMB-NTLMv2-SSP-1.2.3.4.txt
				if !strings.Contains(name, "NTLM") && !strings.Contains(name, "ClearText") {
					continue
				}
				path := filepath.Join(h.tmpFolder, name)
				content, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				for _, line := range strings.Split(string(content), "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					key := name + ":" + line
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					out <- line
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func (h *ResponderServer) handleResponderLogLine(data string) {
	for searchTerm, extractAfter := range responderMonitorList {
		if strings.Contains(data, searchTerm) {
			responderData, err := stringsutil.After(data, extractAfter)
			if err != nil {
				gologger.Warning().Msgf("Could not get responder interaction: %s\n", err)
				continue
			}
			h.storeResponderInteraction(strings.TrimSpace(responderData))
			return
		}
	}

	// Per-client dump files contain the raw fullhash only (no "Hash :" prefix).
	if strings.Count(data, ":") >= 3 && (strings.Contains(data, "::") || strings.Contains(strings.ToUpper(data), "NTLM")) {
		h.storeResponderInteraction(data)
	}
}

func (h *ResponderServer) storeResponderInteraction(responderData string) {
	if responderData == "" {
		return
	}
	interaction := &Interaction{
		Protocol:   "responder",
		RawRequest: responderData,
		Timestamp:  time.Now(),
	}
	data, err := jsoniter.Marshal(interaction)
	if err != nil {
		gologger.Warning().Msgf("Could not encode responder interaction: %s\n", err)
		return
	}
	gologger.Info().Msgf("Responder Interaction: %s\n", responderData)
	if err := h.options.Storage.AddInteractionWithId(h.options.Token, data); err != nil {
		gologger.Warning().Msgf("Could not store responder interaction: %s\n", err)
	}
}

func (h *ResponderServer) Close() {
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
	}
	if fileutil.FolderExists(h.tmpFolder) {
		_ = os.RemoveAll(h.tmpFolder)
	}
}
