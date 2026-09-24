package server

import (
	"context"

	"github.com/Mzack9999/goimpacket/pkg/relay"
	"github.com/projectdiscovery/gologger"
)

// SMBServer is an in-process SMB2 NTLM hash capture server backed by
// goimpacket. It replaces the previous Python/impacket smbserver wrapper.
type SMBServer struct {
	options *Options
	cancel  context.CancelFunc
}

// NewSMBServer returns a new SMB server.
func NewSMBServer(options *Options) (*SMBServer, error) {
	return &SMBServer{options: options}, nil
}

// ListenAndServe listens on the configured SMB port and forwards captured
// NetNTLMv2 hashes into the interactsh storage.
func (h *SMBServer) ListenAndServe(smbAlive chan bool) error {
	smbAlive <- true
	defer func() {
		smbAlive <- false
	}()

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	listenAddr := formatAddress(h.options.ListenIP, h.options.SmbPort)
	srv := relay.NewSMBRelayServer(listenAddr)

	gologger.Info().Msgf("Starting SMB capture server on %s\n", listenAddr)
	return runNTLMCapture(ctx, srv, "smb", h.options, &h.options.Stats.Smb)
}

// Close stops the SMB capture server.
func (h *SMBServer) Close() {
	if h.cancel != nil {
		h.cancel()
	}
}
