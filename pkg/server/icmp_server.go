package server

import (
	"bytes"
	"errors"
	"net"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/icmp"
)

// ICMPServer is a icmp server instance that listens for ICMP packets
type ICMPServer struct {
	options *Options
}

// NewICMPServer returns a ICMP server.
func NewICMPServer(options *Options) (*ICMPServer, error) {
	server := &ICMPServer{options: options}
	return server, nil
}

// ListenAndServe handles the internal logic
func (h *ICMPServer) ListenAndServe() error {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		buf := make([]byte, 512)
		_, from, err := conn.ReadFrom(buf)
		if err != nil {
			gologger.Error().Msgf("Error reading ICMP message: %s\n", err)
			continue
		}

		msg, err := icmp.ParseMessage(1, buf)
		if err != nil {
			gologger.Error().Msgf("Error reading ICMP message: %s\n", err)
			continue
		}

		if err := h.defaultHandler(from, msg); err != nil {
			gologger.Error().Msgf("Error handling ICMP message: %s\n", err)
		}
	}
}

// defaultHandler is a handler for default collaborator requests
func (h *ICMPServer) defaultHandler(remoteAddr net.Addr, msg *icmp.Message) error {
	var uniqueID string

	gologger.Debug().Msgf("New ICMP interaction from: %s \n", remoteAddr)

	// Extract correlation id from the ICMP body
	switch body := msg.Body.(type) {
	case *icmp.Echo:
		uniqueID = string(body.Data[:33])
		if uniqueID != "" {
			correlationID := uniqueID[:20]
			host, _, _ := net.SplitHostPort(remoteAddr.String())
			if host == "" {
				host = remoteAddr.String()
			}
			interaction := &Interaction{
				Protocol:      "icmp",
				UniqueID:      uniqueID,
				RawRequest:    string(body.Data),
				RemoteAddress: host,
				Timestamp:     time.Now(),
			}
			buffer := &bytes.Buffer{}
			if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
				gologger.Warning().Msgf("Could not encode icmp interaction: %s\n", err)
			} else {
				gologger.Debug().Msgf("%s\n", buffer.String())
				if err := h.options.Storage.AddInteraction(correlationID, buffer.Bytes()); err != nil {
					gologger.Warning().Msgf("Could not store icmp interaction: %s\n", err)
				}
			}
		}
	default:
		return errors.New("not a *icmp.Echo")
	}

	return nil
}
