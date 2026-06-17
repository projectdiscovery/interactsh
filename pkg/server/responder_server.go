package server

import (
	"context"
	"sync"

	"github.com/Mzack9999/goimpacket/pkg/relay"
	"github.com/projectdiscovery/gologger"
	"go.uber.org/multierr"
)

// responderListenPorts is the set of TCP ports the Responder-equivalent
// in-process capture binds to. Port 445 covers direct SMB and 139 covers
// NetBIOS-over-TCP. The legacy Python Responder additionally listened on
// LLMNR/NBT-NS/MDNS broadcast ports to poison name resolution, but those
// poisoners are intentionally not part of goimpacket and have therefore
// been dropped: in interactsh's typical OOB-callback deployment the victim
// is reaching the server directly via DNS, so name poisoning would not
// trigger anyway.
var responderListenPorts = []int{445, 139}

// ResponderServer is a Responder-equivalent NTLMv2 hash capture wrapper
// backed by goimpacket. It replaces the previous dockerized Responder
// process, and now binds multiple SMB-compatible ports to maximise the
// chance of catching coerced authentications.
type ResponderServer struct {
	options *Options
	cancel  context.CancelFunc
}

// NewResponderServer returns a new Responder-equivalent server.
func NewResponderServer(options *Options) (*ResponderServer, error) {
	return &ResponderServer{options: options}, nil
}

// ListenAndServe spins up an SMB capture listener on each of
// responderListenPorts. The provided channel is signalled true once at
// least one listener is ready and false on shutdown.
func (h *ResponderServer) ListenAndServe(responderAlive chan bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	// Always include the configured SMB port so users can override 445 the
	// same way they always could.
	ports := uniqueInts(append([]int{h.options.SmbPort}, responderListenPorts...))

	var (
		wg          sync.WaitGroup
		errs        []error
		errsMu      sync.Mutex
		signaledUp  bool
		signaledMu  sync.Mutex
	)

	signalUp := func() {
		signaledMu.Lock()
		defer signaledMu.Unlock()
		if !signaledUp {
			signaledUp = true
			responderAlive <- true
		}
	}

	for _, port := range ports {
		port := port
		listenAddr := formatAddress(h.options.ListenIP, port)
		srv := relay.NewSMBRelayServer(listenAddr)
		gologger.Info().Msgf("Starting Responder SMB capture on %s\n", listenAddr)
		signalUp()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runNTLMCapture(ctx, srv, "responder", h.options, &h.options.Stats.Smb); err != nil {
				gologger.Warning().Msgf("Responder capture on %s exited: %s\n", listenAddr, err)
				errsMu.Lock()
				errs = append(errs, err)
				errsMu.Unlock()
			}
		}()
	}

	wg.Wait()
	responderAlive <- false
	return multierr.Combine(errs...)
}

// Close stops every Responder capture listener.
func (h *ResponderServer) Close() {
	if h.cancel != nil {
		h.cancel()
	}
}

func uniqueInts(in []int) []int {
	seen := make(map[int]bool, len(in))
	out := make([]int, 0, len(in))
	for _, v := range in {
		if v <= 0 || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
