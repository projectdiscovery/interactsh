package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/goimpacket/pkg/ntlm"
	"github.com/projectdiscovery/goimpacket/pkg/relay"
	"github.com/projectdiscovery/goimpacket/pkg/utf16le"
	"github.com/projectdiscovery/gologger"
)

// ntlmCaptureTargetName is the SPNEGO target name advertised in the NTLM Type 2
// challenge. It is intentionally generic and matches what Responder advertises.
const ntlmCaptureTargetName = "WORKGROUP"

const ntlmCaptureTimeout = 30 * time.Second

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

	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		_ = srv.Stop()
		workers.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case auth, ok := <-authCh:
			if !ok {
				return nil
			}

			// A relay handler can exit without sending or closing Type3Ch.
			// Each exchange needs its own bounded wait so it cannot block others.
			workers.Go(func() {
				captureNTLMAuth(ctx, auth, protocolName, options, statsCounter)
			})
		}
	}
}

func captureNTLMAuth(ctx context.Context, auth relay.AuthResult, protocolName string, options *Options, statsCounter *uint64) {
	ctx, cancel := context.WithTimeout(ctx, ntlmCaptureTimeout)
	defer cancel()
	closeOnCancel := context.AfterFunc(ctx, func() {
		if auth.ServerConn != nil {
			_ = auth.ServerConn.Close()
		}
	})
	defer closeOnCancel()
	defer close(auth.Type2Ch)
	// A closed result channel yields false to the relay. Always reject auth:
	// we have no backing session and must not grant the client any access.
	defer close(auth.ResultCh)

	hostname := "INTERACTSH"
	if len(options.Domains) > 0 {
		hostname = options.Domains[0]
	}
	type2, err := ntlmCaptureChallenge(auth.NTLMType1, hostname)
	if err != nil {
		gologger.Debug().Msgf("%s NTLM challenge build failed for %s: %s", protocolName, auth.SourceAddr, err)
		return
	}

	// The 8-byte server challenge sits at bytes 24:32 of the Type 2 message
	// (MS-NLMP 2.2.1.2). Snapshot it before forwarding it to the client.
	serverChallenge := bytes.Clone(type2[24:32])
	select {
	case auth.Type2Ch <- type2:
	case <-ctx.Done():
		return
	}

	var type3 []byte
	select {
	case type3 = <-auth.Type3Ch:
		if len(type3) == 0 {
			// Channel closed without a Type 3, nothing to record.
			return
		}
	case <-ctx.Done():
		return
	}

	hash, _, _, err := formatNetNTLMv2(type3, serverChallenge)
	if err != nil {
		gologger.Debug().Msgf("%s NetNTLMv2 extract failed for %s: %s", protocolName, auth.SourceAddr, err)
		return
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
	data, err := json.Marshal(interaction)
	if err != nil {
		gologger.Warning().Msgf("Could not encode %s interaction: %s\n", protocolName, err)
		return
	}
	gologger.Debug().Msgf("%s NetNTLMv2 capture from %s", protocolName, auth.SourceAddr)
	if err := options.Storage.AddInteractionWithId(options.Token, data); err != nil {
		gologger.Warning().Msgf("Could not store %s interaction: %s\n", protocolName, err)
	}
}

func ntlmCaptureChallenge(type1 []byte, hostname string) ([]byte, error) {
	type2, err := ntlm.NewServer(ntlmCaptureTargetName).Challenge(type1)
	if err != nil {
		return nil, err
	}
	// The library supplies only MsvAvEOL. Windows signing/sealing needs the
	// NetBIOS names, and Impacket uses the DNS computer name to build the SPN.
	var info []byte
	for _, pair := range []struct {
		id   uint16
		name string
	}{
		{ntlm.MsvAvNbComputerName, "INTERACTSH"},
		{ntlm.MsvAvNbDomainName, ntlmCaptureTargetName},
		{ntlm.MsvAvDnsComputerName, hostname},
	} {
		value := utf16le.EncodeStringToBytes(pair.name)
		if len(info)+4+len(value)+4 > 65535 {
			return nil, errors.New("NTLM target information exceeds 65535 bytes")
		}
		info = binary.LittleEndian.AppendUint16(info, pair.id)
		info = binary.LittleEndian.AppendUint16(info, uint16(len(value)))
		info = append(info, value...)
	}
	info = append(info, 0, 0, 0, 0) // MsvAvEOL
	offset := len(type2)
	if existing := binary.LittleEndian.Uint32(type2[44:48]); existing >= 48 && int(existing) <= len(type2) {
		offset = int(existing)
	}
	binary.LittleEndian.PutUint32(type2[20:24], binary.LittleEndian.Uint32(type2[20:24])|ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO)
	binary.LittleEndian.PutUint16(type2[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint16(type2[42:44], uint16(len(info)))
	binary.LittleEndian.PutUint32(type2[44:48], uint32(offset))
	return append(type2[:offset], info...), nil
}

// formatNetNTLMv2 parses an NTLMSSP_AUTH (Type 3) message and returns a
// hashcat NetNTLMv2 (mode 5600) formatted string along with the extracted
// username and domain. Field layout per MS-NLMP 2.2.1.3.
func formatNetNTLMv2(type3, serverChallenge []byte) (hash, user, domain string, err error) {
	le := binary.LittleEndian
	if len(type3) < 64 {
		return "", "", "", errors.New("type3 message too short")
	}
	if !bytes.Equal(type3[:8], []byte("NTLMSSP\x00")) || le.Uint32(type3[8:12]) != ntlm.NtLmAuthenticate {
		return "", "", "", errors.New("invalid NTLM authenticate message")
	}
	if len(serverChallenge) != 8 {
		return "", "", "", errors.New("server challenge must contain 8 bytes")
	}

	ntLen := le.Uint16(type3[20:22])
	ntOff := le.Uint32(type3[24:28])
	if uint64(ntOff)+uint64(ntLen) > uint64(len(type3)) {
		return "", "", "", errors.New("nt response out of bounds")
	}
	ntResp := type3[ntOff : ntOff+uint32(ntLen)]
	if len(ntResp) < 16+28+4 {
		return "", "", "", errors.New("nt response too short for NTLMv2")
	}
	if ntResp[16] != 1 || ntResp[17] != 1 {
		return "", "", "", errors.New("invalid NTLMv2 response version")
	}

	domLen := le.Uint16(type3[28:30])
	domOff := le.Uint32(type3[32:36])
	if uint64(domOff)+uint64(domLen) > uint64(len(type3)) {
		return "", "", "", errors.New("domain field out of bounds")
	}
	if domLen%2 != 0 {
		return "", "", "", errors.New("domain field has an odd UTF-16 byte length")
	}
	domain = utf16le.DecodeToString(type3[domOff : domOff+uint32(domLen)])

	userLen := le.Uint16(type3[36:38])
	userOff := le.Uint32(type3[40:44])
	if uint64(userOff)+uint64(userLen) > uint64(len(type3)) {
		return "", "", "", errors.New("user field out of bounds")
	}
	if userLen%2 != 0 {
		return "", "", "", errors.New("user field has an odd UTF-16 byte length")
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
