package server

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/goimpacket/pkg/ntlm"
	"github.com/projectdiscovery/goimpacket/pkg/utf16le"
	"github.com/stretchr/testify/require"
)

func TestSMBCaptureNTLMv2(t *testing.T) {
	addr, opts := startSMBCaptureTest(t)
	conn, client, type2, sessionID := beginSMBAuthentication(t, addr)
	type3, err := client.Authenticate(type2)
	require.NoError(t, err)
	sendSMBTestPacket(t, conn, smbTestSessionSetup(t, 2, sessionID, type3, false))
	response := receiveSMBTestPacket(t, conn)
	require.Equal(t, uint32(0xc000006d), binary.LittleEndian.Uint32(response[8:12]), "capture must reject authentication")
	require.NotZero(t, binary.LittleEndian.Uint16(response[14:16]), "session setup must replenish the client's credit")

	registerTestKey(t, opts.Storage, "capture-client")
	h := &HTTPServer{options: opts}
	w := httptest.NewRecorder()
	h.pollHandler(w, httptest.NewRequest(http.MethodGet, "/poll?id=capture-client&secret=secret", nil))
	require.Equal(t, http.StatusOK, w.Code)
	var poll PollResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &poll))
	require.Len(t, poll.Extra, 1, "the client poll must contain the SMB interaction")
	var interaction Interaction
	require.NoError(t, json.Unmarshal([]byte(poll.Extra[0]), &interaction))
	require.Equal(t, "smb", interaction.Protocol)
	require.Equal(t, conn.LocalAddr().String(), interaction.RemoteAddress)
	require.False(t, interaction.Timestamp.IsZero())
	ntOffset := binary.LittleEndian.Uint32(type3[24:28])
	ntLength := binary.LittleEndian.Uint16(type3[20:22])
	ntResponse := type3[ntOffset : ntOffset+uint32(ntLength)]
	require.Equal(t, "capture-user::WORKGROUP:"+hex.EncodeToString(type2[24:32])+":"+hex.EncodeToString(ntResponse[:16])+":"+hex.EncodeToString(ntResponse[16:]), interaction.RawRequest)
	require.Equal(t, uint64(1), atomic.LoadUint64(&opts.Stats.Smb))
}

func TestSMBCaptureAfterInterruptedAuthentication(t *testing.T) {
	addr, _ := startSMBCaptureTest(t)
	first, _, _, _ := beginSMBAuthentication(t, addr)
	require.NoError(t, first.Close())
	second, client, type2, sessionID := beginSMBAuthentication(t, addr)
	type3, err := client.Authenticate(type2)
	require.NoError(t, err)
	sendSMBTestPacket(t, second, smbTestSessionSetup(t, 2, sessionID, type3, false))
	response := receiveSMBTestPacket(t, second)
	require.Equal(t, uint32(0xc000006d), binary.LittleEndian.Uint32(response[8:12]))
}

func TestSMBCaptureAfterMalformedAuthentication(t *testing.T) {
	for _, malformed := range []string{"security token", "session setup", "command", "NTLM response"} {
		t.Run(malformed, func(t *testing.T) {
			addr, opts := startSMBCaptureTest(t)
			first, firstClient, firstType2, sessionID := beginSMBAuthentication(t, addr)
			packet := smbTestSessionSetup(t, 2, sessionID, []byte("invalid NTLM"), false)
			switch malformed {
			case "security token":
				packet[88] = 0xff
			case "session setup":
				packet = packet[:64]
			case "command":
				binary.LittleEndian.PutUint16(packet[12:14], 3)
			case "NTLM response":
				type3, err := firstClient.Authenticate(firstType2)
				require.NoError(t, err)
				binary.LittleEndian.PutUint16(type3[20:22], 8)
				packet = smbTestSessionSetup(t, 2, sessionID, type3, false)
			}
			sendSMBTestPacket(t, first, packet)
			if malformed == "NTLM response" {
				response := receiveSMBTestPacket(t, first)
				require.Equal(t, uint32(0xc000006d), binary.LittleEndian.Uint32(response[8:12]))
			} else {
				_, err := first.Read(make([]byte, 1))
				require.ErrorIs(t, err, io.EOF, "relay must close the malformed exchange")
			}
			second, client, type2, sessionID := beginSMBAuthentication(t, addr)
			type3, err := client.Authenticate(type2)
			require.NoError(t, err)
			sendSMBTestPacket(t, second, smbTestSessionSetup(t, 2, sessionID, type3, false))
			response := receiveSMBTestPacket(t, second)
			require.Equal(t, uint32(0xc000006d), binary.LittleEndian.Uint32(response[8:12]))
			interactions, err := opts.Storage.GetInteractionsWithIdForConsumer(opts.Token, "capture-client")
			require.NoError(t, err)
			require.Len(t, interactions, 1, "only the valid authentication must be captured")
		})
	}
}

func TestSMBCaptureWhileAnotherAuthenticationWaits(t *testing.T) {
	addr, _ := startSMBCaptureTest(t)
	beginSMBAuthentication(t, addr)
	second, client, type2, sessionID := beginSMBAuthentication(t, addr)
	type3, err := client.Authenticate(type2)
	require.NoError(t, err)
	sendSMBTestPacket(t, second, smbTestSessionSetup(t, 2, sessionID, type3, false))
	response := receiveSMBTestPacket(t, second)
	require.Equal(t, uint32(0xc000006d), binary.LittleEndian.Uint32(response[8:12]))
}

func TestSMBChallengeTargetInfo(t *testing.T) {
	addr, _ := startSMBCaptureTest(t)
	_, _, type2, _ := beginSMBAuthentication(t, addr)
	start := binary.LittleEndian.Uint32(type2[44:48])
	length := binary.LittleEndian.Uint16(type2[40:42])
	require.LessOrEqual(t, uint64(start)+uint64(length), uint64(len(type2)))
	info, ok := ntlm.ParseAvPairs(type2[start : start+uint32(length)])
	require.True(t, ok)
	for _, id := range []uint16{ntlm.MsvAvNbComputerName, ntlm.MsvAvNbDomainName, ntlm.MsvAvDnsComputerName} {
		require.NotEmpty(t, info[id], "NTLMv2 clients need server identity in target information")
	}
	require.Equal(t, "oast.example.com", utf16le.DecodeToString(info[ntlm.MsvAvDnsComputerName]))
}

func startSMBCaptureTest(t *testing.T) (string, *Options) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	opts := &Options{Domains: []string{"oast.example.com"}, ListenIP: "127.0.0.1", SmbPort: port, Token: "capture-test-token", Storage: newTestStorage(t), Stats: &Metrics{}}
	require.NoError(t, opts.Storage.SetID(opts.Token))
	srv, err := NewSMBServer(opts)
	require.NoError(t, err)
	alive := make(chan bool, 2)
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(alive) }()
	require.True(t, <-alive)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, time.Second, 10*time.Millisecond)
	t.Cleanup(func() {
		srv.Close()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Error("SMB capture did not stop")
		}
	})
	return addr, opts
}

func beginSMBAuthentication(t *testing.T, addr string) (net.Conn, *ntlm.Client, []byte, uint64) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	negotiate := make([]byte, 38)
	binary.LittleEndian.PutUint16(negotiate[0:2], 36)
	binary.LittleEndian.PutUint16(negotiate[2:4], 1)
	binary.LittleEndian.PutUint16(negotiate[4:6], 1)
	binary.LittleEndian.PutUint16(negotiate[36:38], 0x0202)
	sendSMBTestPacket(t, conn, smbTestRequest(0, 0, 0, negotiate))
	response := receiveSMBTestPacket(t, conn)
	require.NotZero(t, binary.LittleEndian.Uint16(response[14:16]), "negotiate must grant a session setup credit")
	require.Equal(t, uint16(0x0202), binary.LittleEndian.Uint16(response[68:70]))
	client := &ntlm.Client{User: "capture-user", Password: "dummy-password", Domain: "WORKGROUP", Workstation: "test-client"}
	type1, err := client.Negotiate()
	require.NoError(t, err)
	sendSMBTestPacket(t, conn, smbTestSessionSetup(t, 1, 0, type1, true))
	response = receiveSMBTestPacket(t, conn)
	require.Equal(t, uint32(0xc0000016), binary.LittleEndian.Uint32(response[8:12]))
	require.NotZero(t, binary.LittleEndian.Uint16(response[14:16]), "challenge must grant an authentication credit")
	start := int(binary.LittleEndian.Uint16(response[68:70]))
	length := int(binary.LittleEndian.Uint16(response[70:72]))
	require.LessOrEqual(t, start+length, len(response))
	security := response[start : start+length]
	offset := bytes.Index(security, []byte("NTLMSSP\x00"))
	require.GreaterOrEqual(t, offset, 0)
	type2 := security[offset:]
	require.GreaterOrEqual(t, len(type2), 48)
	require.Equal(t, uint32(2), binary.LittleEndian.Uint32(type2[8:12]))
	return conn, client, type2, binary.LittleEndian.Uint64(response[40:48])
}

func smbTestRequest(command uint16, messageID, sessionID uint64, body []byte) []byte {
	header := make([]byte, 64)
	copy(header, []byte("\xfeSMB"))
	binary.LittleEndian.PutUint16(header[4:6], 64)
	binary.LittleEndian.PutUint16(header[12:14], command)
	binary.LittleEndian.PutUint16(header[14:16], 1)
	binary.LittleEndian.PutUint64(header[24:32], messageID)
	binary.LittleEndian.PutUint64(header[40:48], sessionID)
	return append(header, body...)
}

func smbTestSessionSetup(t *testing.T, messageID, sessionID uint64, token []byte, initial bool) []byte {
	t.Helper()
	var encoded []byte
	var err error
	if initial {
		inner, e := asn1.Marshal(struct {
			MechTypes []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
			MechToken []byte                  `asn1:"explicit,tag:2"`
		}{[]asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}}, token})
		require.NoError(t, e)
		tagged, e := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner})
		require.NoError(t, e)
		oid, e := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2})
		require.NoError(t, e)
		encoded, err = asn1.Marshal(asn1.RawValue{Class: 1, Tag: 0, IsCompound: true, Bytes: append(oid, tagged...)})
	} else {
		inner, e := asn1.Marshal(struct {
			ResponseToken []byte `asn1:"explicit,tag:2"`
		}{token})
		require.NoError(t, e)
		encoded, err = asn1.Marshal(asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: inner})
	}
	require.NoError(t, err)
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25)
	body[3] = 1
	binary.LittleEndian.PutUint16(body[12:14], 88)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(encoded)))
	return smbTestRequest(1, messageID, sessionID, append(body, encoded...))
}

func sendSMBTestPacket(t *testing.T, conn net.Conn, packet []byte) {
	t.Helper()
	frame := make([]byte, 4, 4+len(packet))
	binary.BigEndian.PutUint32(frame, uint32(len(packet)))
	_, err := io.Copy(conn, bytes.NewReader(append(frame, packet...)))
	require.NoError(t, err)
}

func receiveSMBTestPacket(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var length [4]byte
	_, err := io.ReadFull(conn, length[:])
	require.NoError(t, err, "SMB server must send the next handshake response")
	size := binary.BigEndian.Uint32(length[:])
	require.LessOrEqual(t, size, uint32(1<<20))
	packet := make([]byte, size)
	_, err = io.ReadFull(conn, packet)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(packet), 64)
	require.True(t, strings.HasPrefix(string(packet), "\xfeSMB"))
	return packet
}
