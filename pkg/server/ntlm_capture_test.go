package server

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/goimpacket/pkg/ntlm"
	"github.com/projectdiscovery/goimpacket/pkg/relay"
	"github.com/stretchr/testify/require"
)

func TestFormatNetNTLMv2RejectsMalformedAuthentication(t *testing.T) {
	client := &ntlm.Client{User: "user", Password: "dummy-password", Domain: "WORKGROUP"}
	type1, err := client.Negotiate()
	require.NoError(t, err)
	type2, err := ntlm.NewServer(ntlmCaptureTargetName).Challenge(type1)
	require.NoError(t, err)
	type3, err := client.Authenticate(type2)
	require.NoError(t, err)
	_, user, domain, err := formatNetNTLMv2(type3, type2[24:32])
	require.NoError(t, err)
	require.Equal(t, "user", user)
	require.Equal(t, "WORKGROUP", domain)

	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"signature", func(msg []byte) []byte { msg[0] = 0; return msg }},
		{"message type", func(msg []byte) []byte { binary.LittleEndian.PutUint32(msg[8:12], 1); return msg }},
		{"truncated header", func(msg []byte) []byte { return msg[:63] }},
		{"NTLMv1 response", func(msg []byte) []byte { binary.LittleEndian.PutUint16(msg[20:22], 24); return msg }},
		{"blob version", func(msg []byte) []byte { msg[binary.LittleEndian.Uint32(msg[24:28])+16] = 0; return msg }},
		{"nt response offset", func(msg []byte) []byte { binary.LittleEndian.PutUint32(msg[24:28], ^uint32(0)); return msg }},
		{"domain offset", func(msg []byte) []byte { binary.LittleEndian.PutUint32(msg[32:36], ^uint32(0)); return msg }},
		{"user offset", func(msg []byte) []byte { binary.LittleEndian.PutUint32(msg[40:44], ^uint32(0)); return msg }},
		{"domain encoding", func(msg []byte) []byte { binary.LittleEndian.PutUint16(msg[28:30], 1); return msg }},
		{"user encoding", func(msg []byte) []byte { binary.LittleEndian.PutUint16(msg[36:38], 1); return msg }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := formatNetNTLMv2(tc.mutate(append([]byte(nil), type3...)), type2[24:32])
			require.Error(t, err)
		})
	}
	_, _, _, err = formatNetNTLMv2(type3, nil)
	require.Error(t, err, "a NetNTLMv2 hash needs an eight-byte server challenge")
}

func TestNTLMCaptureShutdownDuringAuthentication(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &captureTestProtocolServer{started: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- runNTLMCapture(ctx, srv, "smb", &Options{}, nil) }()
	<-srv.started
	client := &ntlm.Client{User: "user", Password: "dummy-password"}
	type1, err := client.Negotiate()
	require.NoError(t, err)
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close(); _ = clientConn.Close() })
	auth := relay.AuthResult{NTLMType1: type1, ServerConn: serverConn, Type2Ch: make(chan []byte, 1), Type3Ch: make(chan []byte, 1), ResultCh: make(chan bool, 1)}
	t.Cleanup(func() { close(auth.Type3Ch) })
	srv.authCh <- auth
	select {
	case <-auth.Type2Ch:
	case <-time.After(time.Second):
		t.Fatal("capture did not send a challenge")
	}
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("capture did not stop while waiting for authentication")
	}
	select {
	case result := <-auth.ResultCh:
		require.False(t, result)
	default:
		t.Fatal("capture did not reject the cancelled authentication")
	}
}

type captureTestProtocolServer struct {
	authCh  chan<- relay.AuthResult
	started chan struct{}
}

func (s *captureTestProtocolServer) Start(ch chan<- relay.AuthResult) error {
	s.authCh = ch
	close(s.started)
	return nil
}

func (s *captureTestProtocolServer) Stop() error {
	close(s.authCh)
	return nil
}
