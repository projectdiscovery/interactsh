package server

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSMTPVRFYOnlyReturns252 reproduces the curl flow from issue #991: EHLO,
// VRFY, then further commands. Before the fix VRFY returned 502 and clients
// aborted before MAIL; here we assert 252 and that the session stays usable.
func TestSMTPVRFYOnlyReturns252(t *testing.T) {
	opts := &Options{
		Domains:  []string{"oast.fun"},
		ListenIP: "127.0.0.1",
		Stats:    &Metrics{},
	}
	smtpSrv, err := NewSMTPServer(opts)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() { _ = smtpSrv.smtpServer.Serve(ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	br := bufio.NewReader(conn)
	_, err = br.ReadString('\n')
	require.NoError(t, err)

	require.Equal(t, "250", smtpCmdCode(t, conn, "EHLO skMac2-5"))
	require.Equal(t, "252", smtpCmdCode(t, conn, "VRFY b@abcybn.oast.fun"))
	// Session must remain open for later SMTP commands (curl aborted here on 502).
	require.Equal(t, "250", smtpCmdCode(t, conn, "MAIL FROM:<a@a.com>"))
	require.Equal(t, "221", smtpCmdCode(t, conn, "QUIT"))
}

// Regression for https://github.com/projectdiscovery/interactsh/issues/991:
// VRFY must not return 502 so clients (e.g. curl) can continue to MAIL/DATA.
func TestSMTPVRFYCommandReturns252(t *testing.T) {
	store := newTestStorage(t)
	registerTestKey(t, store, "ab")

	opts := &Options{
		Domains:                  []string{"example.com"},
		ListenIP:                 "127.0.0.1",
		Storage:                  store,
		CorrelationIdLength:      2,
		CorrelationIdNonceLength: 1,
		Stats:                    &Metrics{},
	}
	smtpSrv, err := NewSMTPServer(opts)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() { _ = smtpSrv.smtpServer.Serve(ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	br := bufio.NewReader(conn)
	_, err = br.ReadString('\n') // banner
	require.NoError(t, err)

	require.Equal(t, "250", smtpCmdCode(t, conn, "EHLO testclient"))
	require.Equal(t, "252", smtpCmdCode(t, conn, "VRFY victim@aby.example.com"))
	require.Equal(t, "250", smtpCmdCode(t, conn, "MAIL FROM:<a@a.com>"))
	require.Equal(t, "250", smtpCmdCode(t, conn, "RCPT TO:<victim@aby.example.com>"))
	require.Equal(t, "354", smtpCmdCode(t, conn, "DATA"))
	require.Equal(t, "250", smtpCmdCode(t, conn, "Subject: test\r\n\r\nbody\r\n."))
	require.Equal(t, "221", smtpCmdCode(t, conn, "QUIT"))

	interactions, _, err := store.GetInteractions("ab", "secret")
	require.NoError(t, err)
	require.NotEmpty(t, interactions, "completed mail transaction must be stored")
}

func smtpCmdCode(t *testing.T, conn net.Conn, cmd string) string {
	t.Helper()
	_, err := fmt.Fprintf(conn, "%s\r\n", cmd)
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	for {
		resp, err := br.ReadString('\n')
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(resp), 3)
		// SMTP multiline replies use "250-..." until the final "250 ..." line.
		if len(resp) >= 4 && resp[3] == ' ' {
			return resp[0:3]
		}
	}
}
