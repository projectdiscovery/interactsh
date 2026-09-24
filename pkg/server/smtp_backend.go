package server

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/projectdiscovery/gologger"
)

// interactshBackend is the emersion/go-smtp Backend for collaborator SMTP.
type interactshBackend struct {
	srv *SMTPServer
}

func (b *interactshBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &interactshSession{
		srv:    b.srv,
		remote: c.Conn().RemoteAddr(),
	}, nil
}

// interactshSession accepts all mail and auth, then forwards message bodies
// to the existing interaction storage path.
type interactshSession struct {
	srv    *SMTPServer
	remote net.Addr
	from   string
	to     []string
}

func (s *interactshSession) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

func (s *interactshSession) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return nil
		}), nil
	case sasl.Login:
		return &acceptLoginServer{}, nil
	default:
		return nil, smtp.ErrAuthUnknownMechanism
	}
}

func (s *interactshSession) Mail(from string, _ *smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *interactshSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *interactshSession) Data(r io.Reader) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return s.srv.deliverSMTP(s.remote, s.from, s.to, body)
}

func (s *interactshSession) Reset() {
	s.from = ""
	s.to = nil
}

func (s *interactshSession) Logout() error {
	return nil
}

// acceptLoginServer implements LOGIN auth and always succeeds, matching the
// previous interactsh behavior of accepting any credentials.
type acceptLoginServer struct {
	step int
}

func (a *acceptLoginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	a.step++
	switch a.step {
	case 1:
		return []byte("Password:"), false, nil
	case 2:
		return nil, true, nil
	default:
		return nil, true, nil
	}
}

func (h *SMTPServer) deliverSMTP(remoteAddr net.Addr, from string, to []string, body []byte) error {
	atomic.AddUint64(&h.options.Stats.Smtp, 1)

	buf := bytes.NewBuffer(makeSMTPHeaders(remoteAddr, h.options.Domains[0], to))
	buf.Write(body)
	dataString := buf.String()

	gologger.Debug().Msgf("New SMTP request: %s %s %v %s\n", remoteAddr, from, to, dataString)
	h.storeSMTPRecipients(remoteAddr, from, dataString, to)
	return nil
}

// makeSMTPHeaders mirrors the Received header the previous smtpd integration
// attached before the message body.
func makeSMTPHeaders(remoteAddr net.Addr, hostname string, to []string) []byte {
	if len(to) == 0 {
		return nil
	}
	host, _, _ := net.SplitHostPort(remoteAddr.String())
	if host == "" {
		host = remoteAddr.String()
	}
	now := time.Now().Format("Mon, _2 Jan 2006 15:04:05 -0700 (MST)")
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "Received: from %s ([%s])\r\n", host, host)
	fmt.Fprintf(&buffer, "        by %s (interactsh) with SMTP\r\n", hostname)
	fmt.Fprintf(&buffer, "        for <%s>; %s\r\n", to[0], now)
	return buffer.Bytes()
}
