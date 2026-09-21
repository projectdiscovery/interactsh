package server

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestIsInConfiguredDomain(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1"}, "127.0.0.1")
	opts.Domains = []string{"example.com", "collab.test"}
	dnsServer := NewDNSServer("udp", opts)

	inZone := []string{
		"example.com",
		"example.com.",
		"sub.example.com.",
		"deep.nested.sub.example.com.",
		"SUB.EXAMPLE.COM.",
		"anything.collab.test.",
		"_acme-challenge.example.com.",
	}
	for _, name := range inZone {
		require.True(t, dnsServer.isInConfiguredDomain(name), "expected %q to be in zone", name)
	}

	outOfZone := []string{
		"google.com.",
		"example.org.",
		// label-boundary cases: must not be treated as part of example.com
		"evil-example.com.",
		"notexample.com.",
		// configured domain appearing as a prefix, not a suffix
		"example.com.attacker.net.",
		".",
	}
	for _, name := range outOfZone {
		require.False(t, dnsServer.isInConfiguredDomain(name), "expected %q to be out of zone", name)
	}
}

func TestServeDNSRefusesOutOfZoneQuery(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1"}, "127.0.0.1")
	opts.RestrictToDomains = true
	opts.Stats = &Metrics{}
	dnsServer := NewDNSServer("udp", opts)

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)

	w := &captureResponseWriter{}
	dnsServer.ServeDNS(w, req)

	require.NotNil(t, w.msg, "expected a response to be written")
	require.Equal(t, dns.RcodeRefused, w.msg.Rcode, "expected REFUSED for out-of-zone query")
	require.False(t, w.msg.Authoritative, "should not claim authority over a foreign zone")
	require.Empty(t, w.msg.Answer, "expected no answer records")
	require.Empty(t, w.msg.Extra, "expected no glue records to leak")
}

func TestServeDNSAnswersInZoneQuery(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1"}, "127.0.0.1")
	opts.RestrictToDomains = true
	opts.CorrelationIdLength = 20
	opts.Stats = &Metrics{}
	dnsServer := NewDNSServer("udp", opts)

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("payload.example.com"), dns.TypeA)

	w := &captureResponseWriter{}
	dnsServer.ServeDNS(w, req)

	require.NotNil(t, w.msg, "expected a response to be written")
	require.Equal(t, dns.RcodeSuccess, w.msg.Rcode, "in-zone queries must still be answered")
	require.True(t, w.msg.Authoritative)
	require.True(t, hasRecord(w.msg.Answer, dns.TypeA, "192.0.2.1"), "expected the configured IP in the answer")
}

func TestServeDNSRestrictionDisabledPreservesLegacyBehaviour(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1"}, "127.0.0.1")
	opts.RestrictToDomains = false
	opts.CorrelationIdLength = 20
	opts.Stats = &Metrics{}
	dnsServer := NewDNSServer("udp", opts)

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)

	w := &captureResponseWriter{}
	dnsServer.ServeDNS(w, req)

	require.NotNil(t, w.msg)
	require.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
	require.True(t, hasRecord(w.msg.Answer, dns.TypeA, "192.0.2.1"), "opt-out should restore answering any zone")
}

// A collaborator must answer every subdomain of its configured domain, at any
// depth, since payload hostnames are generated per interaction.
func TestServeDNSAnswersArbitrarySubdomains(t *testing.T) {
	payloads := []string{
		"c8dj4k2l9x.app.collab.tr4t.io.",
		"cq7v0p2m1abcdefghij.app.collab.tr4t.io.",
		"deep.nested.levels.of.subdomains.app.collab.tr4t.io.",
		"with-hyphens-and-123.app.collab.tr4t.io.",
		"MiXeDcAsE.app.collab.tr4t.io.",
		"_acme-challenge.app.collab.tr4t.io.",
		"app.collab.tr4t.io.",
	}

	for _, payload := range payloads {
		opts := newTestOptions([]string{"54.245.113.160"}, "127.0.0.1")
		opts.Domains = []string{"app.collab.tr4t.io"}
		opts.RestrictToDomains = true
		opts.CorrelationIdLength = 20
		opts.Stats = &Metrics{}
		dnsServer := NewDNSServer("udp", opts)

		req := new(dns.Msg)
		req.SetQuestion(payload, dns.TypeA)

		w := &captureResponseWriter{}
		dnsServer.ServeDNS(w, req)

		require.NotNil(t, w.msg, "expected a response for %s", payload)
		require.NotEqual(t, dns.RcodeRefused, w.msg.Rcode, "subdomain %s must not be refused", payload)
		require.True(t, hasRecord(w.msg.Answer, dns.TypeA, "54.245.113.160"),
			"expected collaborator IP in answer for %s", payload)
	}
}

// Subdomains must keep working across every record type the collaborator serves,
// since OOB payloads are not limited to A lookups.
func TestServeDNSAnswersSubdomainsForAllRecordTypes(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeANY, dns.TypeMX, dns.TypeNS, dns.TypeSOA, dns.TypeTXT} {
		opts := newTestOptions([]string{"54.245.113.160"}, "127.0.0.1")
		opts.Domains = []string{"app.collab.tr4t.io"}
		opts.RestrictToDomains = true
		opts.CorrelationIdLength = 20
		opts.Stats = &Metrics{}
		dnsServer := NewDNSServer("udp", opts)

		req := new(dns.Msg)
		req.SetQuestion("c8dj4k2l9x.app.collab.tr4t.io.", qtype)

		w := &captureResponseWriter{}
		dnsServer.ServeDNS(w, req)

		require.NotNil(t, w.msg, "expected a response for qtype %d", qtype)
		require.NotEqual(t, dns.RcodeRefused, w.msg.Rcode,
			"in-zone subdomain must not be refused for qtype %d", qtype)
	}
}

// An in-zone question must not smuggle a foreign one through alongside it.
func TestServeDNSRefusesMixedInAndOutOfZoneQuestions(t *testing.T) {
	opts := newTestOptions([]string{"54.245.113.160"}, "127.0.0.1")
	opts.Domains = []string{"app.collab.tr4t.io"}
	opts.RestrictToDomains = true
	opts.CorrelationIdLength = 20
	opts.Stats = &Metrics{}
	dnsServer := NewDNSServer("udp", opts)

	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "c8dj4k2l9x.app.collab.tr4t.io.", Qclass: dns.ClassINET, Qtype: dns.TypeA},
		{Name: "google.com.", Qclass: dns.ClassINET, Qtype: dns.TypeA},
	}

	w := &captureResponseWriter{}
	dnsServer.ServeDNS(w, req)

	require.NotNil(t, w.msg)
	require.Equal(t, dns.RcodeRefused, w.msg.Rcode, "a foreign question must refuse the whole message")
	require.Empty(t, w.msg.Answer, "no records may leak for the foreign question")
}

// captureResponseWriter is a dns.ResponseWriter that records the written message.
type captureResponseWriter struct {
	msg *dns.Msg
}

func (c *captureResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

func (c *captureResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000}
}

func (c *captureResponseWriter) WriteMsg(m *dns.Msg) error {
	c.msg = m
	return nil
}

func (c *captureResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (c *captureResponseWriter) Close() error                { return nil }
func (c *captureResponseWriter) TsigStatus() error           { return nil }
func (c *captureResponseWriter) TsigTimersOnly(bool)         {}
func (c *captureResponseWriter) Hijack()                     {}
