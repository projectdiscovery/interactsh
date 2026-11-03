package server

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	"github.com/stretchr/testify/require"
)

func TestDNSServerReturnsAAAARecords(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1", "2001:db8::1"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	dnsServer.handleACNAMEANY(dns.Fqdn("test.example.com"), msg)

	require.True(t, hasRecord(msg.Answer, dns.TypeA, "192.0.2.1"), "expected A record")
	require.True(t, hasRecord(msg.Answer, dns.TypeAAAA, "2001:db8::1"), "expected AAAA record")
	require.True(t, hasRecord(msg.Extra, dns.TypeAAAA, "2001:db8::1"), "expected AAAA glue record")
}

func TestDNSServerIPv6OnlyResponses(t *testing.T) {
	opts := newTestOptions([]string{"2001:db8::5"}, "::1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	dnsServer.handleACNAMEANY(dns.Fqdn("ipv6.example.com"), msg)

	require.False(t, hasRecord(msg.Answer, dns.TypeA, ""), "did not expect IPv4 record")
	require.True(t, hasRecord(msg.Answer, dns.TypeAAAA, "2001:db8::5"), "expected IPv6 answer")
}

func TestDNSServerCustomIPv6Record(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1", "2001:db8::1"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)
	dnsServer.customRecords.records["ipv6"] = []CustomRecordConfig{{Type: "AAAA", Value: "2001:db8::dead"}}

	msg := new(dns.Msg)
	msg.Question = []dns.Question{{Name: dns.Fqdn("ipv6.example.com"), Qtype: dns.TypeAAAA}}
	dnsServer.handleACNAMEANY(dns.Fqdn("ipv6.example.com"), msg)

	require.True(t, hasRecord(msg.Answer, dns.TypeAAAA, "2001:db8::dead"), "expected custom AAAA record")
}

func TestDNSServerNoConfiguredIPs(t *testing.T) {
	opts := newTestOptions(nil, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	dnsServer.handleACNAMEANY(dns.Fqdn("empty.example.com"), msg)

	require.Empty(t, msg.Answer, "expected no answers when no IPs configured")
	require.Empty(t, msg.Extra, "expected no glue records when no IPs configured")
}

func TestDNSGlueRecordsIncludeBothFamilies(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1", "2001:db8::1"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	dnsServer.handleACNAMEANY(dns.Fqdn("glue.example.com"), msg)

	require.True(t, hasRecord(msg.Extra, dns.TypeA, "192.0.2.1"), "expected IPv4 glue")
	require.True(t, hasRecord(msg.Extra, dns.TypeAAAA, "2001:db8::1"), "expected IPv6 glue")
}

func TestDNSServerDefaultIPv4Answer(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.50"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	dnsServer.handleACNAMEANY(dns.Fqdn("test.example.com"), msg)

	require.Len(t, msg.Answer, 1)
	require.True(t, hasRecord(msg.Answer, dns.TypeA, "192.0.2.50"))
}

func TestDNSServerCustomIPv4Record(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.50"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)
	dnsServer.customRecords.records["app"] = []CustomRecordConfig{{Type: "A", Value: "198.51.100.5"}}

	msg := new(dns.Msg)
	msg.Question = []dns.Question{{Name: dns.Fqdn("app.example.com"), Qtype: dns.TypeA}}
	dnsServer.handleACNAMEANY(dns.Fqdn("app.example.com"), msg)

	require.True(t, hasRecord(msg.Answer, dns.TypeA, "198.51.100.5"), "expected custom IPv4 answer")
	require.False(t, hasRecord(msg.Answer, dns.TypeA, "192.0.2.50"), "default address should be overridden")
}

func TestDNSServerHandleMX(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.50"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	dnsServer.handleMX(dns.Fqdn("example.com"), msg)

	require.Len(t, msg.Answer, 1)
	record, ok := msg.Answer[0].(*dns.MX)
	require.True(t, ok)
	require.Equal(t, "mail.example.com.", record.Mx)
	require.EqualValues(t, 1, record.Preference)
}

func TestDNSServerHandleNS(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.50"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	dnsServer.handleNS(dns.Fqdn("example.com"), msg)

	require.Len(t, msg.Answer, 2)
	require.Contains(t, []string{msg.Answer[0].(*dns.NS).Ns, msg.Answer[1].(*dns.NS).Ns}, "ns1.example.com.")
	require.Contains(t, []string{msg.Answer[0].(*dns.NS).Ns, msg.Answer[1].(*dns.NS).Ns}, "ns2.example.com.")
}

func TestDNSServerHandleSOA(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.50"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	dnsServer.handleSOA(dns.Fqdn("example.com"), msg)

	require.Len(t, msg.Answer, 1)
	record, ok := msg.Answer[0].(*dns.SOA)
	require.True(t, ok)
	require.Equal(t, "ns1.example.com.", record.Ns)
	require.Equal(t, acme.CertificateAuthority, record.Mbox)
}

func TestDNSServerHandleTXT(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.50"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)
	dnsServer.TxtRecord = "verification-string"

	msg := new(dns.Msg)
	dnsServer.handleTXT(dns.Fqdn("example.com"), msg)

	require.Len(t, msg.Answer, 1)
	record, ok := msg.Answer[0].(*dns.TXT)
	require.True(t, ok)
	require.Equal(t, []string{"verification-string"}, record.Txt)
}

func TestDNSServerMultipleIPv4Addresses(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1", "198.51.100.1", "203.0.113.1"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	dnsServer.handleACNAMEANY(dns.Fqdn("multi.example.com"), msg)

	require.Len(t, msg.Answer, 3)
	require.True(t, hasRecord(msg.Answer, dns.TypeA, "192.0.2.1"))
	require.True(t, hasRecord(msg.Answer, dns.TypeA, "198.51.100.1"))
	require.True(t, hasRecord(msg.Answer, dns.TypeA, "203.0.113.1"))
}

func TestDNSServerMixedIPv4AndIPv6(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1", "2001:db8::1", "198.51.100.1", "2001:db8::2"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	dnsServer.handleACNAMEANY(dns.Fqdn("mixed.example.com"), msg)

	require.Len(t, msg.Answer, 4)
	require.True(t, hasRecord(msg.Answer, dns.TypeA, "192.0.2.1"))
	require.True(t, hasRecord(msg.Answer, dns.TypeA, "198.51.100.1"))
	require.True(t, hasRecord(msg.Answer, dns.TypeAAAA, "2001:db8::1"))
	require.True(t, hasRecord(msg.Answer, dns.TypeAAAA, "2001:db8::2"))
}

func hasRecord(rrs []dns.RR, rrtype uint16, expectedValue string) bool {
	for _, rr := range rrs {
		switch rec := rr.(type) {
		case *dns.A:
			if rrtype == dns.TypeA && (expectedValue == "" || rec.A.String() == expectedValue) {
				return true
			}
		case *dns.AAAA:
			if rrtype == dns.TypeAAAA && (expectedValue == "" || rec.AAAA.String() == expectedValue) {
				return true
			}
		}
	}
	return false
}

func newTestOptions(ips []string, listenIP string) *Options {
	parsed := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			parsed = append(parsed, parsedIP)
		}
	}

	return &Options{
		Domains:     []string{"example.com"},
		IPAddresses: parsed,
		ListenIP:    listenIP,
	}
}

func TestDNSServerRefusesOutOfZoneQueries(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	req := new(dns.Msg)
	req.SetQuestion("anything.notours.org.", dns.TypeA)

	rec := &testResponseWriter{}
	dnsServer.ServeDNS(rec, req)

	require.NotNil(t, rec.msg, "expected response message")
	require.Equal(t, dns.RcodeRefused, rec.msg.Rcode, "out-of-zone queries must be refused")

	for _, name := range []string{"fooexample.com.", "_acme-challenge.notours.org."} {
		req = new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)
		rec = &testResponseWriter{}
		dnsServer.ServeDNS(rec, req)
		require.NotNil(t, rec.msg)
		require.Equal(t, dns.RcodeRefused, rec.msg.Rcode, name)
	}

	mixed := new(dns.Msg)
	mixed.SetQuestion("a.example.com.", dns.TypeA)
	mixed.Question = append(mixed.Question, dns.Question{Name: "fooexample.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	rec = &testResponseWriter{}
	dnsServer.ServeDNS(rec, mixed)
	require.Equal(t, dns.RcodeRefused, rec.msg.Rcode, "one out-of-zone question refuses the message")

	require.True(t, dnsServer.isConfiguredDomain("example.com."))
	require.True(t, dnsServer.isConfiguredDomain("a.example.com."))
	require.False(t, dnsServer.isConfiguredDomain("fooexample.com."))
}

func TestDNSServerToQTypeComprehensive(t *testing.T) {
	testCases := []struct {
		qtype    uint16
		expected string
	}{
		{dns.TypeA, "A"},
		{dns.TypeNS, "NS"},
		{dns.TypeCNAME, "CNAME"},
		{dns.TypeSOA, "SOA"},
		{dns.TypePTR, "PTR"},
		{dns.TypeMX, "MX"},
		{dns.TypeTXT, "TXT"},
		{dns.TypeAAAA, "AAAA"},
		{65, "HTTPS"},
		{dns.TypeCAA, "CAA"},
		{dns.TypeSRV, "SRV"},
		{dns.TypeANY, "ANY"},
		{9999, "TYPE9999"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, toQType(tc.qtype))
	}
}

type testResponseWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (w *testResponseWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m
	return nil
}

func (w *testResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53535}
}

func TestDNSServerAAAAQueryIPv4OnlyReturnsNODATA(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.10"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	msg.Question = []dns.Question{{Name: "sub.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}
	rec := &testResponseWriter{}
	dnsServer.ServeDNS(rec, msg)

	require.Equal(t, dns.RcodeSuccess, rec.msg.Rcode)
	require.Empty(t, rec.msg.Answer, "expected empty answer section for AAAA query when only IPv4 configured")
	require.Len(t, rec.msg.Ns, 1, "expected SOA record in authority section")
	soa, ok := rec.msg.Ns[0].(*dns.SOA)
	require.True(t, ok, "expected SOA record type")
	require.Equal(t, "example.com.", soa.Hdr.Name, "SOA record owner should be zone apex")
}

func TestDNSServerNSAuthorityOwnedByApex(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.10"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := new(dns.Msg)
	msg.Question = []dns.Question{{Name: "deep.sub.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	rec := &testResponseWriter{}
	dnsServer.ServeDNS(rec, msg)

	require.Equal(t, dns.RcodeSuccess, rec.msg.Rcode)
	require.Len(t, rec.msg.Answer, 1)
	require.NotEmpty(t, rec.msg.Ns, "expected NS records in authority section")
	for _, rr := range rec.msg.Ns {
		ns, ok := rr.(*dns.NS)
		require.True(t, ok, "expected NS record")
		require.Equal(t, "example.com.", ns.Hdr.Name, "NS record must be owned by zone apex, not queried name")
	}
}

func TestDNSServerDualStackFiltersQuestionType(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.10", "2001:db8::1"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	// A query should return only A
	msgA := new(dns.Msg)
	msgA.Question = []dns.Question{{Name: "sub.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	recA := &testResponseWriter{}
	dnsServer.ServeDNS(recA, msgA)
	require.True(t, hasRecord(recA.msg.Answer, dns.TypeA, "192.0.2.10"))
	require.False(t, hasRecord(recA.msg.Answer, dns.TypeAAAA, "2001:db8::1"))

	// AAAA query should return only AAAA
	msgAAAA := new(dns.Msg)
	msgAAAA.Question = []dns.Question{{Name: "sub.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}
	recAAAA := &testResponseWriter{}
	dnsServer.ServeDNS(recAAAA, msgAAAA)
	require.False(t, hasRecord(recAAAA.msg.Answer, dns.TypeA, "192.0.2.10"))
	require.True(t, hasRecord(recAAAA.msg.Answer, dns.TypeAAAA, "2001:db8::1"))

	// ANY query should return both A and AAAA
	msgANY := new(dns.Msg)
	msgANY.Question = []dns.Question{{Name: "sub.example.com.", Qtype: dns.TypeANY, Qclass: dns.ClassINET}}
	recANY := &testResponseWriter{}
	dnsServer.ServeDNS(recANY, msgANY)
	require.True(t, hasRecord(recANY.msg.Answer, dns.TypeA, "192.0.2.10"))
	require.True(t, hasRecord(recANY.msg.Answer, dns.TypeAAAA, "2001:db8::1"))
}
