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
	dnsServer.customRecords.records["ipv6"] = "2001:db8::dead"

	msg := new(dns.Msg)
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
	dnsServer.customRecords.records["app"] = "198.51.100.5"

	msg := new(dns.Msg)
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
