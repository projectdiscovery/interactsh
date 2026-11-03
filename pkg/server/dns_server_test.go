package server

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	"github.com/stretchr/testify/require"
)

func TestDNSServerReturnsAAAARecords(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1", "2001:db8::1"}, "127.0.0.1")
	dnsServer := NewDNSServer("udp", opts)

	msg := queryACNAMEANY(dnsServer, "test.example.com", dns.TypeANY)

	require.True(t, hasRecord(msg.Answer, dns.TypeA, "192.0.2.1"), "expected A record")
	require.True(t, hasRecord(msg.Answer, dns.TypeAAAA, "2001:db8::1"), "expected AAAA record")
	require.True(t, hasRecord(msg.Extra, dns.TypeAAAA, "2001:db8::1"), "expected AAAA glue record")
}

func TestDNSServerIPv6OnlyResponses(t *testing.T) {
	opts := newTestOptions([]string{"2001:db8::5"}, "::1")
	dnsServer := NewDNSServer("udp", opts)

	msg := queryACNAMEANY(dnsServer, "ipv6.example.com", dns.TypeAAAA)

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

	msg := queryACNAMEANY(dnsServer, "mixed.example.com", dns.TypeANY)

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

func TestDNSServerAnswersMatchQuestionType(t *testing.T) {
	dualStack := []string{"192.0.2.1", "2001:db8::1"}
	tests := []struct {
		name     string
		ips      []string
		qtype    uint16
		wantA    bool
		wantAAAA bool
	}{
		{"A on dual stack", dualStack, dns.TypeA, true, false},
		{"AAAA on dual stack", dualStack, dns.TypeAAAA, false, true},
		{"ANY on dual stack", dualStack, dns.TypeANY, true, true},
		{"AAAA on IPv4 only", []string{"192.0.2.1"}, dns.TypeAAAA, false, false},
		{"A on IPv6 only", []string{"2001:db8::1"}, dns.TypeA, false, false},
		{"CNAME", dualStack, dns.TypeCNAME, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := queryACNAMEANY(NewDNSServer("udp", newTestOptions(tt.ips, "127.0.0.1")), "x.example.com", tt.qtype)

			require.Equal(t, tt.wantA, hasRecord(msg.Answer, dns.TypeA, ""))
			require.Equal(t, tt.wantAAAA, hasRecord(msg.Answer, dns.TypeAAAA, ""))
		})
	}
}

func TestDNSServerNoDataReturnsApexSOA(t *testing.T) {
	dnsServer := NewDNSServer("udp", newTestOptions([]string{"192.0.2.1"}, "127.0.0.1"))

	msg := queryACNAMEANY(dnsServer, "x.example.com", dns.TypeAAAA)

	require.Empty(t, msg.Answer)
	require.Empty(t, msg.Extra)
	require.Len(t, msg.Ns, 1)
	soa, ok := msg.Ns[0].(*dns.SOA)
	require.True(t, ok, "expected SOA in authority")
	require.Equal(t, "example.com.", soa.Hdr.Name)
	require.Equal(t, "ns1.example.com.", soa.Ns)
	require.NotZero(t, soa.Hdr.Ttl, "zero TTL defeats negative caching")
}

func TestDNSServerAuthorityOwnedByApex(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1"}, "127.0.0.1")
	opts.Domains = []string{"example.com", "example.org"}
	dnsServer := NewDNSServer("udp", opts)

	for name, apex := range map[string]string{"a.b.example.com": "example.com.", "x.example.org": "example.org."} {
		msg := queryACNAMEANY(dnsServer, name, dns.TypeA)

		require.Len(t, msg.Ns, 2)
		for _, rr := range msg.Ns {
			ns, ok := rr.(*dns.NS)
			require.True(t, ok)
			require.Equal(t, apex, ns.Hdr.Name)
			require.True(t, dns.IsSubDomain(apex, ns.Ns), "nameserver %s not under %s", ns.Ns, apex)
		}
	}
}

func TestDNSServerMXNSSOAPointToQueriedDomain(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1"}, "127.0.0.1")
	opts.Domains = []string{"example.com", "example.org", "sub.example.com"}
	dnsServer := NewDNSServer("udp", opts)

	tests := []struct {
		qname string
		apex  string
	}{
		{"x.example.com", "example.com."},
		{"x.example.org", "example.org."},
		{"a.b.example.org", "example.org."},
		{"ExAmPlE.oRg", "example.org."}, // some resolvers (e.g. Google Public DNS) randomise query case
		{"x.sub.example.com", "sub.example.com."},
	}
	for _, tt := range tests {
		t.Run(tt.qname, func(t *testing.T) {
			zone := dns.Fqdn(tt.qname)
			msg := new(dns.Msg)
			dnsServer.handleMX(zone, msg)
			dnsServer.handleNS(zone, msg)
			dnsServer.handleSOA(zone, msg)

			var hosts []string
			for _, rr := range msg.Answer {
				switch rr := rr.(type) {
				case *dns.MX:
					hosts = append(hosts, rr.Mx)
				case *dns.NS:
					hosts = append(hosts, rr.Ns)
				case *dns.SOA:
					hosts = append(hosts, rr.Ns)
				}
			}
			require.Equal(t, []string{"mail." + tt.apex, "ns1." + tt.apex, "ns2." + tt.apex, "ns1." + tt.apex}, hosts)
		})
	}
}

func TestDNSServerNoDataForUnservedTypes(t *testing.T) {
	opts := newTestOptions([]string{"192.0.2.1"}, "127.0.0.1")
	opts.Domains = []string{"example.com", "example.org"}
	opts.DnsPort = freeUDPPort(t)
	// ServeDNS records interactions, so it needs storage and id lengths
	opts.Storage = newTestStorage(t)
	opts.CorrelationIdLength = 20
	opts.CorrelationIdNonceLength = 13
	opts.Stats = &Metrics{}
	startTestDNSServer(t, opts)

	tests := []struct {
		qname string
		qtype uint16
		apex  string
	}{
		{"x.example.com", dns.TypeHTTPS, "example.com."},
		{"x.example.com", dns.TypeSVCB, "example.com."},
		{"x.example.com", dns.TypeCAA, "example.com."},
		{"x.example.com", dns.TypeSRV, "example.com."},
		{"a.b.example.org", dns.TypeHTTPS, "example.org."},
	}
	for _, tt := range tests {
		t.Run(tt.qname+" "+dns.TypeToString[tt.qtype], func(t *testing.T) {
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(tt.qname), tt.qtype)
			client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
			resp, _, err := client.Exchange(msg, formatAddress(opts.ListenIP, opts.DnsPort))
			require.NoError(t, err)

			require.Equal(t, dns.RcodeSuccess, resp.Rcode)
			require.True(t, resp.Authoritative)
			require.Empty(t, resp.Answer)
			require.Len(t, resp.Ns, 1)
			soa, ok := resp.Ns[0].(*dns.SOA)
			require.True(t, ok, "expected SOA in authority")
			require.Equal(t, tt.apex, soa.Hdr.Name)
			require.Equal(t, "ns1."+tt.apex, soa.Ns)
			require.NotZero(t, soa.Minttl, "zero MINIMUM defeats negative caching")
		})
	}
}

func queryACNAMEANY(dnsServer *DNSServer, name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	dnsServer.handleACNAMEANY(dns.Fqdn(name), msg)
	return msg
}
