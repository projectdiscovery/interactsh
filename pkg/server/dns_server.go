package server

import (
	"bytes"
	"net"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
)

// DNSServer is a DNS server instance that listens on port 53.
type DNSServer struct {
	options    *Options
	mxDomain   string
	ns1Domain  string
	ns2Domain  string
	dotDomain  string
	ipAddress  net.IP
	timeToLive uint32
	server     *dns.Server
}

// NewDNSServer returns a new DNS server.
func NewDNSServer(options *Options) (*DNSServer, error) {
	options.Domain = dns.Fqdn(options.Domain)
	server := &DNSServer{
		options:    options,
		ipAddress:  net.ParseIP(options.IPAddress),
		mxDomain:   "mail." + options.Domain,
		ns1Domain:  "ns1." + options.Domain,
		ns2Domain:  "ns2." + options.Domain,
		dotDomain:  "." + options.Domain,
		timeToLive: 3600,
	}

	server.server = &dns.Server{
		Addr:    "0.0.0.0:53",
		Net:     "udp",
		Handler: server,
	}
	return server, nil
}

// ListenAndServe listens on dns ports for the server.
func (h *DNSServer) ListenAndServe() {
	if err := h.server.ListenAndServe(); err != nil {
		gologger.Error().Msgf("Could not serve dns on port 53: %s\n", err)
	}
}

// ServeDNS is the default handler for DNS queries.
func (h *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	// bail early for no queries.
	if len(r.Question) == 0 {
		return
	}
	gologger.Debug().Msgf("New DNS request: %s\n", r.String())
	domain := m.Question[0].Name

	var uniqueID string
	if r.Question[0].Qtype == dns.TypeA || r.Question[0].Qtype == dns.TypeANY {
		nsHeader := dns.RR_Header{Name: domain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: h.timeToLive}
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: h.ipAddress})
		m.Ns = append(m.Ns, &dns.NS{Hdr: nsHeader, Ns: h.ns1Domain})
		m.Ns = append(m.Ns, &dns.NS{Hdr: nsHeader, Ns: h.ns2Domain})
		m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: h.ns1Domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: h.ipAddress})
		m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: h.ns2Domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: h.ipAddress})
	}
	if r.Question[0].Qtype == dns.TypeSOA {
		nsHdr := dns.RR_Header{Name: domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: h.timeToLive}
		m.Answer = append(m.Answer, &dns.SOA{Hdr: nsHdr, Ns: h.ns1Domain, Mbox: h.options.Hostmaster})
	}
	if r.Question[0].Qtype == dns.TypeMX {
		nsHdr := dns.RR_Header{Name: domain, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: h.timeToLive}
		m.Answer = append(m.Answer, &dns.MX{Hdr: nsHdr, Mx: h.mxDomain, Preference: 1})
	}
	if strings.HasSuffix(domain, h.dotDomain) {
		parts := strings.Split(domain, ".")
		for _, part := range parts {
			if len(part) == 33 {
				uniqueID = part
			}
		}
	}
	if uniqueID != "" {
		correlationID := uniqueID[:20]
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		interaction := &Interaction{
			Protocol:      "dns",
			UniqueID:      uniqueID,
			QType:         toQType(r.Question[0].Qtype),
			RawRequest:    r.String(),
			RawResponse:   m.String(),
			RemoteAddress: host,
		}
		buffer := &bytes.Buffer{}
		if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
			gologger.Warning().Msgf("Could not encode dns interaction: %s\n", err)
		} else {
			gologger.Debug().Msgf("DNS Interaction: \n%s\n", string(buffer.Bytes()))
			if err := h.options.Storage.AddInteraction(correlationID, buffer.Bytes()); err != nil {
				gologger.Warning().Msgf("Could not store dns interaction: %s\n", err)
			}
		}
	}
	if err := w.WriteMsg(m); err != nil {
		gologger.Warning().Msgf("Could not write DNS response: %s\n", err)
	}
}

func toQType(ttype uint16) (rtype string) {
	switch ttype {
	case dns.TypeA:
		rtype = "A"
	case dns.TypeNS:
		rtype = "NS"
	case dns.TypeCNAME:
		rtype = "CNAME"
	case dns.TypeSOA:
		rtype = "SOA"
	case dns.TypePTR:
		rtype = "PTR"
	case dns.TypeMX:
		rtype = "MX"
	case dns.TypeTXT:
		rtype = "TXT"
	case dns.TypeAAAA:
		rtype = "AAAA"
	}
	return
}
