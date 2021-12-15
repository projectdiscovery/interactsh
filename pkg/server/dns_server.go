package server

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

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
	TxtRecord  string // used for ACME verification
}

// NewDNSServer returns a new DNS server.
func NewDNSServer(options *Options) (*DNSServer, error) {
	dotdomain := dns.Fqdn(options.Domain)
	server := &DNSServer{
		options:    options,
		ipAddress:  net.ParseIP(options.IPAddress),
		mxDomain:   "mail." + dotdomain,
		ns1Domain:  "ns1." + dotdomain,
		ns2Domain:  "ns2." + dotdomain,
		dotDomain:  "." + dotdomain,
		timeToLive: 3600,
	}
	server.server = &dns.Server{
		Addr:    options.ListenIP + fmt.Sprintf(":%d", options.DomainPort),
		Net:     "udp",
		Handler: server,
	}
	return server, nil
}

// ListenAndServe listens on dns ports for the server.
func (h *DNSServer) ListenAndServe() {
	if err := h.server.ListenAndServe(); err != nil {
		gologger.Error().Msgf("Could not serve dns on port %d: %s\n", h.options.DomainPort, err)
	}
}

// ServeDNS is the default handler for DNS queries.
func (h *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// bail early for no queries.
	if len(r.Question) == 0 {
		return
	}
	requestMsg := r.String()

	gologger.Debug().Msgf("New DNS request: %s\n", requestMsg)
	domain := m.Question[0].Name

	var uniqueID, fullID string

	// Clould providers
	if r.Question[0].Qtype == dns.TypeTXT {
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{h.TxtRecord}})
	} else if r.Question[0].Qtype == dns.TypeA || r.Question[0].Qtype == dns.TypeANY {
		nsHeader := dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: h.timeToLive}

		handleClould := func(ipAddress net.IP) {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: ipAddress})

			m.Ns = append(m.Ns, &dns.NS{Hdr: nsHeader, Ns: h.ns1Domain})
			m.Ns = append(m.Ns, &dns.NS{Hdr: nsHeader, Ns: h.ns2Domain})
			m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: h.ns1Domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: h.ipAddress})
			m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: h.ns2Domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: h.ipAddress})
		}

		handleAppWithCname := func(cname string, ips ...net.IP) {
			fqdnCname := dns.Fqdn(cname)
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: h.timeToLive}, Target: fqdnCname})
			for _, ip := range ips {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: fqdnCname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: ip})
			}

			m.Ns = append(m.Ns, &dns.NS{Hdr: nsHeader, Ns: h.ns1Domain})
			m.Ns = append(m.Ns, &dns.NS{Hdr: nsHeader, Ns: h.ns2Domain})
			m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: h.ns1Domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: h.ipAddress})
			m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: h.ns2Domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: h.ipAddress})
		}

		// check for clould providers
		switch {
		case strings.EqualFold(domain, "aws"+h.dotDomain):
			handleClould(net.ParseIP("169.254.169.254"))
		case strings.EqualFold(domain, "alibaba"+h.dotDomain):
			handleClould(net.ParseIP("100.100.100.200"))
		case strings.EqualFold(domain, "app"+h.dotDomain):
			handleAppWithCname("projectdiscovery.github.io", net.ParseIP("185.199.108.153"), net.ParseIP("185.199.110.153"), net.ParseIP("185.199.111.153"), net.ParseIP("185.199.108.153"))
		default:
			handleClould(h.ipAddress)
		}

	} else if r.Question[0].Qtype == dns.TypeSOA {
		nsHdr := dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: h.timeToLive}
		m.Answer = append(m.Answer, &dns.SOA{Hdr: nsHdr, Ns: h.ns1Domain, Mbox: h.options.Hostmaster})
	} else if r.Question[0].Qtype == dns.TypeMX {
		nsHdr := dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: h.timeToLive}
		m.Answer = append(m.Answer, &dns.MX{Hdr: nsHdr, Mx: h.mxDomain, Preference: 1})
	} else if r.Question[0].Qtype == dns.TypeNS {
		nsHeader := dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: h.timeToLive}
		m.Ns = append(m.Ns, &dns.NS{Hdr: nsHeader, Ns: h.ns1Domain})
		m.Ns = append(m.Ns, &dns.NS{Hdr: nsHeader, Ns: h.ns2Domain})
	}
	responseMsg := m.String()

	// if root-tld is enabled stores any interaction towards the main domain
	if h.options.RootTLD && strings.HasSuffix(domain, h.dotDomain) {
		correlationID := h.options.Domain
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		interaction := &Interaction{
			Protocol:      "dns",
			UniqueID:      domain,
			FullId:        domain,
			QType:         toQType(r.Question[0].Qtype),
			RawRequest:    requestMsg,
			RawResponse:   responseMsg,
			RemoteAddress: host,
			Timestamp:     time.Now(),
		}
		buffer := &bytes.Buffer{}
		if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
			gologger.Warning().Msgf("Could not encode root tld dns interaction: %s\n", err)
		} else {
			gologger.Debug().Msgf("Root TLD DNS Interaction: \n%s\n", buffer.String())
			if err := h.options.Storage.AddInteractionWithId(correlationID, buffer.Bytes()); err != nil {
				gologger.Warning().Msgf("Could not store dns interaction: %s\n", err)
			}
		}
	}

	if strings.HasSuffix(domain, h.dotDomain) {
		parts := strings.Split(domain, ".")
		for i, part := range parts {
			if len(part) == 33 {
				uniqueID = part
				fullID = part
				if i+1 <= len(parts) {
					fullID = strings.Join(parts[:i+1], ".")
				}
			}
		}
	}
	if uniqueID != "" {
		correlationID := uniqueID[:20]
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		interaction := &Interaction{
			Protocol:      "dns",
			UniqueID:      uniqueID,
			FullId:        fullID,
			QType:         toQType(r.Question[0].Qtype),
			RawRequest:    requestMsg,
			RawResponse:   responseMsg,
			RemoteAddress: host,
			Timestamp:     time.Now(),
		}
		buffer := &bytes.Buffer{}
		if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
			gologger.Warning().Msgf("Could not encode dns interaction: %s\n", err)
		} else {
			gologger.Debug().Msgf("DNS Interaction: \n%s\n", buffer.String())
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
