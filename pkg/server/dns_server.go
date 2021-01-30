package server

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
)

// DNSServer is a DNS server instance that listens on port 53.
type DNSServer struct {
	options    *Options
	ns1Domain  string
	ns2Domain  string
	ipAddress  net.IP
	timeToLive time.Duration
	server     *dns.Server
}

// NewDNSServer returns a new DNS server.
func NewDNSServer(options *Options) (*DNSServer, error) {
	server := &DNSServer{
		options:    options,
		ipAddress:  net.ParseIP(options.IPAddress),
		ns1Domain:  "ns1." + options.Domain,
		ns2Domain:  "ns2." + options.Domain,
		timeToLive: 60 * time.Minute,
	}

	server.server = &dns.Server{
		Addr:    "0.0.0.0:25",
		Net:     "udp",
		Handler: dns.HandlerFunc(server.defaultHandler),
	}
	return server, nil
}

// ListenAndServe listens on dns ports for the server.
func (h *DNSServer) ListenAndServe() {
	go func() {
		if err := h.server.ListenAndServe(); err != nil {
			gologger.Error().Msgf("Could not serve smtp on port 25: %s\n", err)
		}
	}()
}

// defaultHandler is the default handler for DNS queries.
func (h *DNSServer) defaultHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	// bail early for no queries.
	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	if r.Question[0].Qtype == dns.TypeA || r.Question[0].Qtype == dns.TypeANY {
		m.Authoritative = true
		domain := m.Question[0].Name
		//	s.NewExfiltration(domain, w.RemoteAddr().String())

		aHeader := dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(h.timeToLive)}
		if strings.EqualFold(domain, h.options.Domain) {
			nsHeader := dns.RR_Header{Name: domain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: uint32(h.timeToLive)}
			m.Answer = append(m.Answer, &dns.A{Hdr: aHeader, A: h.ipAddress})
			m.Answer = append(m.Answer, &dns.NS{Hdr: nsHeader, Ns: h.ns1Domain})
			m.Answer = append(m.Answer, &dns.NS{Hdr: nsHeader, Ns: h.ns2Domain})
		} else if strings.EqualFold(domain, h.ns1Domain) || strings.EqualFold(domain, h.ns2Domain) {
			m.Answer = append(m.Answer, &dns.A{Hdr: aHeader, A: h.ipAddress})
		} else if strings.HasSuffix(domain, "."+h.options.Domain) {
			m.Answer = append(m.Answer, &dns.A{Hdr: aHeader, A: h.ipAddress})
		}
	}
	w.WriteMsg(m)
}
