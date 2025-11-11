package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/server/acme"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"gopkg.in/yaml.v3"
)

// DNSServer is a DNS server instance that listens on port 53.
type DNSServer struct {
	options       *Options
	mxDomains     map[string]string
	nsDomains     map[string][]string
	ipAddress     net.IP
	timeToLive    uint32
	server        *dns.Server
	customRecords *customDNSRecords
	TxtRecord     string // used for ACME verification
}

// NewDNSServer returns a new DNS server.
func NewDNSServer(network string, options *Options) *DNSServer {
	mxDomains := make(map[string]string)
	nsDomains := make(map[string][]string)

	for _, domain := range options.Domains {
		dotdomain := dns.Fqdn(domain)

		mxDomain := fmt.Sprintf("mail.%s", dotdomain)
		mxDomains[dotdomain] = mxDomain

		ns1Domain := fmt.Sprintf("ns1.%s", dotdomain)
		ns2Domain := fmt.Sprintf("ns2.%s", dotdomain)
		nsDomains[dotdomain] = []string{ns1Domain, ns2Domain}
	}

	server := &DNSServer{
		options:       options,
		ipAddress:     net.ParseIP(options.IPAddress),
		mxDomains:     mxDomains,
		nsDomains:     nsDomains,
		timeToLive:    3600,
		customRecords: newCustomDNSRecordsServer(options.CustomRecords, options.Domains),
	}
	server.server = &dns.Server{
		Addr:    options.ListenIP + fmt.Sprintf(":%d", options.DnsPort),
		Net:     network,
		Handler: server,
	}
	return server
}

// ListenAndServe listens on dns ports for the server.
func (h *DNSServer) ListenAndServe(dnsAlive chan bool) {
	dnsAlive <- true
	if err := h.server.ListenAndServe(); err != nil {
		gologger.Error().Msgf("Could not listen for %s DNS on %s (%s)\n", strings.ToUpper(h.server.Net), h.server.Addr, err)
		dnsAlive <- false
	}
}

// ServeDNS is the default handler for DNS queries.
func (h *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddUint64(&h.options.Stats.Dns, 1)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// bail early for no queries.
	if len(r.Question) == 0 {
		return
	}

	isDNSChallenge := false
	for _, question := range r.Question {
		domain := question.Name

		// Handle DNS server cases for ACME server
		if strings.HasPrefix(strings.ToLower(domain), acme.DNSChallengeString) {
			isDNSChallenge = true

			gologger.Debug().Msgf("Got acme dns request: \n%s\n", r.String())

			switch question.Qtype {
			case dns.TypeSOA:
				h.handleSOA(domain, m)
			case dns.TypeTXT:
				err := h.handleACMETXTChallenge(domain, m)
				if err != nil {
					fmt.Printf("handleACMETXTChallenge for zone %s err: %+v\n", domain, err)
					return
				}
			case dns.TypeNS:
				h.handleNS(domain, m)
			case dns.TypeA, dns.TypeAAAA:
				h.handleACNAMEANY(domain, m)
			}

			gologger.Debug().Msgf("Got acme dns response: \n%s\n", m.String())
		} else {
			switch question.Qtype {
			case dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeANY:
				h.handleACNAMEANY(domain, m)
			case dns.TypeMX:
				h.handleMX(domain, m)
			case dns.TypeNS:
				h.handleNS(domain, m)
			case dns.TypeSOA:
				h.handleSOA(domain, m)
			case dns.TypeTXT:
				h.handleTXT(domain, m)
			}
		}
	}
	if !isDNSChallenge {
		// Write interaction for first question and dns request
		h.handleInteraction(r.Question[0].Name, w, r, m)
	}

	if err := w.WriteMsg(m); err != nil {
		gologger.Warning().Msgf("Could not write DNS response: \n%s\n %s\n", m.String(), err)
	}
}

// handleACMETXTChallenge handles solving of ACME TXT challenge with the given provider
func (h *DNSServer) handleACMETXTChallenge(zone string, m *dns.Msg) error {
	records, err := h.options.ACMEStore.GetRecords(context.Background(), strings.ToLower(zone))
	if err != nil {
		return err
	}

	rrs := []dns.RR{}
	for _, record := range records {
		txtHdr := dns.RR_Header{Name: zone, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(record.TTL)}
		rrs = append(rrs, &dns.TXT{Hdr: txtHdr, Txt: []string{record.Value}})
	}
	m.Answer = append(m.Answer, rrs...)
	return nil
}

// handleACNAMEANY handles A, CNAME or ANY queries for DNS server
func (h *DNSServer) handleACNAMEANY(zone string, m *dns.Msg) {
	// Determine the query type from the question
	var qtype uint16 = dns.TypeA
	if len(m.Question) > 0 {
		qtype = m.Question[0].Qtype
	}

	// Check for custom records
	customRecords := h.customRecords.checkCustomResponse(zone, qtype)
	if len(customRecords) > 0 {
		for _, record := range customRecords {
			h.addCustomRecordToMessage(record, zone, m)
		}
		return
	}

	// No custom records, use default IP
	nsHeader := dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: h.timeToLive}
	h.resultFunction(nsHeader, zone, h.ipAddress, m)
}

func (h *DNSServer) resultFunction(nsHeader dns.RR_Header, zone string, ipAddress net.IP, m *dns.Msg) {
	m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: ipAddress})
	dotDomains := []string{zone, dns.Fqdn(h.options.Domains[0])}
	for _, dotDomain := range dotDomains {
		if nsDomains, ok := h.nsDomains[dotDomain]; ok {
			for _, nsDomain := range nsDomains {
				m.Ns = append(m.Ns, &dns.NS{Hdr: nsHeader, Ns: nsDomain})
				m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: nsDomain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.timeToLive}, A: h.ipAddress})
			}
			return
		}
	}
}

func (h *DNSServer) handleMX(zone string, m *dns.Msg) {
	// Check for custom MX records first
	customRecords := h.customRecords.checkCustomResponse(zone, dns.TypeMX)
	if len(customRecords) > 0 {
		for _, record := range customRecords {
			h.addCustomRecordToMessage(record, zone, m)
		}
		return
	}

	// Fall back to default MX records
	nsHdr := dns.RR_Header{Name: zone, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: h.timeToLive}
	dotDomains := []string{zone, dns.Fqdn(h.options.Domains[0])}
	for _, dotDomain := range dotDomains {
		if mxdomain, ok := h.mxDomains[dotDomain]; ok {
			m.Answer = append(m.Answer, &dns.MX{Hdr: nsHdr, Mx: mxdomain, Preference: 1})
			return
		}
	}
}

func (h *DNSServer) handleNS(zone string, m *dns.Msg) {
	// Check for custom NS records first
	customRecords := h.customRecords.checkCustomResponse(zone, dns.TypeNS)
	if len(customRecords) > 0 {
		for _, record := range customRecords {
			h.addCustomRecordToMessage(record, zone, m)
		}
		return
	}

	// Fall back to default NS records
	nsHeader := dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: h.timeToLive}
	dotDomains := []string{zone, dns.Fqdn(h.options.Domains[0])}
	for _, dotDomain := range dotDomains {
		if nsDomains, ok := h.nsDomains[dotDomain]; ok {
			for _, nsDomain := range nsDomains {
				m.Answer = append(m.Answer, &dns.NS{Hdr: nsHeader, Ns: nsDomain})
			}
			return
		}
	}
}

func (h *DNSServer) handleSOA(zone string, m *dns.Msg) {
	nsHdr := dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET}
	dotDomains := []string{zone, dns.Fqdn(h.options.Domains[0])}
	for _, dotDomain := range dotDomains {
		if nsDomains, ok := h.nsDomains[dotDomain]; ok {
			for _, nsDomain := range nsDomains {
				m.Answer = append(m.Answer, &dns.SOA{Hdr: nsHdr, Ns: nsDomain, Mbox: acme.CertificateAuthority, Serial: 1, Expire: 60, Minttl: 60})
				return
			}
		}
	}
}

func (h *DNSServer) handleTXT(zone string, m *dns.Msg) {
	// Check for custom TXT records first
	customRecords := h.customRecords.checkCustomResponse(zone, dns.TypeTXT)
	if len(customRecords) > 0 {
		for _, record := range customRecords {
			h.addCustomRecordToMessage(record, zone, m)
		}
		return
	}

	// Fall back to default TXT record
	m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{h.TxtRecord}})
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

// handleInteraction handles an interaction for the DNS server
func (h *DNSServer) handleInteraction(domain string, w dns.ResponseWriter, r *dns.Msg, m *dns.Msg) {
	var uniqueID, fullID string

	requestMsg := r.String()
	responseMsg := m.String()

	gologger.Debug().Msgf("New DNS request: %s\n", requestMsg)

	var foundDomain string
	for _, configuredDomain := range h.options.Domains {
		configuredDotDomain := dns.Fqdn(configuredDomain)
		if stringsutil.HasSuffixI(domain, configuredDotDomain) {
			foundDomain = configuredDomain
			break
		}
	}

	// if root-tld is enabled stores any interaction towards the main domain
	if h.options.RootTLD && foundDomain != "" {
		correlationID := foundDomain
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

		if nil != h.options.OnResult {
			h.options.OnResult(interaction)
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

	if foundDomain != "" {
		if h.options.ScanEverywhere {
			chunks := stringsutil.SplitAny(requestMsg, ".\n\t\"'")
			for _, chunk := range chunks {
				for part := range stringsutil.SlideWithLength(chunk, h.options.GetIdLength()) {
					normalizedPart := strings.ToLower(part)
					if h.options.isCorrelationID(normalizedPart) {
						uniqueID = normalizedPart
						fullID = part
					}
				}
			}
		} else {
			parts := strings.Split(domain, ".")
			for i, part := range parts {
				for partChunk := range stringsutil.SlideWithLength(part, h.options.GetIdLength()) {
					normalizedPartChunk := strings.ToLower(partChunk)
					if h.options.isCorrelationID(normalizedPartChunk) {
						fullID = part
						if i+1 <= len(parts) {
							fullID = strings.Join(parts[:i+1], ".")
						}
						uniqueID = normalizedPartChunk
					}
				}
			}
		}
	}

	if uniqueID != "" {
		correlationID := uniqueID[:h.options.CorrelationIdLength]
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
}

// CustomRecordConfig represents a custom DNS record configuration
type CustomRecordConfig struct {
	Type     string `yaml:"type"`
	Value    string `yaml:"value"`
	TTL      uint32 `yaml:"ttl,omitempty"`
	Priority uint16 `yaml:"priority,omitempty"` // for MX records
}

// DNSRecordsConfig represents the structured DNS records configuration (YAML format)
type DNSRecordsConfig map[string][]CustomRecordConfig

// customDNSRecords is a server for custom dns records
type customDNSRecords struct {
	records map[string][]CustomRecordConfig
	domains []string
}

// defaultCustomRecords is the list of default custom DNS records
var defaultCustomRecords = map[string]string{
	"aws":       "169.254.169.254",
	"alibaba":   "100.100.100.200",
	"localhost": "127.0.0.1",
	"oracle":    "192.0.0.192",
}

func newCustomDNSRecordsServer(input string, domains []string) *customDNSRecords {
	server := &customDNSRecords{
		records: make(map[string][]CustomRecordConfig),
		domains: domains,
	}
	// Add default records as A records
	for k, v := range defaultCustomRecords {
		server.records[k] = []CustomRecordConfig{
			{Type: "A", Value: v},
		}
	}
	if input != "" {
		if err := server.readRecordsFromFile(input); err != nil {
			gologger.Error().Msgf("Could not read custom DNS records: %s", err)
		}
	}
	return server
}

func (c *customDNSRecords) readRecordsFromFile(input string) error {
	// Read the entire file once
	data, err := os.ReadFile(input)
	if err != nil {
		return errors.Wrap(err, "could not read file")
	}

	// Try to parse as structured format first
	var structuredData DNSRecordsConfig
	if err := yaml.Unmarshal(data, &structuredData); err == nil && len(structuredData) > 0 {
		// Successfully parsed as structured format
		for subdomain, entries := range structuredData {
			subdomainLower := strings.ToLower(subdomain)
			for _, entry := range entries {
				if entry.Type == "" {
					return errors.New("record type is required")
				}
				if entry.Value == "" {
					return errors.New("record value is required")
				}

				// Normalize type to uppercase
				entry.Type = strings.ToUpper(entry.Type)
				c.records[subdomainLower] = append(c.records[subdomainLower], entry)
			}
		}
		return nil
	}

	// If structured format failed, try legacy format (backwards compatibility)
	var legacyData map[string]string
	if err := yaml.Unmarshal(data, &legacyData); err != nil {
		return errors.Wrap(err, "could not decode file as structured or legacy format")
	}

	// Convert legacy format to CustomRecordConfig (assume A records)
	for k, v := range legacyData {
		c.records[strings.ToLower(k)] = []CustomRecordConfig{
			{Type: "A", Value: v},
		}
	}
	return nil
}

// checkCustomResponse returns custom DNS records for the given zone and record type
func (c *customDNSRecords) checkCustomResponse(zone string, recordType uint16) []CustomRecordConfig {
	// Normalize zone (remove trailing dot if present)
	zone = strings.TrimSuffix(zone, ".")
	zoneLower := strings.ToLower(zone)

	// Try to find which base domain this zone belongs to and extract the subdomain
	var subdomain string
	for _, domain := range c.domains {
		domainLower := strings.ToLower(domain)
		// Check if zone ends with .domain or is exactly domain
		if zoneLower == domainLower {
			// It's the base domain itself, no custom subdomain
			continue
		}
		suffix := "." + domainLower
		if strings.HasSuffix(zoneLower, suffix) {
			// Extract the subdomain part (everything before .domain)
			subdomain = zoneLower[:len(zoneLower)-len(suffix)]
			break
		}
	}

	if subdomain == "" {
		return nil
	}

	configs, ok := c.records[subdomain]
	if !ok {
		return nil
	}

	// Filter by record type
	var filtered []CustomRecordConfig
	for _, config := range configs {
		// Match the requested type
		switch recordType {
		case dns.TypeA:
			if config.Type == "A" {
				filtered = append(filtered, config)
			}
		case dns.TypeAAAA:
			if config.Type == "AAAA" {
				filtered = append(filtered, config)
			}
		case dns.TypeCNAME:
			if config.Type == "CNAME" {
				filtered = append(filtered, config)
			}
		case dns.TypeMX:
			if config.Type == "MX" {
				filtered = append(filtered, config)
			}
		case dns.TypeTXT:
			if config.Type == "TXT" {
				filtered = append(filtered, config)
			}
		case dns.TypeNS:
			if config.Type == "NS" {
				filtered = append(filtered, config)
			}
		case dns.TypeANY:
			// Return all records for ANY query
			filtered = append(filtered, config)
		}
	}

	return filtered
}

// addCustomRecordToMessage adds a custom DNS record to the DNS message
func (h *DNSServer) addCustomRecordToMessage(record CustomRecordConfig, zone string, m *dns.Msg) error {
	// Determine TTL (use custom if set, otherwise use server default)
	ttl := h.timeToLive
	if record.TTL > 0 {
		ttl = record.TTL
	}

	// Create the appropriate DNS record based on type
	switch record.Type {
	case "A":
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.ParseIP(record.Value),
		})
	case "AAAA":
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: zone, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: net.ParseIP(record.Value),
		})
	case "CNAME":
		m.Answer = append(m.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: zone, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: dns.Fqdn(record.Value),
		})
	case "MX":
		priority := record.Priority
		if priority == 0 {
			priority = 10 // default priority if not specified
		}
		m.Answer = append(m.Answer, &dns.MX{
			Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
			Mx:         dns.Fqdn(record.Value),
			Preference: priority,
		})
	case "TXT":
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{record.Value},
		})
	case "NS":
		m.Answer = append(m.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
			Ns:  dns.Fqdn(record.Value),
		})
	default:
		return fmt.Errorf("unsupported record type: %s", record.Type)
	}

	return nil
}
