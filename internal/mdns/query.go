package mdns

import (
	"github.com/miekg/dns"
)

const (
	// DefaultServiceQuery is the PTR query name used to enumerate all mDNS
	// services on a host (DNS-SD service type enumeration).
	DefaultServiceQuery = "_services._dns-sd._udp.local."

	// MulticastAddr is the standard mDNS IPv4 multicast address.
	MulticastAddr = "224.0.0.251:5353"

	// DefaultPort is the standard mDNS port.
	DefaultPort = 5353
)

// Common mDNS service types to probe when service enumeration fails.
var CommonServiceTypes = []string{
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_ssh._tcp.local.",
	"_sftp-ssh._tcp.local.",
	"_smb._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_nfs._tcp.local.",
	"_ftp._tcp.local.",
	"_telnet._tcp.local.",
	"_rdp._tcp.local.",
	"_vnc._tcp.local.",
	"_printer._tcp.local.",
	"_ipp._tcp.local.",
	"_pdl-datastream._tcp.local.",
	"_scanner._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_homekit._tcp.local.",
	"_hap._tcp.local.",
	"_companion-link._tcp.local.",
	"_googlecast._tcp.local.",
	"_spotify-connect._tcp.local.",
	"_workstation._tcp.local.",
	"_udisks-ssh._tcp.local.",
	"_device-info._tcp.local.",
	"_touch-able._tcp.local.",
}

// BuildServiceEnumQuery builds a PTR query for DNS-SD service enumeration.
// This asks the target: "list all service types you advertise".
func BuildServiceEnumQuery() *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(DefaultServiceQuery, dns.TypePTR)
	msg.RecursionDesired = false
	msg.Question[0].Qclass |= 0x8000 // Unicast-response bit (mDNS)
	return msg
}

// BuildQuery constructs an mDNS query for the given name and query type.
// name should be a fully-qualified mDNS name (ends in .local).
func BuildQuery(name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = false
	msg.Question[0].Qclass |= 0x8000 // Unicast-response bit
	return msg
}

// BuildQueryNoUnicast constructs an mDNS query without the unicast-response bit.
// Use for multicast queries where we want all responders.
func BuildQueryNoUnicast(name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = false
	return msg
}

// BuildAnyQuery sends an ANY query to pull all records for a name.
func BuildAnyQuery(name string) *dns.Msg {
	return BuildQuery(name, dns.TypeANY)
}
