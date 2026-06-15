package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cyb/mdns-scanner/internal/mdns"
	"github.com/cyb/mdns-scanner/internal/output"
	"github.com/miekg/dns"
)

func main() {
	// Build synthetic mDNS response matching the example spec:
	//   - workstation, http, smb, qdiscover, device-info, afpovertcp
	//   - Full TXT records with Name, IPv4, IPv6, Hostname, TTL, model, etc.
	//   - PTR records for the service type list

	msgs := []*dns.Msg{buildSyntheticResponse()}

	// Parse all responses
	var allServices []mdns.ServiceInfo
	var allPTRs []string
	var hostname string
	var hinfo *mdns.HInfo

	for _, msg := range msgs {
		svcs, ptrs := mdns.DeepParse(msg)
		allServices = append(allServices, svcs...)
		allPTRs = append(allPTRs, ptrs...)
		if hostname == "" {
			hostname = mdns.ExtractHostname(msg)
		}
		if hinfo == nil {
			hinfo = mdns.ExtractHInfo(msg)
		}
	}

	asset := mdns.Asset{
		IP:       "10.0.0.10",
		Port:     5353,
		Hostname: "slw-nas.local",
		Services: allServices,
		PTRList:  allPTRs,
		HInfo:    hinfo,
		Elapsed:  15 * time.Millisecond,
	}

	fmt.Println("=== TABLE OUTPUT ===")
	output.Write([]mdns.Asset{asset}, output.FormatTable)

	fmt.Println()
	fmt.Println("=== JSON OUTPUT ===")
	output.Write([]mdns.Asset{asset}, output.FormatJSON)

	os.Exit(0)
}

func buildSyntheticResponse() *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Authoritative = true

	ip := "10.0.0.10"
	ipv6 := "fe80::265e:beff:fe69:a313"
	host := "slw-nas.local"
	mac := "24:5e:be:69:a3:13"

	// ---- PTR records ----
	ptrTargets := []string{
		"_workstation._tcp.local",
		"_http._tcp.local",
		"_smb._tcp.local",
		"_qdiscover._tcp.local",
		"_device-info._tcp.local",
		"_afpovertcp._tcp.local",
	}
	for _, pt := range ptrTargets {
		rr, _ := dns.NewRR(fmt.Sprintf("_services._dns-sd._udp.local. 10 IN PTR %s", pt))
		msg.Answer = append(msg.Answer, rr)
	}

	// ---- Workstation (9/tcp) ----
	addServiceBlock(msg, "slw-nas._workstation._tcp.local.", 9, host, ip, ipv6, host, 10,
		map[string]string{
			"Name": fmt.Sprintf("%s [%s]", "slw-nas", mac),
			"MAC":  mac,
		})

	// ---- HTTP (5000/tcp) ----
	addServiceBlock(msg, "slw-nas._http._tcp.local.", 5000, host, ip, ipv6, host, 10,
		map[string]string{
			"Name": "slw-nas",
			"path": "/",
		})

	// ---- SMB (445/tcp) ----
	addServiceBlock(msg, "slw-nas._smb._tcp.local.", 445, host, ip, ipv6, host, 10,
		map[string]string{
			"Name": "slw-nas",
		})

	// ---- QDiscover (5000/tcp) ----
	addServiceBlock(msg, "slw-nas._qdiscover._tcp.local.", 5000, host, ip, ipv6, host, 10,
		map[string]string{
			"Name":        "slw-nas",
			"accessType":  "https",
			"accessPort":  "86",
			"model":       "TS-X64",
			"displayModel": "TS-464C",
			"fwVer":       "5.2.9",
			"fwBuildNum":  "20260214",
		})

	// ---- device-info (portless) ----
	addServiceBlockNoSRV(msg, "slw-nas\\ (AFP)._device-info._tcp.local.", host, ip, ipv6, host, 10,
		map[string]string{
			"Name":  "slw-nas(AFP)",
			"model": "Xserve",
		})

	// ---- AFP over TCP (548/tcp) ----
	addServiceBlock(msg, "slw-nas\\ (AFP)._afpovertcp._tcp.local.", 548, host, ip, ipv6, host, 10,
		map[string]string{
			"Name": "slw-nas(AFP)",
		})

	return msg
}

func addServiceBlock(msg *dns.Msg, ownerName string, port int, target, ipv4, ipv6, hostname string, ttl uint32, extraTXT map[string]string) {
	// SRV
	srvRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN SRV 0 0 %d %s", ownerName, ttl, port, target))
	msg.Answer = append(msg.Answer, srvRR)

	// TXT
	txtPairs := make([]string, 0)
	txtPairs = append(txtPairs, fmt.Sprintf("IPv4=%s", ipv4))
	txtPairs = append(txtPairs, fmt.Sprintf("IPv6=%s", ipv6))
	txtPairs = append(txtPairs, fmt.Sprintf("Hostname=%s", hostname))
	txtPairs = append(txtPairs, fmt.Sprintf("TTL=%d", ttl))
	for k, v := range extraTXT {
		txtPairs = append(txtPairs, fmt.Sprintf("%s=%s", k, v))
	}
	txtStr := ""
	for i, p := range txtPairs {
		if i > 0 {
			txtStr += " "
		}
		txtStr += fmt.Sprintf("%q", p)
	}
	txtRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", ownerName, ttl, txtStr))
	msg.Answer = append(msg.Answer, txtRR)

	// A record (for the target host)
	aAlreadyExists := false
	for _, rr := range msg.Extra {
		if a, ok := rr.(*dns.A); ok && a.Hdr.Name == target {
			aAlreadyExists = true
			break
		}
	}
	if !aAlreadyExists {
		aRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN A %s", target, ttl, ipv4))
		msg.Extra = append(msg.Extra, aRR)
	}

	// AAAA record
	aaaaRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", target, ttl, ipv6))
	msg.Extra = append(msg.Extra, aaaaRR)
}

func addServiceBlockNoSRV(msg *dns.Msg, ownerName, target, ipv4, ipv6, hostname string, ttl uint32, extraTXT map[string]string) {
	// No SRV — just TXT + A/AAAA (portless service like device-info)
	txtPairs := []string{
		fmt.Sprintf("IPv4=%s", ipv4),
		fmt.Sprintf("IPv6=%s", ipv6),
		fmt.Sprintf("Hostname=%s", hostname),
		fmt.Sprintf("TTL=%d", ttl),
	}
	for k, v := range extraTXT {
		txtPairs = append(txtPairs, fmt.Sprintf("%s=%s", k, v))
	}
	txtStr := ""
	for i, p := range txtPairs {
		if i > 0 {
			txtStr += " "
		}
		txtStr += fmt.Sprintf("%q", p)
	}
	txtRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", ownerName, ttl, txtStr))
	msg.Answer = append(msg.Answer, txtRR)
}
