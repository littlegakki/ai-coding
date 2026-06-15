package mdns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// ParseResponse parses a raw DNS wire-format response into a dns.Msg.
func ParseResponse(raw []byte) (*dns.Msg, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil {
		return nil, fmt.Errorf("unpack dns response: %w", err)
	}
	return msg, nil
}

// recordGroup bundles DNS records that share the same owner name.
type recordGroup struct {
	name  string
	srv   *dns.SRV
	txts  []*dns.TXT
	as    []*dns.A
	aaaas []*dns.AAAA
	ttl   uint32
}

// DeepParse extracts detailed service information from all DNS response sections.
// It groups records by owner name to correlate SRV/TXT/A/AAAA records belonging
// to the same service instance. Returns services and the global PTR list.
func DeepParse(msg *dns.Msg) ([]ServiceInfo, []string) {
	// Step 1: collect all RRs and build lookup maps
	allRRs := collectAllRRs(msg)

	// Maps for cross-referencing
	hostToA := make(map[string]string)    // hostname → IPv4
	hostToAAAA := make(map[string]string) // hostname → IPv6
	ptrList := make([]string, 0)          // global PTR targets

	// Step 2: first pass — collect A/AAAA by hostname and PTR targets
	for _, rr := range allRRs {
		name := strings.TrimSuffix(rr.Header().Name, ".")
		switch r := rr.(type) {
		case *dns.A:
			if _, exists := hostToA[name]; !exists {
				hostToA[name] = r.A.String()
			}
		case *dns.AAAA:
			// Prefer link-local or global over others
			if _, exists := hostToAAAA[name]; !exists || isPreferredV6(r.AAAA.String()) {
				hostToAAAA[name] = r.AAAA.String()
			}
		case *dns.PTR:
			ptrTarget := strings.TrimSuffix(r.Ptr, ".")
			ptrList = appendUniqueStr(ptrList, ptrTarget)
		}
	}

	// Step 3: group RRs by owner name (the name that owns the record)
	groups := make(map[string]*recordGroup) // keyed by normalized owner name

	getGroup := func(name string) *recordGroup {
		key := strings.ToLower(name)
		if g, ok := groups[key]; ok {
			return g
		}
		g := &recordGroup{name: name}
		groups[key] = g
		return g
	}

	for _, rr := range allRRs {
		switch r := rr.(type) {
		case *dns.PTR:
			// Skip — PTR targets are collected above
		case *dns.SRV:
			name := rr.Header().Name
			g := getGroup(name)
			g.srv = r
			if r.Hdr.Ttl > 0 {
				g.ttl = r.Hdr.Ttl
			}
		case *dns.TXT:
			name := rr.Header().Name
			g := getGroup(name)
			g.txts = append(g.txts, r)
			if r.Hdr.Ttl > 0 && g.ttl == 0 {
				g.ttl = r.Hdr.Ttl
			}
		case *dns.A:
			name := rr.Header().Name
			g := getGroup(name)
			g.as = append(g.as, r)
			if r.Hdr.Ttl > 0 && g.ttl == 0 {
				g.ttl = r.Hdr.Ttl
			}
		case *dns.AAAA:
			name := rr.Header().Name
			g := getGroup(name)
			g.aaaas = append(g.aaaas, r)
		}
	}

	// Step 4: build ServiceInfo from each group that has meaningful content
	services := make([]ServiceInfo, 0)
	seenLabels := make(map[string]bool)

	for _, g := range groups {
		svc := buildServiceInfo(g, hostToA, hostToAAAA, ptrList)

		// Skip empty services (groups with only PTR targets, no actual service data)
		if svc.Label == "" && svc.Name == "" && svc.Port == 0 && len(svc.Extra) == 0 {
			continue
		}

		// Deduplicate by label+port+name
		dedupKey := fmt.Sprintf("%s|%d|%s", svc.Label, svc.Port, svc.Name)
		if seenLabels[dedupKey] {
			continue
		}
		seenLabels[dedupKey] = true

		services = append(services, svc)
	}

	return services, ptrList
}

// buildServiceInfo builds a ServiceInfo from a grouped set of records.
func buildServiceInfo(g *recordGroup, hostToA, hostToAAAA map[string]string, ptrList []string) ServiceInfo {
	svc := ServiceInfo{}
	ownerName := strings.TrimSuffix(g.name, ".")

	// Determine label and proto from the service type embedded in the owner name.
	// e.g. "slw-nas._workstation._tcp.local" → label="workstation", proto="tcp"
	svcType := extractServiceType(g.name)
	svc.Label, svc.Proto = parseLabelProto(svcType)
	svc.Type = svcType

	// SRV data
	if g.srv != nil {
		svc.Port = int(g.srv.Port)
		svc.Target = strings.TrimSuffix(g.srv.Target, ".")
		svc.Priority = g.srv.Priority
		svc.Weight = g.srv.Weight
	}

	// TTL
	if g.ttl > 0 {
		svc.TTL = g.ttl
	}

		// Instance name: the leftmost label of the owner, before the first underscore
	// e.g. "slw-nas._workstation._tcp.local" → "slw-nas"
	// e.g. "slw-nas (AFP)._afpovertcp._tcp.local" → "slw-nas (AFP)"
	if idx := findServiceUnderscore(ownerName); idx > 0 {
		svc.Name = unescapeDNS(ownerName[:idx-1]) // -1 for the dot before _
	} else if g.srv != nil && g.srv.Target != "" {
		svc.Name = unescapeDNS(strings.TrimSuffix(g.srv.Target, "."))
	}

	// Merge all TXT records
	svc.AllTXT = make(map[string]string)
	svc.Extra = make(map[string]string)
	mergeTXTRecords(&svc, g.txts)

	// If no name yet, try TXT "Name" key
	if svc.Name == "" {
		if n, ok := svc.AllTXT["Name"]; ok {
			svc.Name = n
		}
	}

	// MAC address from TXT or from name
	if mac, ok := svc.AllTXT["MAC"]; ok {
		svc.MAC = mac
	}

	// IPv4 / IPv6: first check TXT, then A/AAAA from this group, then cross-reference by target hostname
	svc.IPv4 = resolveIPv4(g, svc, hostToA)
	svc.IPv6 = resolveIPv6(g, svc, hostToAAAA)

	// Hostname from TXT or SRV target
	if hn, ok := svc.AllTXT["Hostname"]; ok {
		svc.Hostname = hn
	} else if svc.Target != "" {
		svc.Hostname = svc.Target
	} else if len(g.as) > 0 {
		svc.Hostname = strings.TrimSuffix(g.as[0].Hdr.Name, ".")
	}

	// Extra fields are non-standard TXT keys
	standardKeys := map[string]bool{
		"Name": true, "name": true, "Hostname": true, "hostname": true,
		"MAC": true, "mac": true, "IPv4": true, "ipv4": true,
		"IPv6": true, "ipv6": true, "TTL": true, "ttl": true,
	}
	for k, v := range svc.AllTXT {
		if !standardKeys[k] {
			svc.Extra[k] = v
		}
	}

	// If not a real service but has meaningful TXT data, derive label from the owner name
	if svc.Label == "" && svc.Port == 0 && len(svc.AllTXT) > 0 {
		// Extract a label from the owner name (leftmost segment)
		parts := strings.SplitN(ownerName, ".", 2)
		if len(parts) > 0 && parts[0] != "" {
			svc.Label = parts[0]
		}
	}

	return svc
}

// mergeTXTRecords merges all TXT records in the group into the ServiceInfo.
func mergeTXTRecords(svc *ServiceInfo, txts []*dns.TXT) {
	for _, txt := range txts {
		for _, t := range txt.Txt {
			parts := strings.SplitN(t, "=", 2)
			key := parts[0]
			val := "true"
			if len(parts) == 2 {
				val = parts[1]
			}
			// Keep first occurrence in AllTXT
			if _, exists := svc.AllTXT[key]; !exists {
				svc.AllTXT[key] = val
			}
		}
	}
}

// resolveIPv4 finds the best IPv4 for a service group.
func resolveIPv4(g *recordGroup, svc ServiceInfo, hostToA map[string]string) string {
	// 1. TXT record
	if v, ok := svc.AllTXT["IPv4"]; ok {
		return v
	}
	if v, ok := svc.AllTXT["ipv4"]; ok {
		return v
	}
	// 2. A record from this group
	if len(g.as) > 0 {
		return g.as[0].A.String()
	}
	// 3. Cross-reference by SRV target hostname
	if g.srv != nil {
		target := strings.TrimSuffix(g.srv.Target, ".")
		if a, ok := hostToA[target]; ok {
			return a
		}
	}
	// 4. Cross-reference by owner name
	owner := strings.TrimSuffix(g.name, ".")
	if a, ok := hostToA[owner]; ok {
		return a
	}
	return ""
}

// resolveIPv6 finds the best IPv6 for a service group.
func resolveIPv6(g *recordGroup, svc ServiceInfo, hostToAAAA map[string]string) string {
	// 1. TXT record
	if v, ok := svc.AllTXT["IPv6"]; ok {
		return v
	}
	if v, ok := svc.AllTXT["ipv6"]; ok {
		return v
	}
	// 2. AAAA record from this group
	if len(g.aaaas) > 0 {
		return g.aaaas[0].AAAA.String()
	}
	// 3. Cross-reference by SRV target hostname
	if g.srv != nil {
		target := strings.TrimSuffix(g.srv.Target, ".")
		if a, ok := hostToAAAA[target]; ok {
			return a
		}
	}
	// 4. Cross-reference by owner name
	owner := strings.TrimSuffix(g.name, ".")
	if a, ok := hostToAAAA[owner]; ok {
		return a
	}
	return ""
}

// isPreferredV6 prefers link-local (fe80::) and global unicast over other types.
func isPreferredV6(addr string) bool {
	return strings.HasPrefix(addr, "fe80:") || strings.HasPrefix(addr, "2") || strings.HasPrefix(addr, "3")
}

// parseLabelProto extracts a human-readable label and protocol from a service type.
// e.g. "_workstation._tcp.local" → ("workstation", "tcp")
// e.g. "_http._tcp.local" → ("http", "tcp")
// e.g. "_device-info._tcp.local" → ("device-info", "tcp")
func parseLabelProto(svcType string) (label, proto string) {
	svcType = strings.TrimSuffix(svcType, ".")
	parts := strings.Split(svcType, ".")
	for i, p := range parts {
		if strings.HasPrefix(p, "_") {
			if i+1 < len(parts) && strings.HasPrefix(parts[i+1], "_") {
				label = strings.TrimPrefix(p, "_")
				proto = strings.TrimPrefix(parts[i+1], "_")
				return
			}
		}
	}
	return
}

// findServiceUnderscore finds the index where the service type (starting with _) begins.
func findServiceUnderscore(name string) int {
	parts := strings.Split(name, ".")
	for i, p := range parts {
		if strings.HasPrefix(p, "_") {
			// Return the position in the original string
			pos := 0
			for j := 0; j < i; j++ {
				pos += len(parts[j]) + 1 // +1 for the dot
			}
			return pos
		}
	}
	return -1
}

// collectAllRRs gathers all resource records from all DNS message sections.
func collectAllRRs(msg *dns.Msg) []dns.RR {
	all := make([]dns.RR, 0, len(msg.Answer)+len(msg.Ns)+len(msg.Extra))
	all = append(all, msg.Answer...)
	all = append(all, msg.Ns...)
	all = append(all, msg.Extra...)
	return all
}

// ExtractHostname discovers the primary hostname from an mDNS response.
// It ignores service-type names (starting with _) and query names.
func ExtractHostname(msg *dns.Msg) string {
	allRRs := collectAllRRs(msg)
	hostnames := make(map[string]int)
	for _, rr := range allRRs {
		name := strings.TrimSuffix(rr.Header().Name, ".")
		if name != "" && !strings.HasPrefix(name, "_") {
			hostnames[name]++
		}
		switch r := rr.(type) {
		case *dns.SRV:
			target := strings.TrimSuffix(r.Target, ".")
			if target != "" && !strings.HasPrefix(target, "_") {
				hostnames[target]++
			}
		case *dns.TXT:
			for _, t := range r.Txt {
				if strings.HasPrefix(t, "Hostname=") || strings.HasPrefix(t, "hostname=") {
					hn := strings.SplitN(t, "=", 2)[1]
					hostnames[hn] += 2
				}
			}
		}
	}

	var bestName string
	var bestCount int
	for name, count := range hostnames {
		if count > bestCount {
			bestCount = count
			bestName = name
		}
	}
	return bestName
}

// ExtractHInfo extracts HINFO record from the response if present.
func ExtractHInfo(msg *dns.Msg) *HInfo {
	for _, rr := range msg.Answer {
		if h, ok := rr.(*dns.HINFO); ok {
			return &HInfo{CPU: h.Cpu, OS: h.Os}
		}
	}
	for _, rr := range msg.Extra {
		if h, ok := rr.(*dns.HINFO); ok {
			return &HInfo{CPU: h.Cpu, OS: h.Os}
		}
	}
	return nil
}

// HasRecords checks whether the response contains any meaningful records.
func HasRecords(msg *dns.Msg) bool {
	return len(msg.Answer) > 0 || len(msg.Ns) > 0 || len(msg.Extra) > 0
}

// extractServiceType extracts the service type suffix from an mDNS name.
// e.g. "MyPrinter._ipp._tcp.local" → "_ipp._tcp.local"
// e.g. "_http._tcp.local" → "_http._tcp.local"
func extractServiceType(name string) string {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	for i := 0; i < len(parts); i++ {
		if strings.HasPrefix(parts[i], "_") {
			if i+1 < len(parts) && strings.HasPrefix(parts[i+1], "_") {
				return strings.Join(parts[i:], ".") + "."
			}
			// Single underscore label like "_tcp" or "_udp" — go back one more
			if i > 0 && strings.HasPrefix(parts[i-1], "_") {
				return strings.Join(parts[i-1:], ".") + "."
			}
		}
	}
	return ""
}

// unescapeDNS converts DNS-escaped names back to their readable form.
// DNS escaping uses backslash followed by the literal character, e.g.
// "slw-nas\ (AFP)" → "slw-nas (AFP)"
func unescapeDNS(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			// Check for \DDD (3-digit decimal escape)
			if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
				val := int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')
				b.WriteByte(byte(val))
				i += 4
				continue
			}
			// \X — literal next character
			b.WriteByte(s[i+1])
			i += 2
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func appendUniqueStr(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
