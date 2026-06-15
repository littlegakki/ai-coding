// Package scanner provides concurrent mDNS network scanning over IP ranges.
package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cyb/mdns-scanner/internal/mdns"
	"github.com/miekg/dns"
	"github.com/schollz/progressbar/v3"
)

// Config holds scanner configuration.
type Config struct {
	CIDR        string
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	ServiceName string // The PTR query name for service enumeration
}

// target holds a single IP:port combination to probe.
type target struct {
	ip   string
	port int
}

// Scan runs the mDNS scan over the configured IP range and ports.
func Scan(ctx context.Context, cfg Config) ([]mdns.Asset, error) {
	ips, err := expandCIDR(cfg.CIDR)
	if err != nil {
		return nil, fmt.Errorf("expand CIDR %q: %w", cfg.CIDR, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses in range %q", cfg.CIDR)
	}

	// Build the target list: every IP × every port
	targets := make([]target, 0, len(ips)*len(cfg.Ports))
	for _, ip := range ips {
		for _, port := range cfg.Ports {
			targets = append(targets, target{ip: ip, port: port})
		}
	}

	// Channels
	targetCh := make(chan target, len(targets))
	resultCh := make(chan mdns.ScanResult, len(targets))

	for _, t := range targets {
		targetCh <- t
	}
	close(targetCh)

	// Worker pool
	var wg sync.WaitGroup
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	bar := progressbar.Default(int64(len(targets)), "scanning")

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, targetCh, resultCh, cfg.Timeout, cfg.ServiceName, bar)
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results
	assets := make([]mdns.Asset, 0)
	for r := range resultCh {
		if r.Err != nil {
			continue
		}
		if r.Asset != nil {
			assets = append(assets, *r.Asset)
		}
	}

	return assets, nil
}

// worker pulls targets, sends mDNS queries, and pushes results.
func worker(ctx context.Context, targets <-chan target,
	results chan<- mdns.ScanResult, timeout time.Duration,
	serviceName string, bar *progressbar.ProgressBar) {

	client := &dns.Client{Net: "udp", Timeout: timeout}

	for t := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		results <- scanTarget(client, t.ip, t.port, timeout, serviceName)
		_ = bar.Add(1)
	}
}

// scanTarget sends mDNS queries to a single IP:port and builds an Asset
// using deep banner parsing.
func scanTarget(client *dns.Client, ip string, port int,
	timeout time.Duration, serviceName string) mdns.ScanResult {

	result := mdns.ScanResult{IP: ip, Port: port}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	start := time.Now()

	// Accumulate all services and PTRs from multiple query phases
	var allServices []mdns.ServiceInfo
	var allPTRs []string
	var resolvedHostname string
	var hinfo *mdns.HInfo

	// Helper: process a response and merge findings
	processResp := func(msg *dns.Msg) {
		if msg == nil || !mdns.HasRecords(msg) {
			return
		}
		svcs, ptrs := mdns.DeepParse(msg)
		allServices = append(allServices, svcs...)
		allPTRs = append(allPTRs, ptrs...)
		if resolvedHostname == "" {
			resolvedHostname = mdns.ExtractHostname(msg)
		}
		if hinfo == nil {
			hinfo = mdns.ExtractHInfo(msg)
		}
	}

	// Track which service types we've already probed deeply
	queriedTypes := make(map[string]bool)

	// Phase 1: Service enumeration query
	svcMsg := buildInitialQuery(serviceName)
	svcMsg.Id = dns.Id()
	svcResp, _, err := client.Exchange(svcMsg, addr)
	if err != nil {
		result.Err = err
		return result
	}
	processResp(svcResp)

	// Collect service types discovered from phase 1 for deep probing
	svcTypesToQuery := make([]string, 0)
	for _, s := range allServices {
		if s.Type != "" && !queriedTypes[s.Type] {
			svcTypesToQuery = append(svcTypesToQuery, s.Type)
			queriedTypes[s.Type] = true
		}
	}

	// Phase 2: Deep probe each discovered service type
	for _, svcType := range svcTypesToQuery {
		anyMsg := mdns.BuildAnyQuery(svcType)
		anyMsg.Id = dns.Id()
		resp, _, err := client.Exchange(anyMsg, addr)
		if err == nil {
			processResp(resp)
		}
	}

	// Phase 3: Fallback — probe common service types for hosts that
	// don't support service enumeration (embedded/IoT devices)
	if len(allServices) == 0 && !osSupportsServiceEnum(svcResp) {
		for _, svcType := range mdns.CommonServiceTypes {
			anyMsg := mdns.BuildAnyQuery(svcType)
			anyMsg.Id = dns.Id()
			resp, _, err := client.Exchange(anyMsg, addr)
			if err == nil {
				processResp(resp)
			}
		}
	}

	if len(allServices) == 0 && !mdns.HasRecords(svcResp) {
		result.Err = fmt.Errorf("no mDNS response")
		return result
	}

	// Ensure every service inherits the host-level IPv4/IPv6 if not already set.
	// Collect host-level addresses from services that have them.
	hostIPv4, hostIPv6 := findHostAddrs(allServices)
	for i := range allServices {
		if allServices[i].IPv4 == "" {
			allServices[i].IPv4 = hostIPv4
		}
		if allServices[i].IPv6 == "" {
			allServices[i].IPv6 = hostIPv6
		}
	}

	result.Asset = &mdns.Asset{
		IP:       ip,
		Port:     port,
		Hostname: resolvedHostname,
		Services: dedupeServices(allServices),
		PTRList:  allPTRs,
		HInfo:    hinfo,
		Elapsed:  time.Since(start),
	}

	return result
}

// findHostAddrs finds the most common IPv4/IPv6 from a list of services.
func findHostAddrs(services []mdns.ServiceInfo) (ipv4, ipv6 string) {
	for _, s := range services {
		if s.IPv4 != "" && ipv4 == "" {
			ipv4 = s.IPv4
		}
		if s.IPv6 != "" && ipv6 == "" {
			ipv6 = s.IPv6
		}
		if ipv4 != "" && ipv6 != "" {
			break
		}
	}
	return
}

// buildInitialQuery builds the opening mDNS query.
func buildInitialQuery(serviceName string) *dns.Msg {
	if serviceName == mdns.DefaultServiceQuery {
		return mdns.BuildServiceEnumQuery()
	}
	return mdns.BuildAnyQuery(serviceName)
}

// osSupportsServiceEnum checks if the response indicates DNS-SD enumeration support.
func osSupportsServiceEnum(msg *dns.Msg) bool {
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.PTR); ok {
			return true
		}
	}
	return false
}

// expandCIDR expands a CIDR notation string into a slice of IP strings.
func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	var ips []string
	ip := ipnet.IP.Mask(ipnet.Mask)

	for ip = ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 4 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

// incIP increments an IP address by 1.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// dedupeServices removes duplicate services by label+port+name.
func dedupeServices(services []mdns.ServiceInfo) []mdns.ServiceInfo {
	seen := make(map[string]bool)
	uniq := make([]mdns.ServiceInfo, 0, len(services))
	for _, s := range services {
		key := fmt.Sprintf("%s|%d|%s", s.Label, s.Port, s.Name)
		if !seen[key] {
			seen[key] = true
			uniq = append(uniq, s)
		}
	}
	return uniq
}
