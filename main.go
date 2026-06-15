// mdns-scanner is a network reconnaissance CLI tool that scans IP ranges
// and port ranges for mDNS services, extracting IP, port, hostname, and
// deep banner information.
//
// Usage:
//
//	mdns-scanner -c 192.168.1.0/24 -p 5353
//	mdns-scanner -c 10.0.0.0/28 -p 5353-5355 -o json
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cyb/mdns-scanner/internal/output"
	"github.com/cyb/mdns-scanner/internal/scanner"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// CLI flags
	var (
		cidr        string
		portsStr    string
		timeoutSec  int
		concurrency int
		outFormat   string
		serviceName string
	)

	flag.StringVar(&cidr, "c", "", "Target CIDR range (e.g., \"192.168.1.0/24\")")
	flag.StringVar(&cidr, "cidr", "", "Target CIDR range")
	flag.StringVar(&portsStr, "p", "5353", "Port range (e.g., \"5353\" or \"5353-5355\")")
	flag.StringVar(&portsStr, "ports", "5353", "Port range")
	flag.IntVar(&timeoutSec, "t", 2, "Query timeout in seconds")
	flag.IntVar(&timeoutSec, "timeout", 2, "Query timeout in seconds")
	flag.IntVar(&concurrency, "n", 50, "Number of concurrent workers")
	flag.IntVar(&concurrency, "concurrency", 50, "Number of concurrent workers")
	flag.StringVar(&outFormat, "o", "table", "Output format: table, json, or csv")
	flag.StringVar(&outFormat, "output", "table", "Output format: table, json, or csv")
	flag.StringVar(&serviceName, "s", "", "Custom service query name (default: _services._dns-sd._udp.local)")
	flag.StringVar(&serviceName, "services", "", "Custom service query name")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "mdns-scanner — mDNS Network Asset Scanner\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  mdns-scanner -c <CIDR> [-p <ports>] [-o <format>] [-n <workers>] [-t <seconds>]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  mdns-scanner -c 192.168.1.0/24\n")
		fmt.Fprintf(os.Stderr, "  mdns-scanner -c 10.0.0.0/28 -p 5353-5355 -o json\n")
		fmt.Fprintf(os.Stderr, "  mdns-scanner -c 172.16.0.0/24 -p 5353 -n 100 -t 3 -o csv\n")
	}

	flag.Parse()

	if cidr == "" {
		flag.Usage()
		return fmt.Errorf("CIDR range is required (use -c)")
	}

	// Parse ports
	ports, err := parsePorts(portsStr)
	if err != nil {
		return fmt.Errorf("invalid port range %q: %w", portsStr, err)
	}

	// Validate output format
	var fmt_ output.Format
	switch strings.ToLower(outFormat) {
	case "table":
		fmt_ = output.FormatTable
	case "json":
		fmt_ = output.FormatJSON
	case "csv":
		fmt_ = output.FormatCSV
	default:
		return fmt.Errorf("unknown output format %q (use: table, json, csv)", outFormat)
	}

	// Use custom service name if provided, else default
	svcQuery := serviceName
	if svcQuery == "" {
		svcQuery = "_services._dns-sd._udp.local"
	}

	// Context with cancellation on SIGINT/SIGTERM
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n[!] received interrupt, shutting down...")
		cancel()
	}()

	fmt.Fprintf(os.Stderr, "[*] Scanning %s, ports %s, timeout=%ds, workers=%d\n",
		cidr, portsStr, timeoutSec, concurrency)

	start := time.Now()

	assets, err := scanner.Scan(ctx, scanner.Config{
		CIDR:        cidr,
		Ports:       ports,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		Concurrency: concurrency,
		ServiceName: svcQuery,
	})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	elapsed := time.Since(start)

	if err := output.Write(assets, fmt_); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[*] Scan complete: %d assets found in %v\n", len(assets), elapsed.Round(time.Millisecond))

	return nil
}

// parsePorts parses a port range string like "5353" or "5353-5355".
func parsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)

	// Single port
	if !strings.Contains(s, "-") {
		port, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", s)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port out of range: %d", port)
		}
		return []int{port}, nil
	}

	// Port range
	parts := strings.SplitN(s, "-", 2)
	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid start port: %s", parts[0])
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid end port: %s", parts[1])
	}

	if start < 1 || end > 65535 || start > end {
		return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
	}

	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports, nil
}
