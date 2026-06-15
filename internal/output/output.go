// Package output formats scan results for display.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cyb/mdns-scanner/internal/mdns"
)

// Format represents an output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatCSV   Format = "csv"
)

// Write writes the asset list to stdout in the requested format.
func Write(assets []mdns.Asset, format Format) error {
	switch format {
	case FormatJSON:
		return writeJSON(assets)
	case FormatCSV:
		return writeCSV(assets)
	default:
		return writeText(assets)
	}
}

// writeText outputs a human-readable deep banner format matching the example:
//
//	services:
//	9/tcp workstation:
//	Name=slw-nas [24:5e:be:69:a3:13]
//	IPv4=x.x.x.x
//	IPv6=...
func writeText(assets []mdns.Asset) error {
	if len(assets) == 0 {
		fmt.Println("No mDNS assets found.")
		return nil
	}

	for i, a := range assets {
		if i > 0 {
			fmt.Println(strings.Repeat("─", 72))
		}

		// Header
		hn := a.Hostname
		if hn == "" {
			hn = "<unknown>"
		}
		fmt.Printf("[%s:%d]  hostname=%s  latency=%v\n",
			a.IP, a.Port, hn, a.Elapsed.Round(0))
		fmt.Println()

		// Services section
		if len(a.Services) > 0 {
			fmt.Println("services:")

			// Sort a copy: portless (device-info) first, then by port
			sorted := make([]mdns.ServiceInfo, len(a.Services))
			copy(sorted, a.Services)
			sort.Slice(sorted, func(i, j int) bool {
				if sorted[i].Port == 0 && sorted[j].Port != 0 {
					return true
				}
				if sorted[i].Port != 0 && sorted[j].Port == 0 {
					return false
				}
				return sorted[i].Port < sorted[j].Port
			})

			for i := range sorted {
				writeServiceBlock(&sorted[i])
			}
		}

		// HInfo
		if a.HInfo != nil {
			fmt.Println("host-info:")
			fmt.Printf("CPU=%s\n", a.HInfo.CPU)
			fmt.Printf("OS=%s\n", a.HInfo.OS)
			fmt.Println()
		}

		// PTR list (answers)
		if len(a.PTRList) > 0 {
			fmt.Println("answers:")
			fmt.Println("PTR:")

			// Deduplicate and sort
			seen := make(map[string]bool)
			uniq := make([]string, 0)
			for _, p := range a.PTRList {
				if !seen[p] {
					seen[p] = true
					uniq = append(uniq, p)
				}
			}
			sort.Strings(uniq)

			for _, p := range uniq {
				fmt.Printf("%s\n", p)
			}
			fmt.Println()
		}
	}

	return nil
}

// writeServiceBlock writes a single service's deep banner block.
func writeServiceBlock(svc *mdns.ServiceInfo) {
	// Header line: "<port>/<proto> <label>:"  or  "<label>:"
	if svc.Label == "" {
		return
	}

	if svc.Port > 0 {
		fmt.Printf("%d/%s %s:\n", svc.Port, svc.Proto, svc.Label)
	} else {
		fmt.Printf("%s:\n", svc.Label)
	}

	// Name with optional MAC
	if svc.Name != "" {
		if svc.MAC != "" {
			fmt.Printf("Name=%s [%s]\n", svc.Name, svc.MAC)
		} else {
			fmt.Printf("Name=%s\n", svc.Name)
		}
	}

	// IPv4
	if svc.IPv4 != "" {
		fmt.Printf("IPv4=%s\n", svc.IPv4)
	}

	// IPv6
	if svc.IPv6 != "" {
		fmt.Printf("IPv6=%s\n", svc.IPv6)
	}

	// Hostname
	if svc.Hostname != "" {
		fmt.Printf("Hostname=%s\n", svc.Hostname)
	}

	// TTL
	if svc.TTL > 0 {
		fmt.Printf("TTL=%d\n", svc.TTL)
	}

	// Extra TXT fields (non-standard)
	if len(svc.Extra) > 0 {
		// Sort keys for consistent output
		keys := make([]string, 0, len(svc.Extra))
		for k := range svc.Extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%s=%s\n", k, svc.Extra[k])
		}
	}

	fmt.Println()
}

func writeJSON(assets []mdns.Asset) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(assets)
}

func writeCSV(assets []mdns.Asset) error {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	_ = w.Write([]string{
		"IP", "Port", "Hostname", "ServiceLabel", "Proto", "ServicePort",
		"Name", "MAC", "IPv4", "IPv6", "TTL", "ExtraTXT", "PTRList",
	})

	for _, a := range assets {
		ptrJSON, _ := json.Marshal(a.PTRList)

		if len(a.Services) == 0 {
			_ = w.Write([]string{
				a.IP,
				fmt.Sprintf("%d", a.Port),
				a.Hostname,
				"", "", "", "", "", "", "", "",
				"",
				string(ptrJSON),
			})
			continue
		}

		for _, svc := range a.Services {
			extraJSON, _ := json.Marshal(svc.Extra)
			ttl := ""
			if svc.TTL > 0 {
				ttl = fmt.Sprintf("%d", svc.TTL)
			}
			_ = w.Write([]string{
				a.IP,
				fmt.Sprintf("%d", a.Port),
				a.Hostname,
				svc.Label,
				svc.Proto,
				fmt.Sprintf("%d", svc.Port),
				svc.Name,
				svc.MAC,
				svc.IPv4,
				svc.IPv6,
				ttl,
				string(extraJSON),
				string(ptrJSON),
			})
		}
	}

	return w.Error()
}
