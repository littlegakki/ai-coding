// Package mdns provides mDNS protocol query construction and response parsing
// for network asset reconnaissance with deep banner recognition.
package mdns

import "time"

// Asset represents a discovered mDNS host with its services.
type Asset struct {
	IP       string        `json:"ip"`
	Port     int           `json:"port"`
	Hostname string        `json:"hostname"`
	Services []ServiceInfo `json:"services"`
	PTRList  []string      `json:"ptr_list"`  // All discovered PTR targets
	HInfo    *HInfo        `json:"hinfo"`     // Host info if available (HINFO record)
	Elapsed  time.Duration `json:"elapsed"`   // Scan latency
}

// ServiceInfo describes a single mDNS service instance with deep banner detail.
type ServiceInfo struct {
	// Display label, e.g. "workstation", "http", "smb", "device-info"
	Label string `json:"label"`
	// Protocol: "tcp" or "udp" (extracted from service type)
	Proto string `json:"proto"`
	// Service port from SRV record (0 if portless, e.g. device-info)
	Port int `json:"port"`
	// Instance name, e.g. "slw-nas"
	Name string `json:"name"`
	// MAC address if found in TXT records
	MAC string `json:"mac,omitempty"`
	// IPv4 address from A records
	IPv4 string `json:"ipv4,omitempty"`
	// IPv6 address from AAAA records
	IPv6 string `json:"ipv6,omitempty"`
	// Hostname from SRV target or record owner names
	Hostname string `json:"hostname,omitempty"`
	// TTL from the records (seconds)
	TTL uint32 `json:"ttl"`
	// Original service type FQDN, e.g. "_workstation._tcp.local"
	Type string `json:"type,omitempty"`
	// SRV target hostname
	Target string `json:"target,omitempty"`
	// SRV priority
	Priority uint16 `json:"priority,omitempty"`
	// SRV weight
	Weight uint16 `json:"weight,omitempty"`
	// Extra key-value pairs from TXT records (excluding standard fields)
	Extra map[string]string `json:"extra,omitempty"`
	// All raw TXT key-values including standard fields
	AllTXT map[string]string `json:"all_txt,omitempty"`
}

// HInfo holds host information from an HINFO record.
type HInfo struct {
	CPU string `json:"cpu"`
	OS  string `json:"os"`
}

// ScanResult wraps a single scan target with its discovered asset or error.
type ScanResult struct {
	IP    string
	Port  int
	Asset *Asset
	Err   error
}
