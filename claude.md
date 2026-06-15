# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
go build -o mdns-scanner .       # Build the CLI binary
go test ./...                     # Run all tests
go test ./internal/mdns/ -v       # Run mDNS parser tests with verbose output
go test -run TestDeepParse ./internal/mdns/  # Run a single test
go run ./cmd/demo/                # Run synthetic data demo (deep banner preview)
```

## Architecture

This is a Go CLI tool that scans IP ranges for mDNS services using unicast DNS queries. It sends DNS packets (via `github.com/miekg/dns`) directly to each target IP:port and extracts deeply structured banner data from responses.

### Package Dependency Flow

```
main.go  ──→  scanner  ──→  mdns
                  │
                  └──→  output  ──→  mdns (types only)
```

- **`internal/mdns/`** — Core protocol layer. No dependencies on scanner or output.
  - `types.go` — `Asset`, `ServiceInfo`, `HInfo`, `ScanResult` structs. `ServiceInfo` is the rich per-service output type with Label, Proto, Port, Name, MAC, IPv4/IPv6, Hostname, TTL, and Extra TXT key-values.
  - `query.go` — DNS/mDNS query packet construction. `BuildServiceEnumQuery()` (PTR for `_services._dns-sd._udp.local`), `BuildAnyQuery()`, and the `CommonServiceTypes` list used as fallback probes.
  - `parse.go` — **Core deep parser.** `DeepParse(msg)` does 3 passes over all DNS response sections (Answer+Ns+Extra): (1) builds `hostname→A`/`hostname→AAAA` maps and collects PTR targets, (2) groups SRV/TXT/A/AAAA records by **owner name** using `recordGroup`, (3) builds `ServiceInfo` from each group with cross-referenced address resolution. IPv4/IPv6 resolution priority: TXT keys → own A/AAAA records → SRV target hostname A/AAAA → owner name A/AAAA.

- **`internal/scanner/`** — Concurrent unicast scanning with worker pool.
  - `Scan()` expands CIDR via `expandCIDR()`, builds an IP×port target list, feeds a buffered channel to N concurrent workers (`sync.WaitGroup` + `progressbar`), collects `mdns.Asset` results.
  - `scanTarget()` runs a **three-phase probe** per target: Phase 1 sends the service-enumeration PTR query; Phase 2 sends ANY queries for each discovered service type; Phase 3 (fallback, only if Phase 1 yielded nothing and no PTR answers) probes all 25 `CommonServiceTypes` for IoT/embedded devices that don't support DNS-SD enumeration.
  - Results from all phases are merged via `processResp()` → `mdns.DeepParse()`. Services are deduplicated by `label|port|name` key.

- **`internal/output/`** — Three output formatters: human-readable text (the default "table" format), JSON, and CSV. The text formatter prints per-service blocks with `<port>/<proto> <label>` headers followed by `Name=`, `IPv4=` etc., then a PTR list section, matching the deep banner spec.

### Key Design Decisions

- **Unicast, not multicast**: Queries are sent directly to each target IP (not to `224.0.0.251`). This allows scanning specific IP ranges rather than passive discovery.
- **Unicast-response bit**: Queries set bit `0x8000` in QCLASS per RFC 6762 to request unicast responses.
- **Record grouping**: Services are reconstructed by grouping DNS records that share the same owner name (e.g., `slw-nas._workstation._tcp.local`). This is how SRV port, TXT metadata, and A/AAAA addresses are correlated.
- **Service type extraction**: `extractServiceType()` and `parseLabelProto()` parse `_type._proto.local` patterns from owner names to derive the short label (`workstation`, `http`) and protocol (`tcp`, `udp`).
- **DNS name unescaping**: `unescapeDNS()` handles `\X` and `\DDD` escape sequences in DNS names (e.g., `slw-nas\ (AFP)` → `slw-nas (AFP)`).
- **CIDR expansion**: `expandCIDR()` strips network and broadcast addresses for subnets with >4 hosts.
