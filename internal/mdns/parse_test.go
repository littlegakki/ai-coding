package mdns

import (
	"testing"

	"github.com/miekg/dns"
)

func TestDeepParse_Empty(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)

	services, ptrs := DeepParse(msg)
	if len(services) != 0 {
		t.Errorf("expected 0 services, got %d", len(services))
	}
	if len(ptrs) != 0 {
		t.Errorf("expected 0 PTRs, got %d", len(ptrs))
	}
}

func TestDeepParse_PTR(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)

	ptr1, _ := dns.NewRR("_services._dns-sd._udp.local. 10 IN PTR _http._tcp.local.")
	ptr2, _ := dns.NewRR("_services._dns-sd._udp.local. 10 IN PTR _ssh._tcp.local.")
	msg.Answer = append(msg.Answer, ptr1, ptr2)

	_, ptrs := DeepParse(msg)
	if len(ptrs) != 2 {
		t.Errorf("expected 2 PTRs, got %d: %v", len(ptrs), ptrs)
	}
}

func TestDeepParse_SRV_TXT_Grouping(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("MyService._http._tcp.local.", dns.TypeANY)

	// SRV and TXT share the same owner name → should be grouped into one service
	srv, _ := dns.NewRR("MyService._http._tcp.local. 10 IN SRV 0 0 8080 myhost.local.")
	txt, _ := dns.NewRR("MyService._http._tcp.local. 10 IN TXT \"model=TestDevice\" \"version=1.0\" \"path=/\"")
	a, _ := dns.NewRR("myhost.local. 10 IN A 192.168.1.50")
	msg.Answer = append(msg.Answer, srv, txt, a)

	services, _ := DeepParse(msg)

	// Should have 1 service (SRV+TXT grouped) and possibly myhost.local A record
	if len(services) == 0 {
		t.Fatal("expected at least 1 service, got 0")
	}

	// Find the HTTP service
	var httpSvc *ServiceInfo
	for i := range services {
		if services[i].Label == "http" {
			httpSvc = &services[i]
			break
		}
	}
	if httpSvc == nil {
		t.Fatalf("expected http service, got: %+v", services)
	}

	if httpSvc.Port != 8080 {
		t.Errorf("expected port 8080, got %d", httpSvc.Port)
	}
	if httpSvc.Proto != "tcp" {
		t.Errorf("expected proto tcp, got %s", httpSvc.Proto)
	}
	if httpSvc.Name != "MyService" {
		t.Errorf("expected name MyService, got %q", httpSvc.Name)
	}

	// Check TXT-derived extra fields
	if httpSvc.Extra == nil {
		t.Fatal("expected extra TXT fields")
	}
	if v := httpSvc.Extra["model"]; v != "TestDevice" {
		t.Errorf("expected model=TestDevice, got %s", v)
	}
	if v := httpSvc.Extra["path"]; v != "/" {
		t.Errorf("expected path=/, got %s", v)
	}
}

func TestDeepParse_Workstation_Example(t *testing.T) {
	// Simulate the slw-nas workstation example from the spec
	msg := new(dns.Msg)

	// PTR: _workstation._tcp.local → slw-nas._workstation._tcp.local
	ptr, _ := dns.NewRR("_workstation._tcp.local. 10 IN PTR slw-nas._workstation._tcp.local.")

	// SRV for the workstation instance
	srv, _ := dns.NewRR("slw-nas._workstation._tcp.local. 10 IN SRV 0 0 9 slw-nas.local.")

	// TXT for the workstation instance
	txt, _ := dns.NewRR("slw-nas._workstation._tcp.local. 10 IN TXT " +
		"\"Name=slw-nas\" \"MAC=24:5e:be:69:a3:13\" " +
		"\"IPv4=10.0.0.10\" \"IPv6=fe80::265e:beff:fe69:a313\" " +
		"\"Hostname=slw-nas.local\"")

	msg.Answer = append(msg.Answer, ptr, srv, txt)

	services, ptrs := DeepParse(msg)

	if len(ptrs) == 0 {
		t.Error("expected PTR targets")
	}

	// Find the workstation service
	var wsSvc *ServiceInfo
	for i := range services {
		if services[i].Label == "workstation" {
			wsSvc = &services[i]
			break
		}
	}
	if wsSvc == nil {
		t.Fatalf("expected workstation service, got: %+v", services)
	}

	if wsSvc.Port != 9 {
		t.Errorf("expected port 9, got %d", wsSvc.Port)
	}
	if wsSvc.Proto != "tcp" {
		t.Errorf("expected proto tcp, got %s", wsSvc.Proto)
	}
	if wsSvc.Name != "slw-nas" {
		t.Errorf("expected name slw-nas, got %q", wsSvc.Name)
	}
	if wsSvc.MAC != "24:5e:be:69:a3:13" {
		t.Errorf("expected MAC 24:5e:be:69:a3:13, got %q", wsSvc.MAC)
	}
	if wsSvc.IPv4 != "10.0.0.10" {
		t.Errorf("expected IPv4 10.0.0.10, got %q", wsSvc.IPv4)
	}
	if wsSvc.IPv6 != "fe80::265e:beff:fe69:a313" {
		t.Errorf("expected IPv6 fe80::..., got %q", wsSvc.IPv6)
	}
	if wsSvc.Hostname != "slw-nas.local" {
		t.Errorf("expected hostname slw-nas.local, got %q", wsSvc.Hostname)
	}
}

func TestDeepParse_DeviceInfo_Example(t *testing.T) {
	// Simulate device-info (portless service)
	msg := new(dns.Msg)

	txt, _ := dns.NewRR("slw-nas._device-info._tcp.local. 10 IN TXT " +
		"\"model=Xserve\"")
	msg.Answer = append(msg.Answer, txt)

	services, _ := DeepParse(msg)

	var diSvc *ServiceInfo
	for i := range services {
		if services[i].Label == "device-info" {
			diSvc = &services[i]
			break
		}
	}
	if diSvc == nil {
		t.Fatalf("expected device-info service, got: %+v", services)
	}

	if diSvc.Port != 0 {
		t.Errorf("expected port 0 (portless), got %d", diSvc.Port)
	}
	if v := diSvc.Extra["model"]; v != "Xserve" {
		t.Errorf("expected model=Xserve, got %s", v)
	}
}

func TestDeepParse_AFPOvertcp_WithParenthetical(t *testing.T) {
	msg := new(dns.Msg)

	srv, _ := dns.NewRR("slw-nas\\ (AFP)._afpovertcp._tcp.local. 10 IN SRV 0 0 548 slw-nas.local.")
	txt, _ := dns.NewRR("slw-nas\\ (AFP)._afpovertcp._tcp.local. 10 IN TXT " +
		"\"Name=slw-nas(AFP)\" \"IPv4=10.0.0.10\"")
	msg.Answer = append(msg.Answer, srv, txt)

	services, _ := DeepParse(msg)

	if len(services) == 0 {
		t.Fatal("expected services, got none")
	}

	var afpSvc *ServiceInfo
	for i := range services {
		if services[i].Label == "afpovertcp" {
			afpSvc = &services[i]
			break
		}
	}
	if afpSvc == nil {
		t.Fatalf("expected afpovertcp service, got: %+v", services)
	}
	if afpSvc.Port != 548 {
		t.Errorf("expected port 548, got %d", afpSvc.Port)
	}
}

func TestExtractHostname(t *testing.T) {
	msg := new(dns.Msg)
	a, _ := dns.NewRR("printer-office._ipp._tcp.local. 10 IN A 192.168.1.50")
	srv, _ := dns.NewRR("_ipp._tcp.local. 10 IN SRV 0 0 631 printer-office.local.")
	msg.Answer = append(msg.Answer, a, srv)

	hostname := ExtractHostname(msg)
	if hostname == "" {
		t.Error("expected non-empty hostname")
	}
}

func TestHasRecords(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("test.local.", dns.TypeA)
	if HasRecords(msg) {
		t.Error("expected false for query-only message")
	}

	a, _ := dns.NewRR("test.local. 10 IN A 1.2.3.4")
	msg.Answer = append(msg.Answer, a)
	if !HasRecords(msg) {
		t.Error("expected true for message with answer")
	}
}

func TestExtractServiceType(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"MyPrinter._ipp._tcp.local", "_ipp._tcp.local."},
		{"_http._tcp.local", "_http._tcp.local."},
		{"myhost.local", ""},
		{"192.168.1.10._http._tcp.local", "_http._tcp.local."},
		{"slw-nas._workstation._tcp.local", "_workstation._tcp.local."},
	}

	for _, tt := range tests {
		result := extractServiceType(tt.name)
		if result != tt.expected {
			t.Errorf("extractServiceType(%q) = %q, want %q", tt.name, result, tt.expected)
		}
	}
}

func TestParseLabelProto(t *testing.T) {
	tests := []struct {
		svcType    string
		wantLabel  string
		wantProto  string
	}{
		{"_workstation._tcp.local.", "workstation", "tcp"},
		{"_http._tcp.local.", "http", "tcp"},
		{"_device-info._tcp.local.", "device-info", "tcp"},
		{"_afpovertcp._tcp.local.", "afpovertcp", "tcp"},
	}

	for _, tt := range tests {
		label, proto := parseLabelProto(tt.svcType)
		if label != tt.wantLabel || proto != tt.wantProto {
			t.Errorf("parseLabelProto(%q) = (%q, %q), want (%q, %q)",
				tt.svcType, label, proto, tt.wantLabel, tt.wantProto)
		}
	}
}

func TestBuildServiceEnumQuery(t *testing.T) {
	q := BuildServiceEnumQuery()
	if len(q.Question) != 1 {
		t.Fatalf("expected 1 question, got %d", len(q.Question))
	}
	if q.Question[0].Name != "_services._dns-sd._udp.local." {
		t.Errorf("unexpected name: %s", q.Question[0].Name)
	}
	if q.Question[0].Qtype != dns.TypePTR {
		t.Errorf("expected PTR type, got %d", q.Question[0].Qtype)
	}
}

func TestBuildAnyQuery(t *testing.T) {
	q := BuildAnyQuery("_http._tcp.local")
	if q.Question[0].Qtype != dns.TypeANY {
		t.Errorf("expected ANY type, got %d", q.Question[0].Qtype)
	}
}

func TestExtractHInfo(t *testing.T) {
	msg := new(dns.Msg)
	hinfo, _ := dns.NewRR("myhost.local. 10 IN HINFO \"x86_64\" \"Linux\"")
	msg.Answer = append(msg.Answer, hinfo)

	hi := ExtractHInfo(msg)
	if hi == nil {
		t.Fatal("expected HInfo, got nil")
	}
	if hi.CPU != "x86_64" {
		t.Errorf("expected CPU x86_64, got %s", hi.CPU)
	}
	if hi.OS != "Linux" {
		t.Errorf("expected OS Linux, got %s", hi.OS)
	}
}
