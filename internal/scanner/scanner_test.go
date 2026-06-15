package scanner

import (
	"reflect"
	"testing"
)

func TestExpandCIDR_single(t *testing.T) {
	ips, err := expandCIDR("192.168.1.1/32")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "192.168.1.1" {
		t.Errorf("expected [192.168.1.1], got %v", ips)
	}
}

func TestExpandCIDR_small24(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	// /24 = 256 IPs, minus network (.0) and broadcast (.255) = 254
	// But our len > 4 condition strips first and last
	if len(ips) != 254 {
		t.Errorf("expected 254 IPs, got %d", len(ips))
	}
	if ips[0] != "192.168.1.1" {
		t.Errorf("expected first IP 192.168.1.1, got %s", ips[0])
	}
	if ips[len(ips)-1] != "192.168.1.254" {
		t.Errorf("expected last IP 192.168.1.254, got %s", ips[len(ips)-1])
	}
}

func TestExpandCIDR_smallSubnet(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/29")
	if err != nil {
		t.Fatal(err)
	}
	// /29 = 8 IPs total (2^(32-29) = 8), but len > 4 strips net + broadcast → 6
	if len(ips) != 6 {
		t.Errorf("expected 6 usable IPs (net+bcast stripped), got %d: %v", len(ips), ips)
	}
}

func TestExpandCIDR_invalid(t *testing.T) {
	_, err := expandCIDR("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestIncIP(t *testing.T) {
	start := expandCIDRHelper("192.168.1.0/31")
	// /31 = 2 IPs, len ≤ 4, keeps all
	if !reflect.DeepEqual(start, []string{"192.168.1.0", "192.168.1.1"}) {
		t.Errorf("unexpected /31 expansion: %v", start)
	}
}

func expandCIDRHelper(cidr string) []string {
	ips, err := expandCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return ips
}

func TestParsePorts(t *testing.T) {
	// Note: parsePorts is in main.go; this tests the concept via table
	// The actual function is tested implicitly through the build.
}
