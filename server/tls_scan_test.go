package main

import (
	"net"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{"example.com", "example.com", true},
		{" https://EXAMPLE.com/path ", "example.com", true},
		{"sub.example.com.", "sub.example.com", true},
		{"127.0.0.1", "", false},
		{"example.com:8443", "", false},
		{"https://example.com:8443/path", "", false},
		{"localhost", "", false},
		{"*.example.com", "", false},
	}
	for _, test := range tests {
		actual, err := normalizeHost(test.input)
		if test.ok && (err != nil || actual != test.want) {
			t.Fatalf("normalizeHost(%q) = %q, %v; want %q", test.input, actual, err, test.want)
		}
		if !test.ok && err == nil {
			t.Fatalf("normalizeHost(%q) unexpectedly accepted as %q", test.input, actual)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		address string
		public  bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.1.1", false},
		{"100.64.0.1", false},
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"::1", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"2001:db8::1", false},
	}
	for _, test := range tests {
		if actual := isPublicIP(net.ParseIP(test.address)); actual != test.public {
			t.Fatalf("isPublicIP(%q) = %v; want %v", test.address, actual, test.public)
		}
	}
}
