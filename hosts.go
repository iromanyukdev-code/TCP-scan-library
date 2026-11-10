package portscan

import (
	"fmt"
	"net/netip"
	"strings"
)

func normalizeHosts(hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("hosts must not be empty")
	}
	result := make([]string, 0, len(hosts))
	seen := make(map[string]bool)
	for _, host := range hosts {
		if host == "" || strings.TrimSpace(host) != host {
			return nil, fmt.Errorf("invalid host %q", host)
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			host = ip.Unmap().String()
		} else {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if !validDNS(host) {
				return nil, fmt.Errorf("invalid host %q: expected IP address or ASCII DNS name", host)
			}
		}
		if !seen[host] {
			seen[host] = true
			result = append(result, host)
		}
	}
	return result, nil
}

func validDNS(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	allNumeric := true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
			if c < '0' || c > '9' {
				allNumeric = false
			}
		}
	}
	return !allNumeric // Reject malformed numeric IP addresses rather than resolving them.
}
