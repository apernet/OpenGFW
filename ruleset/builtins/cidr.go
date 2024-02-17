package builtins

import (
	"net"
)

func MatchCIDR(ip string, cidr *net.IPNet) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}
	return cidr.Contains(ipAddr)
}

func CompileCIDR(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	return ipNet, err
}
