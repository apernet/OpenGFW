package acl

import (
	"fmt"
	"net"
)

type GeoMatcher struct {
	geoLoader      GeoLoader
	geoSiteMatcher map[string]hostMatcher
	geoIpMatcher   map[string]hostMatcher
}

func NewGeoLoader() (*GeoMatcher, error) {
	geoLoader := NewDefaultGeoLoader()
	return &GeoMatcher{
		geoLoader:      geoLoader,
		geoSiteMatcher: make(map[string]hostMatcher),
		geoIpMatcher:   make(map[string]hostMatcher),
	}, nil
}

func (g *GeoMatcher) MatchGeoIp(ip, condition string) bool {
	matcher, ok := g.geoIpMatcher[condition]
	if !ok {
		var errString string
		matcher, errString = compileHostMatcher("geoip:"+condition, g.geoLoader)
		if errString != "" {
			return false
		}
		g.geoIpMatcher[condition] = matcher
	}
	parseIp := net.ParseIP(ip)
	if parseIp == nil {
		return false
	}
	ipv4 := parseIp.To4()
	if ipv4 != nil {
		return matcher.Match(HostInfo{IPv4: ipv4})
	}
	ipv6 := parseIp.To16()
	if ipv6 != nil {
		return matcher.Match(HostInfo{IPv6: ipv6})
	}
	return false
}

func (g *GeoMatcher) MatchGeoSite(site, condition string) bool {
	matcher, ok := g.geoSiteMatcher[condition]
	if !ok {
		var errString string
		matcher, errString = compileHostMatcher("geosite:"+condition, g.geoLoader)
		fmt.Println(errString)
		if errString != "" {
			return false
		}
		g.geoSiteMatcher[condition] = matcher
	}
	return matcher.Match(HostInfo{Name: site})
}
