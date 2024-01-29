package geo

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

type GeoMatcher struct {
	geoLoader       GeoLoader
	geoSiteMatcher  map[string]hostMatcher
	siteMatcherLock sync.Mutex
	geoIpMatcher    map[string]hostMatcher
	ipMatcherLock   sync.Mutex
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
	g.ipMatcherLock.Lock()
	defer g.ipMatcherLock.Unlock()

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
	g.siteMatcherLock.Lock()
	defer g.siteMatcherLock.Unlock()

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

func compileHostMatcher(addr string, geoLoader GeoLoader) (hostMatcher, string) {
	addr = strings.ToLower(addr) // Normalize to lower case
	if addr == "*" || addr == "all" {
		// Match all hosts
		return &allMatcher{}, ""
	}
	if strings.HasPrefix(addr, "geoip:") {
		// GeoIP matcher
		country := addr[6:]
		if len(country) == 0 {
			return nil, "empty GeoIP country code"
		}
		gMap, err := geoLoader.LoadGeoIP()
		if err != nil {
			return nil, err.Error()
		}
		list, ok := gMap[country]
		if !ok || list == nil {
			return nil, fmt.Sprintf("GeoIP country code %s not found", country)
		}
		m, err := newGeoIPMatcher(list)
		if err != nil {
			return nil, err.Error()
		}
		return m, ""
	}
	if strings.HasPrefix(addr, "geosite:") {
		// MatchGeoSite matcher
		name, attrs := parseGeoSiteName(addr[8:])
		if len(name) == 0 {
			return nil, "empty MatchGeoSite name"
		}
		gMap, err := geoLoader.LoadGeoSite()
		if err != nil {
			return nil, err.Error()
		}
		list, ok := gMap[name]
		if !ok || list == nil {
			return nil, fmt.Sprintf("MatchGeoSite name %s not found", name)
		}
		m, err := newGeositeMatcher(list, attrs)
		if err != nil {
			return nil, err.Error()
		}
		return m, ""
	}
	if strings.HasPrefix(addr, "suffix:") {
		// Domain suffix matcher
		suffix := addr[7:]
		if len(suffix) == 0 {
			return nil, "empty domain suffix"
		}
		return &domainMatcher{
			Pattern: suffix,
			Mode:    domainMatchSuffix,
		}, ""
	}
	if strings.Contains(addr, "/") {
		// CIDR matcher
		_, ipnet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil, fmt.Sprintf("invalid CIDR address: %s", addr)
		}
		return &cidrMatcher{ipnet}, ""
	}
	if ip := net.ParseIP(addr); ip != nil {
		// Single IP matcher
		return &ipMatcher{ip}, ""
	}
	if strings.Contains(addr, "*") {
		// Wildcard domain matcher
		return &domainMatcher{
			Pattern: addr,
			Mode:    domainMatchWildcard,
		}, ""
	}
	// Nothing else matched, treat it as a non-wildcard domain
	return &domainMatcher{
		Pattern: addr,
		Mode:    domainMatchExact,
	}, ""
}

func parseGeoSiteName(s string) (string, []string) {
	parts := strings.Split(s, "@")
	base := strings.TrimSpace(parts[0])
	attrs := parts[1:]
	for i := range attrs {
		attrs[i] = strings.TrimSpace(attrs[i])
	}
	return base, attrs
}
