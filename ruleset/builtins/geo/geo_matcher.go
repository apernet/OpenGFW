package geo

import (
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

func NewGeoMatcher(geoSiteFilename, geoIpFilename string) *GeoMatcher {
	return &GeoMatcher{
		geoLoader:      NewDefaultGeoLoader(geoSiteFilename, geoIpFilename),
		geoSiteMatcher: make(map[string]hostMatcher),
		geoIpMatcher:   make(map[string]hostMatcher),
	}
}

func (g *GeoMatcher) MatchGeoIp(ip, condition string) bool {
	g.ipMatcherLock.Lock()
	defer g.ipMatcherLock.Unlock()

	matcher, ok := g.geoIpMatcher[condition]
	if !ok {
		// GeoIP matcher
		condition = strings.ToLower(condition)
		country := condition
		if len(country) == 0 {
			return false
		}
		gMap, err := g.geoLoader.LoadGeoIP()
		if err != nil {
			return false
		}
		list, ok := gMap[country]
		if !ok || list == nil {
			return false
		}
		matcher, err = newGeoIPMatcher(list)
		if err != nil {
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
		// MatchGeoSite matcher
		condition = strings.ToLower(condition)
		name, attrs := parseGeoSiteName(condition)
		if len(name) == 0 {
			return false
		}
		gMap, err := g.geoLoader.LoadGeoSite()
		if err != nil {
			return false
		}
		list, ok := gMap[name]
		if !ok || list == nil {
			return false
		}
		matcher, err = newGeositeMatcher(list, attrs)
		if err != nil {
			return false
		}
		g.geoSiteMatcher[condition] = matcher
	}
	return matcher.Match(HostInfo{Name: site})
}

func (g *GeoMatcher) LoadGeoSite() error {
	_, err := g.geoLoader.LoadGeoSite()
	return err
}

func (g *GeoMatcher) LoadGeoIP() error {
	_, err := g.geoLoader.LoadGeoIP()
	return err
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
