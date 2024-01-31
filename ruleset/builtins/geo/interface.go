package geo

import (
	"fmt"
	"net"

	"github.com/apernet/OpenGFW/ruleset/builtins/geo/v2geo"
)

type HostInfo struct {
	Name string
	IPv4 net.IP
	IPv6 net.IP
}

func (h HostInfo) String() string {
	return fmt.Sprintf("%s|%s|%s", h.Name, h.IPv4, h.IPv6)
}

type GeoLoader interface {
	LoadGeoIP() (map[string]*v2geo.GeoIP, error)
	LoadGeoSite() (map[string]*v2geo.GeoSite, error)
}

type hostMatcher interface {
	Match(HostInfo) bool
}
