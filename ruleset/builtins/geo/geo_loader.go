package geo

import (
	"io"
	"net/http"
	"os"
	"time"

	"github.com/apernet/OpenGFW/ruleset/builtins/geo/v2geo"
)

const (
	geoipFilename   = "geoip.dat"
	geoipURL        = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
	geositeFilename = "geosite.dat"
	geositeURL      = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"

	geoDefaultUpdateInterval = 7 * 24 * time.Hour // 7 days
)

var _ GeoLoader = (*V2GeoLoader)(nil)

// V2GeoLoader provides the on-demand GeoIP/MatchGeoSite database
// loading functionality required by the ACL engine.
// Empty filenames = automatic download from built-in URLs.
type V2GeoLoader struct {
	GeoIPFilename   string
	GeoSiteFilename string
	UpdateInterval  time.Duration

	DownloadFunc    func(filename, url string)
	DownloadErrFunc func(err error)

	geoipMap   map[string]*v2geo.GeoIP
	geositeMap map[string]*v2geo.GeoSite
}

func NewDefaultGeoLoader(geoSiteFilename, geoIpFilename string) *V2GeoLoader {
	return &V2GeoLoader{
		GeoIPFilename:   geoIpFilename,
		GeoSiteFilename: geoSiteFilename,
		DownloadFunc:    func(filename, url string) {},
		DownloadErrFunc: func(err error) {},
	}
}

func (l *V2GeoLoader) shouldDownload(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return true
	}
	dt := time.Since(info.ModTime())
	if l.UpdateInterval == 0 {
		return dt > geoDefaultUpdateInterval
	} else {
		return dt > l.UpdateInterval
	}
}

func (l *V2GeoLoader) download(filename, url string) error {
	l.DownloadFunc(filename, url)

	resp, err := http.Get(url)
	if err != nil {
		l.DownloadErrFunc(err)
		return err
	}
	defer resp.Body.Close()

	f, err := os.Create(filename)
	if err != nil {
		l.DownloadErrFunc(err)
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	l.DownloadErrFunc(err)
	return err
}

func (l *V2GeoLoader) LoadGeoIP() (map[string]*v2geo.GeoIP, error) {
	if l.geoipMap != nil {
		return l.geoipMap, nil
	}
	autoDL := false
	filename := l.GeoIPFilename
	if filename == "" {
		autoDL = true
		filename = geoipFilename
	}
	if autoDL && l.shouldDownload(filename) {
		err := l.download(filename, geoipURL)
		if err != nil {
			return nil, err
		}
	}
	m, err := v2geo.LoadGeoIP(filename)
	if err != nil {
		return nil, err
	}
	l.geoipMap = m
	return m, nil
}

func (l *V2GeoLoader) LoadGeoSite() (map[string]*v2geo.GeoSite, error) {
	if l.geositeMap != nil {
		return l.geositeMap, nil
	}
	autoDL := false
	filename := l.GeoSiteFilename
	if filename == "" {
		autoDL = true
		filename = geositeFilename
	}
	if autoDL && l.shouldDownload(filename) {
		err := l.download(filename, geositeURL)
		if err != nil {
			return nil, err
		}
	}
	m, err := v2geo.LoadGeoSite(filename)
	if err != nil {
		return nil, err
	}
	l.geositeMap = m
	return m, nil
}
