package tor

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
)

const (
	onionooUrl = "https://onionoo.torproject.org/details"
)

var _ TorDirectory = (*OnionooDirectory)(nil)

// Singleton instance
var onionooInstance *OnionooDirectory
var once sync.Once

func GetOnionooDirectory() (*OnionooDirectory, error) {
	var err error
	// Singleton initialization
	once.Do(func() {
		onionooInstance = &OnionooDirectory{
			directory: make(map[string]struct{}),
		}
		err = onionooInstance.Init()
	})
	return onionooInstance, err
}

type OnionooDirectory struct {
	directory map[string]struct{}
	sync.RWMutex
}

// example detail entry
// {..., "or_addresses":["195.15.242.99:9001","[2001:1600:10:100::201]:9001"], ...}

type OnionooDetail struct {
	OrAddresses []string `json:"or_addresses"`
}

type OnionooResponse struct {
	Relays []OnionooDetail `json:"relays"`
}

func (d *OnionooDirectory) Init() error {
	response, err := d.downloadDirectory(onionooUrl)
	if err != nil {
		return err
	}
	for _, relay := range response.Relays {
		for _, address := range relay.OrAddresses {
			ipStr, portStr, err := net.SplitHostPort(address)
			if err != nil {
				continue
			}
			ip := net.ParseIP(ipStr)
			port, err := strconv.ParseUint(portStr, 10, 16)
			if ip != nil && err == nil {
				d.Add(ip, uint16(port))
			}
		}
	}
	// TODO: log number of entries loaded
	return nil
}

func (d *OnionooDirectory) Add(ip net.IP, port uint16) {
	d.Lock()
	defer d.Unlock()
	addr := net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(port), 10))
	d.directory[addr] = struct{}{}
}

func (d *OnionooDirectory) Query(ip net.IP, port uint16) bool {
	d.RLock()
	defer d.RUnlock()
	addr := net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(port), 10))
	_, exists := d.directory[addr]
	return exists
}

func (d *OnionooDirectory) downloadDirectory(url string) (*OnionooResponse, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch onionoo data: status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var onionooResponse OnionooResponse
	err = json.Unmarshal(body, &onionooResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse onionoo json response: %s", err)
	}

	return &onionooResponse, nil
}
