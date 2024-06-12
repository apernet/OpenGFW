package tor

import "net"

type TorDirectory interface {
	Init() error
	Add(ip net.IP, port uint16)
	Query(ip net.IP, port uint16) bool
}
