package internal

import (
	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

// TLS record types.
const (
	RecordTypeHandshake = 0x16
)

// TLS handshake message types.
const (
	TypeClientHello = 0x01
	TypeServerHello = 0x02
)

// TLS extension numbers.
const (
	extServerName           = 0x0000
	extALPN                 = 0x0010
	extSupportedVersions    = 0x002b
	extEncryptedClientHello = 0xfe0d
)

func ParseTLSClientHelloMsgData(chBuf *utils.ByteBuffer) analyzer.PropMap {
	var ok bool
	m := make(analyzer.PropMap)
	// Version, random & session ID length combined are within 35 bytes,
	// so no need for bounds checking
	m["version"], _ = chBuf.GetUint16(false, true)
	m["random"], _ = chBuf.Get(32, true)
	sessionIDLen, _ := chBuf.GetByte(true)
	m["session"], ok = chBuf.Get(int(sessionIDLen), true)
	if !ok {
		// Not enough data for session ID
		return nil
	}
	cipherSuitesLen, ok := chBuf.GetUint16(false, true)
	if !ok {
		// Not enough data for cipher suites length
		return nil
	}
	if cipherSuitesLen%2 != 0 {
		// Cipher suites are 2 bytes each, so must be even
		return nil
	}
	ciphers := make([]uint16, cipherSuitesLen/2)
	for i := range ciphers {
		ciphers[i], ok = chBuf.GetUint16(false, true)
		if !ok {
			return nil
		}
	}
	m["ciphers"] = ciphers
	compressionMethodsLen, ok := chBuf.GetByte(true)
	if !ok {
		// Not enough data for compression methods length
		return nil
	}
	// Compression methods are 1 byte each, we just put a byte slice here
	m["compression"], ok = chBuf.Get(int(compressionMethodsLen), true)
	if !ok {
		// Not enough data for compression methods
		return nil
	}
	extsLen, ok := chBuf.GetUint16(false, true)
	if !ok {
		// No extensions, I guess it's possible?
		return m
	}
	extBuf, ok := chBuf.GetSubBuffer(int(extsLen), true)
	if !ok {
		// Not enough data for extensions
		return nil
	}
	for extBuf.Len() > 0 {
		extType, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension type
			return nil
		}
		extLen, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension length
			return nil
		}
		extDataBuf, ok := extBuf.GetSubBuffer(int(extLen), true)
		if !ok || !parseTLSExtensions(extType, extDataBuf, m) {
			// Not enough data for extension data, or invalid extension
			return nil
		}
	}
	return m
}

func ParseTLSServerHelloMsgData(shBuf *utils.ByteBuffer) analyzer.PropMap {
	var ok bool
	m := make(analyzer.PropMap)
	// Version, random & session ID length combined are within 35 bytes,
	// so no need for bounds checking
	m["version"], _ = shBuf.GetUint16(false, true)
	m["random"], _ = shBuf.Get(32, true)
	sessionIDLen, _ := shBuf.GetByte(true)
	m["session"], ok = shBuf.Get(int(sessionIDLen), true)
	if !ok {
		// Not enough data for session ID
		return nil
	}
	cipherSuite, ok := shBuf.GetUint16(false, true)
	if !ok {
		// Not enough data for cipher suite
		return nil
	}
	m["cipher"] = cipherSuite
	compressionMethod, ok := shBuf.GetByte(true)
	if !ok {
		// Not enough data for compression method
		return nil
	}
	m["compression"] = compressionMethod
	extsLen, ok := shBuf.GetUint16(false, true)
	if !ok {
		// No extensions, I guess it's possible?
		return m
	}
	extBuf, ok := shBuf.GetSubBuffer(int(extsLen), true)
	if !ok {
		// Not enough data for extensions
		return nil
	}
	for extBuf.Len() > 0 {
		extType, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension type
			return nil
		}
		extLen, ok := extBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for extension length
			return nil
		}
		extDataBuf, ok := extBuf.GetSubBuffer(int(extLen), true)
		if !ok || !parseTLSExtensions(extType, extDataBuf, m) {
			// Not enough data for extension data, or invalid extension
			return nil
		}
	}
	return m
}

func parseTLSExtensions(extType uint16, extDataBuf *utils.ByteBuffer, m analyzer.PropMap) bool {
	switch extType {
	case extServerName:
		ok := extDataBuf.Skip(2) // Ignore list length, we only care about the first entry for now
		if !ok {
			// Not enough data for list length
			return false
		}
		sniType, ok := extDataBuf.GetByte(true)
		if !ok || sniType != 0 {
			// Not enough data for SNI type, or not hostname
			return false
		}
		sniLen, ok := extDataBuf.GetUint16(false, true)
		if !ok {
			// Not enough data for SNI length
			return false
		}
		m["sni"], ok = extDataBuf.GetString(int(sniLen), true)
		if !ok {
			// Not enough data for SNI
			return false
		}
	case extALPN:
		ok := extDataBuf.Skip(2) // Ignore list length, as we read until the end
		if !ok {
			// Not enough data for list length
			return false
		}
		var alpnList []string
		for extDataBuf.Len() > 0 {
			alpnLen, ok := extDataBuf.GetByte(true)
			if !ok {
				// Not enough data for ALPN length
				return false
			}
			alpn, ok := extDataBuf.GetString(int(alpnLen), true)
			if !ok {
				// Not enough data for ALPN
				return false
			}
			alpnList = append(alpnList, alpn)
		}
		m["alpn"] = alpnList
	case extSupportedVersions:
		if extDataBuf.Len() == 2 {
			// Server only selects one version
			m["supported_versions"], _ = extDataBuf.GetUint16(false, true)
		} else {
			// Client sends a list of versions
			ok := extDataBuf.Skip(1) // Ignore list length, as we read until the end
			if !ok {
				// Not enough data for list length
				return false
			}
			var versions []uint16
			for extDataBuf.Len() > 0 {
				ver, ok := extDataBuf.GetUint16(false, true)
				if !ok {
					// Not enough data for version
					return false
				}
				versions = append(versions, ver)
			}
			m["supported_versions"] = versions
		}
	case extEncryptedClientHello:
		// We can't parse ECH for now, just set a flag
		m["ech"] = true
	}
	return true
}
