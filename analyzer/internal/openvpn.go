package internal

// Ref paper:
// https://www.usenix.org/system/files/sec22fall_xue-diwen.pdf

// OpenVPN Opcodes definitions from:
// https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/ssl_pkt.h
const (
	OpenVpnControlHardResetClientV1 = 1
	OpenVpnControlHardResetServerV1 = 2
	OpenVpnControlSoftResetV1       = 3
	OpenVpnControlV1                = 4
	OpenVpnAckV1                    = 5
	OpenVpnDataV1                   = 6
	OpenVpnControlHardResetClientV2 = 7
	OpenVpnControlHardResetServerV2 = 8
	OpenVpnDataV2                   = 9
	OpenVpnControlHardResetClientV3 = 10
	OpenVpnControlWkcV1             = 11
)

const (
	OpenVpnMinPktLen          = 6
	OpenVpnTcpPktDefaultLimit = 256
	OpenVpnUdpPktDefaultLimit = 256
)

func OpenVpnCheckForValidOpcode(opcode byte) bool {
	switch opcode {
	case OpenVpnControlHardResetClientV1,
		OpenVpnControlHardResetServerV1,
		OpenVpnControlSoftResetV1,
		OpenVpnControlV1,
		OpenVpnAckV1,
		OpenVpnDataV1,
		OpenVpnControlHardResetClientV2,
		OpenVpnControlHardResetServerV2,
		OpenVpnDataV2,
		OpenVpnControlHardResetClientV3,
		OpenVpnControlWkcV1:
		return true
	}
	return false
}
