package udp

import (
	"errors"
	"net"

	"github.com/apernet/OpenGFW/modifier"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var _ modifier.Modifier = (*DNSModifier)(nil)

var (
	errInvalidIP           = errors.New("invalid ip")
	errNotValidDNSResponse = errors.New("not a valid dns response")
	errEmptyDNSQuestion    = errors.New("empty dns question")
)

type DNSModifier struct{}

func (m *DNSModifier) Name() string {
	return "dns"
}

func (m *DNSModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	i := &dnsModifierInstance{}
	aStr, ok := args["a"].(string)
	if ok {
		a := net.ParseIP(aStr).To4()
		if a == nil {
			return nil, &modifier.ErrInvalidArgs{Err: errInvalidIP}
		}
		i.A = a
	}
	aaaaStr, ok := args["aaaa"].(string)
	if ok {
		aaaa := net.ParseIP(aaaaStr).To16()
		if aaaa == nil {
			return nil, &modifier.ErrInvalidArgs{Err: errInvalidIP}
		}
		i.AAAA = aaaa
	}
	return i, nil
}

var _ modifier.UDPModifierInstance = (*dnsModifierInstance)(nil)

type dnsModifierInstance struct {
	A    net.IP
	AAAA net.IP
}

func (i *dnsModifierInstance) Process(data []byte) ([]byte, error) {
	dns := &layers.DNS{}
	err := dns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, &modifier.ErrInvalidPacket{Err: err}
	}
	if !dns.QR || dns.ResponseCode != layers.DNSResponseCodeNoErr {
		return nil, &modifier.ErrInvalidPacket{Err: errNotValidDNSResponse}
	}
	if len(dns.Questions) == 0 {
		return nil, &modifier.ErrInvalidPacket{Err: errEmptyDNSQuestion}
	}
	// In practice, most if not all DNS clients only send one question
	// per packet, so we don't care about the rest for now.
	q := dns.Questions[0]
	switch q.Type {
	case layers.DNSTypeA:
		if i.A != nil {
			dns.Answers = []layers.DNSResourceRecord{{
				Name:  q.Name,
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    i.A,
			}}
		}
	case layers.DNSTypeAAAA:
		if i.AAAA != nil {
			dns.Answers = []layers.DNSResourceRecord{{
				Name:  q.Name,
				Type:  layers.DNSTypeAAAA,
				Class: layers.DNSClassIN,
				IP:    i.AAAA,
			}}
		}
	}
	buf := gopacket.NewSerializeBuffer() // Modifiers must be safe for concurrent use, so we can't reuse the buffer
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, dns)
	return buf.Bytes(), err
}
