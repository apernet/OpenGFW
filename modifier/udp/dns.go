package udp

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"math/rand/v2"
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

func (m *DNSModifier) New(args map[string][]interface{}) (modifier.Instance, error) {
	i := &dnsModifierInstance{}
	i.seed = rand.Uint32()
	for _, arg := range args["a"] {
		aStr, ok := arg.(string)
		if ok {
			a := net.ParseIP(aStr).To4()
			if a == nil {
				return nil, &modifier.ErrInvalidArgs{Err: errInvalidIP}
			}
			i.A = append(i.A, a)
		}
	}
	for _, arg := range args["aaaa"] {
		aaaaStr, ok := arg.(string)
		if ok {
			aaaa := net.ParseIP(aaaaStr).To16()
			if aaaa == nil {
				return nil, &modifier.ErrInvalidArgs{Err: errInvalidIP}
			}
			i.AAAA = append(i.AAAA, aaaa)
		}
	}
	return i, nil
}

var _ modifier.UDPModifierInstance = (*dnsModifierInstance)(nil)

type dnsModifierInstance struct {
	A    []net.IP
	AAAA []net.IP
	seed uint32
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

	// Hash the query name so that DNS response is fixed for a given query.
	// Use a random seed to avoid determinism.
	hashStringToIndex := func(b []byte, sliceLength int, seed uint32) int {
        h := fnv.New32a()
		seedBytes := make([]byte, 4)
        binary.LittleEndian.PutUint32(seedBytes, seed)
		h.Write(seedBytes)
        h.Write(b)
        hashValue := h.Sum32()
        return int(hashValue % uint32(sliceLength))
    }

	// In practice, most if not all DNS clients only send one question
	// per packet, so we don't care about the rest for now.
	q := dns.Questions[0]
	switch q.Type {
	case layers.DNSTypeA:
		if i.A != nil {
			idx := hashStringToIndex(q.Name, len(i.A), i.seed)
			dns.Answers = []layers.DNSResourceRecord{{
				Name:  q.Name,
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    i.A[idx],
			}}
		}
	case layers.DNSTypeAAAA:
		if i.AAAA != nil {
			idx := hashStringToIndex(q.Name, len(i.AAAA), i.seed)
			dns.Answers = []layers.DNSResourceRecord{{
				Name:  q.Name,
				Type:  layers.DNSTypeAAAA,
				Class: layers.DNSClassIN,
				IP:    i.AAAA[idx],
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
