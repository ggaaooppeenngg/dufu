package dufu

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	IPv4ProtocolNumber = 0x0800
	IPv6ProtocolNumber = 0x86DD
)

// IPv4
type IPv4 []byte

// Version returns IPv4 version, it's always 4.
func (b IPv4) Version() uint8     { return uint8(b[0] >> 4) }
func (b IPv4) SetVersion(v uint8) { b[0] = (b[0] & 0x0f) | (v << 4) }

// HeaderLength returns IPv4 headerlength, it's unit is 4.
func (b IPv4) HeaderLength() uint8     { return uint8(b[0]) & 0xf }
func (b IPv4) SetHeaderLength(l uint8) { b[0] = (b[0] & 0xf0) | (l & 0xf) }

// ToS returns IPv4 type of service.
func (b IPv4) ToS() uint8       { return uint8(b[1]) }
func (b IPv4) SetToS(tos uint8) { b[1] = tos; return }

// TotalLength returns the total length of the IPv4 header and payload.
func (b IPv4) TotalLength() uint16        { return binary.BigEndian.Uint16(b[2:4]) }
func (b IPv4) SetTotalLength(totl uint16) { binary.BigEndian.PutUint16(b[2:4], totl); return }

// Identification returns identification of the IPv4 header.
func (b IPv4) Identification() uint16 { return binary.BigEndian.Uint16(b[4:6]) }

// SetIdentification sets packet ID for this IPv4 packet.
func (b IPv4) SetIdentification(id uint16) { binary.BigEndian.PutUint16(b[4:6], id) }

// flagsOffset returns flags and offset filed of the header.
func (b IPv4) FlagsOffset() uint16 { return binary.BigEndian.Uint16(b[6:8]) }

// Flags returns segmentation flags of the header.
func (b IPv4) Flags() uint8 { return uint8(b.FlagsOffset() >> 13) }

// FragmentOffset returns offset of the IP fragment.
func (b IPv4) FragmentOffset() uint16 { return uint16(b.FlagsOffset()) }

// TTL returns the time to live.
func (b IPv4) TTL() uint8       { return uint8(b[8]) }
func (b IPv4) SetTTL(ttl uint8) { b[8] = byte(ttl); return }

// Protocol returns the protocol used in the data portion.
func (b IPv4) Protocol() uint8     { return uint8(b[9]) }
func (b IPv4) SetProtocol(p uint8) { b[9] = byte(p) }

// Checksum returns header checksum.
func (b IPv4) Checksum() uint16       { return binary.BigEndian.Uint16(b[10:12]) }
func (b IPv4) SetChecksum(cks uint16) { binary.BigEndian.PutUint16(b[10:12], cks) }

// SourceAddress returns IP source address.
func (b IPv4) SourceAddress() []byte { return b[12:16] }

// DestinationAddress returns IP destination address.
func (b IPv4) DestinationAddress() []byte { return b[16:20] }
func (b IPv4) Message() []byte            { return b[b.HeaderLength()*4:] }

// L3Layer is a IP layer.
type L3Layer struct {
	*L2Layer
	*linkAddrCache
}

var L3 *L3Layer

func NewL3Layer(l2 *L2Layer) *L3Layer {
	return &L3{
		l2,
		newLinkAddrCache(time.Minute),
	}
}

// IPHandle handles IP packet.
func (l3 *L3Layer) IPRcv(l2l *L2Layer, skb *SkBuff) {
	ip := IPv4(skb.Data())
	fmt.Printf("IP Protocol 0x%x\n", ip.Protocol())
	fmt.Printf("Header Length %d\n", ip.HeaderLength())
	fmt.Printf("Header Checksum 0x%x\n", ip.Checksum())
	fmt.Printf("IPv4 Checksum 0x%x\n", ipv4Checksum(ip[:ip.HeaderLength()*4]))
	if ip.Protocol() == ICMPv4ProtocolNumber {
		ICMPRcv(l3, ip)
	}
}

func (l3 *L3Layer) IPSend(skb *SkBuff) {
	// assume up layer has set the destination address and source address.
	ip := IPv4(skb.Data())
	ip.SetVersion(4)
	ip.SetTotalLength(uint16(len(skb.Data())))
	ip.SetIdentification(uint16(IpSelectIdent(ip)))
	sh := l3.linkAddrCache.get([4]byte(ip.SourceAddrss()))
	dh := l3.linkAddrCache.get([4]byte(ip.DestinationAddress()))

}

// ipv4Checksum get buf checksum based on rfc1071
func ipv4Checksum(buf []byte) uint16 {
	var sum uint32
	count := len(buf)
	for i := 0; count > 1; i += 2 {
		sum += uint32(buf[i])<<8 + uint32(buf[i+1])
		count -= 2
	}
	if count > 0 {
		sum += uint32(buf[len(buf)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + (sum >> 16)
	}
	return ^uint16(sum)
}
