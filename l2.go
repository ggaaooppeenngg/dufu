package dufu

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	MaxFrameSize      = 1526 // max frame size
	EthMACAddressSize = 6
	EthEtherTypeSize  = 2
	EthHeaderSize     = EthEtherTypeSize + 2*EthMACAddressSize
)

type L2Layer struct {
	*TapDevice
}

func NewL2Layer(tap *TapDevice) {
	l2 := &dufu.L2Layer{TapDevice: tap}
	go l2.Loop()
}

// Link layer frame
type Frame []byte

//  Destination is the mac destination address.
func (f Frame) Destination() []byte { return f[0:6] }

// Source is the mac source address.
func (f Frame) Source() []byte { return f[6:12] }

//  EtherType is the ethernet type.
func (f Frame) EtherType() []byte { return f[12:14] }

// Packet returns frame payload.
func (f Frame) Packet() []byte { return f[14:] }

func (l2l *L2Layer) Read() (*SkBuff, error) {
	var (
		buf [MaxFrameSize]byte
	)

	n, err := l2l.TapDevice.Read(buf[:])
	if err != nil {
		return nil, err
	}
	return &SkBuff{buf: buf[:n]}, nil
}

func (l2l *L2Layer) Loop() {
	for {
		skb, err := l2l.Read()
		if err != nil {
			fmt.Println(err)
			continue
		}
		frame := Frame(skb.Data())
		fmt.Println("source", net.HardwareAddr(frame.Source()), "dest", net.HardwareAddr(frame.Destination()))
		fmt.Printf("0x%.4x\n", binary.BigEndian.Uint16(frame.EtherType()))
		if binary.BigEndian.Uint16(frame.EtherType()) == ARPProtocolNumber {
			skb.TrimFront(EthHeaderSize)
			ARPHandle(l2l, skb)
		}
		if binary.BigEndian.Uint16(frame.EtherType()) == 4 {
			skb.TrimFront(EthHeaderSize)
			(&L3Layer{}).IPRcv(l2l, skb)
		}
	}
}

func (l2l *L2Layer) Send(frame Frame) {
	_, err := l2l.TapDevice.Write([]byte(frame))
	if err != nil {
		panic(err)
	}
}
