package dufu

import (
	"os"
	"syscall"
	"unsafe"
	"net"
)

const (
	IFF_TUN   = 0x0001
	IFF_TAP   = 0x0002
	IFF_NO_PI = 0x1000
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

// NewTAP creates a new tap device with the name
func NewTAP(name string) (*TapDevice, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	//  ifReq is a helper struct, to call TUNSETIFF ioctl
	req := struct {
		Name  [0x10]byte
		Flags uint16
		pad   [0x28 - 0x10 - 2]byte
	}{}
	req.Flags = IFF_TAP | IFF_NO_PI
	copy(req.Name[:], name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		err = errno
		return nil, err
	}
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.SIOCGIFHWADDR), uintptr(unsafe.Pointer(&req)))
	return &TapDevice{
		File: file,
	}, err
}

type TapDevice struct {
	net.HardwareAddr
	*os.File
}
