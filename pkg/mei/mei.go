package mei

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	ioctl "github.com/vtolstov/go-ioctl"
)

// DefaultMEIDevicePath is the path of the default MEI device. This file will be
// present if the "mei_me" kernel module is loaded.
var DefaultMEIDevicePath = "/dev/mei0"

// HECIGuids maps the known HECI GUIDs to their values. The MEI interface wants
// little-endian. See all the GUIDs at
// https://github.com/intel/lms/blob/master/MEIClient/Include/HECI_if.h
var (
	// "8e6a6715-9abc-4043-88ef-9e39c6f63e0f"
	MKHIGuid = ClientGUID{0x15, 0x67, 0x6a, 0x8e, 0xbc, 0x9a, 0x43, 0x40, 0x88, 0xef, 0x9e, 0x39, 0xc6, 0xf6, 0x3e, 0xf}
)

// see include/uapi/linux/mei.h
var (
	IoctlMEIConnectClient = ioctl.IOWR('H', 0x01, uintptr(len(ClientGUID{})))
)

// ClientGUID is the data buffer to pass to `ioctl` to connect to
// MEI. See include/uapi/linux/mei.h .
type ClientGUID [16]byte

// ClientProperties is the data buffer returned by `ioctl` after connecting to
// MEI. See include/uapi/linux/mei.h .
type ClientProperties [6]byte

// MaxMsgLength is the maximum size of a message for this client.
func (c ClientProperties) MaxMsgLength() uint32 {
	return binary.LittleEndian.Uint32(c[:4])
}

// ProtocolVersion is this client's protocol version.
func (c ClientProperties) ProtocolVersion() uint8 {
	return c[4]
}

// MEI represents an Intel ME Interface object.
type MEI struct {
	fd *os.File
}

// OpenMKHI opens the specified MEI device using the MKHI client GUID.
func (m *MEI) OpenMKHI(meiPath string) (*ClientProperties, error) {
	return m.open(meiPath, MKHIGuid)
}

// open opens the specified MEI device, using the client type defined by the
// given name. See `HECIGuids` in this package.
func (m *MEI) open(meiPath string, guid ClientGUID) (*ClientProperties, error) {
	fd, err := os.OpenFile(meiPath, os.O_RDWR, 0755)
	if err != nil {
		return nil, err
	}
	data := [16]byte(guid)
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), IoctlMEIConnectClient, uintptr(unsafe.Pointer(&data))); err != 0 {
		return nil, fmt.Errorf("ioctl IOCTL_MEI_CONNECT_CLIENT failed: %w", err)
	}
	// can be racy, unless protected by a mutex
	m.fd = fd
	var cp ClientProperties
	copy(cp[:], data[:])
	return &cp, nil
}

// Close closes the MEI device, if open, and does nothing otherwise.
func (m *MEI) Close() error {
	if m.fd != nil {
		err := m.fd.Close()
		m.fd = nil
		return err
	}
	return nil
}

// Write writes to the MEI file descriptor.
func (m *MEI) Write(p []byte) (int, error) {
	return m.fd.Write(p)
}

// Read reads from the MEI file descriptor.
func (m *MEI) Read(p []byte) (int, error) {
	return m.fd.Read(p)
}
