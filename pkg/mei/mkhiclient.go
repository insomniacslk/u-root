package mei

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	txtsuite "github.com/9elements/txt-suite/pkg/api"
	"github.com/jaypipes/ghw"
)

// Intel MEI PCI dev IDs,
// from https://elixir.bootlin.com/linux/latest/source/drivers/misc/mei/hw-me-regs.h
var meiDevIDs = map[string]uint{
	// awk '/MEI_DEV_ID/ {print "\t\"" $2 "\": " $3 ","}' hw-me-regs.h
	"MEI_DEV_ID_82946GZ":    0x2974,
	"MEI_DEV_ID_82G35":      0x2984,
	"MEI_DEV_ID_82Q965":     0x2994,
	"MEI_DEV_ID_82G965":     0x29A4,
	"MEI_DEV_ID_82GM965":    0x2A04,
	"MEI_DEV_ID_82GME965":   0x2A14,
	"MEI_DEV_ID_ICH9_82Q35": 0x29B4,
	"MEI_DEV_ID_ICH9_82G33": 0x29C4,
	"MEI_DEV_ID_ICH9_82Q33": 0x29D4,
	"MEI_DEV_ID_ICH9_82X38": 0x29E4,
	"MEI_DEV_ID_ICH9_3200":  0x29F4,
	"MEI_DEV_ID_ICH9_6":     0x28B4,
	"MEI_DEV_ID_ICH9_7":     0x28C4,
	"MEI_DEV_ID_ICH9_8":     0x28D4,
	"MEI_DEV_ID_ICH9_9":     0x28E4,
	"MEI_DEV_ID_ICH9_10":    0x28F4,
	"MEI_DEV_ID_ICH9M_1":    0x2A44,
	"MEI_DEV_ID_ICH9M_2":    0x2A54,
	"MEI_DEV_ID_ICH9M_3":    0x2A64,
	"MEI_DEV_ID_ICH9M_4":    0x2A74,
	"MEI_DEV_ID_ICH10_1":    0x2E04,
	"MEI_DEV_ID_ICH10_2":    0x2E14,
	"MEI_DEV_ID_ICH10_3":    0x2E24,
	"MEI_DEV_ID_ICH10_4":    0x2E34,
	"MEI_DEV_ID_IBXPK_1":    0x3B64,
	"MEI_DEV_ID_IBXPK_2":    0x3B65,
	"MEI_DEV_ID_CPT_1":      0x1C3A,
	"MEI_DEV_ID_PBG_1":      0x1D3A,
	"MEI_DEV_ID_PPT_1":      0x1E3A,
	"MEI_DEV_ID_PPT_2":      0x1CBA,
	"MEI_DEV_ID_PPT_3":      0x1DBA,
	"MEI_DEV_ID_LPT_H":      0x8C3A,
	"MEI_DEV_ID_LPT_W":      0x8D3A,
	"MEI_DEV_ID_LPT_LP":     0x9C3A,
	"MEI_DEV_ID_LPT_HR":     0x8CBA,
	"MEI_DEV_ID_WPT_LP":     0x9CBA,
	"MEI_DEV_ID_WPT_LP_2":   0x9CBB,
	"MEI_DEV_ID_SPT":        0x9D3A,
	"MEI_DEV_ID_SPT_2":      0x9D3B,
	"MEI_DEV_ID_SPT_H":      0xA13A,
	"MEI_DEV_ID_SPT_H_2":    0xA13B,
	"MEI_DEV_ID_LBG":        0xA1BA,
	"MEI_DEV_ID_BXT_M":      0x1A9A,
	"MEI_DEV_ID_APL_I":      0x5A9A,
	"MEI_DEV_ID_DNV_IE":     0x19E5,
	"MEI_DEV_ID_GLK":        0x319A,
	"MEI_DEV_ID_KBP":        0xA2BA,
	"MEI_DEV_ID_KBP_2":      0xA2BB,
	"MEI_DEV_ID_CNP_LP":     0x9DE0,
	"MEI_DEV_ID_CNP_LP_4":   0x9DE4,
	"MEI_DEV_ID_CNP_H":      0xA360,
	"MEI_DEV_ID_CNP_H_4":    0xA364,
	"MEI_DEV_ID_CMP_LP":     0x02e0,
	"MEI_DEV_ID_CMP_LP_3":   0x02e4,
	"MEI_DEV_ID_CMP_V":      0xA3BA,
	"MEI_DEV_ID_CMP_H":      0x06e0,
	"MEI_DEV_ID_CMP_H_3":    0x06e4,
	"MEI_DEV_ID_CDF":        0x18D3,
	"MEI_DEV_ID_ICP_LP":     0x34E0,
	"MEI_DEV_ID_JSP_N":      0x4DE0,
	"MEI_DEV_ID_TGP_LP":     0xA0E0,
	"MEI_DEV_ID_MCC":        0x4B70,
	"MEI_DEV_ID_MCC_4":      0x4B75,
}

// MKHIClient is a client to send MKHI commands via MEI.
type MKHIClient struct {
	MEI MEI
}

// MKHI command groups, see
// https://github.com/coreboot/coreboot/blob/b8b8ec832360ada5a313f10938bb6cfc310a11eb/src/soc/intel/common/block/include/intelblocks/cse.h#L22
const (
	MKHIGroupIDCbm    = 0x0
	MKHIGroupIDHmrfpo = 0x5
	MKHIGroupIDGen    = 0xff
)

// MKHI HMRFPO command IDs, see
// https://github.com/coreboot/coreboot/blob/b8b8ec832360ada5a313f10938bb6cfc310a11eb/src/soc/intel/common/block/include/intelblocks/cse.h#L33
const (
	MKHIHmrfpoEnable    = 0x1
	MKHIHmrfpoGetStatus = 0x3
	MKHIGetEOPState     = 0x1d
)

// pciAddressToInt converts the last part of a PCI address string to integer,
// e.g. 0000:00:16.0 will return 0x16 .
func pciAddressToInt(pciaddr string) (int, error) {
	parts := strings.Split(pciaddr, ":")
	if len(parts) != 3 {
		return 0, fmt.Errorf("wrong PCI address string '%s': want 3 colon-separated groups, got %d", pciaddr, len(parts))
	}
	parts = strings.Split(parts[2], ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("wrong PCI address sub-component '%s': want 2 dot-separated groups, got %d", pciaddr, len(parts))
	}
	a, err := strconv.ParseInt(parts[0], 16, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse hex string '%s': %w", parts[0], err)
	}
	return int(a), nil
}

// IsHmrfpoEnableAllowed queries whether the HMRFPO enable is allowed.
func (m MKHIClient) IsHmrfpoEnableAllowed() (bool, error) {
	/* This is a reimplementation of cse_is_hmrfpo_enable_allowed from
	 * coreboot/src/soc/intel/common/block/cse/cse.c . The below comment also
	 * comes from that function.
	 *
	 * Allow sending HMRFPO ENABLE command only if:
	 *  - CSE's current working state is Normal and current operation mode is Normal
	 *  - (or) cse's current working state is normal and current operation mode is
	 *    Soft Temp Disable if CSE's Firmware SKU is Custom
	 *
	 */
	meiDev, err := GetMeiPciDevice()
	if err != nil {
		return false, fmt.Errorf("failed to get PCI MEI device: %w", err)
	}
	log.Printf("MEI Device found: %s", meiDev)
	intelBusID := 0
	intelMEDeviceID, err := pciAddressToInt(meiDev.Address)
	if err != nil {
		return false, fmt.Errorf("failed to parse MEI product ID: %w", err)
	}
	// usually 0. Any better way to discover this dynamically?
	intelMEDevFn := 0

	// check that CSE's current working state is normal
	cs, err := txtsuite.PCIReadConfig32(intelBusID, int(intelMEDeviceID), intelMEDevFn, 0x40 /* PCI_ME_HFSTS1 */)
	if err != nil {
		return false, fmt.Errorf("PCIReadConfig32 failed: %w", err)
	}
	// check that the current working state is ME_HFS1_CWS_NORMAL (0x05) and
	// current operation mode is ME_HFS1_COM_NORMAL (0x0).
	// `working_state` is bits 1-4 and `operation_state` is bits 7-9.
	// FIXME validate this code against the logic in this function's top
	// comment.
	if (cs&0xf) != 0x05 || ((cs>>6)&0x7) != 0x0 {
		return false, nil
	}
	// check that CSE's firmware SKU is not custom, and if it is, that the
	// current operation mode is Soft Temp Disable.
	cs, err = txtsuite.PCIReadConfig32(intelBusID, int(intelMEDeviceID), intelMEDevFn, 0x60 /* PCI_ME_HFSTS3 */)
	if err != nil {
		return false, fmt.Errorf("PCIReadConfig32 failed: %w", err)
	}
	// fw_sku is in bits 5-7 . ME_HFS3_FW_SKU_CUSTOM is 0x5
	if (cs>>4)&0x7 == 0x5 {
		// TODO implement the same as coreboot's cse_is_hfs1_com_soft_temp_disable()
		return false, errors.New("IsHmrfpoEnableAllowed does not support checking for Soft Temp Disable yet")
	}
	return true, nil
}

type hmrfpoEnableMsg struct {
	header MKHIHdr
	nonce  uint32
}

type getEOPStateMsg struct {
	header MKHIHdr
	nonce  uint32
}

func (hem hmrfpoEnableMsg) ToBytes() []byte {
	var buf []byte
	buf = append(buf, hem.header[:]...)
	var nonce [4]byte
	binary.LittleEndian.PutUint32(nonce[:], hem.nonce)
	return append(buf, nonce[:]...)
}

func (gesm getEOPStateMsg) ToBytes() []byte {
	var buf []byte
	buf = append(buf, gesm.header[:]...)
	var nonce [4]byte
	binary.LittleEndian.PutUint32(nonce[:], gesm.nonce)
	return append(buf, nonce[:]...)
}

type hmrfpoEnableResponse struct {
	Header   MKHIHdr
	FctBase  uint32
	FctLimit uint32
	Status   uint8
	reserved [3]byte
}

type getEOPStateResponse struct {
	Header   MKHIHdr
	Status   uint8
	reserved [3]byte
}

func hmrfpoEnableResponseFromBytes(b []byte) (*hmrfpoEnableResponse, error) {
	var resp hmrfpoEnableResponse
	minlen := len(resp.Header)
	maxlen := minlen +
		4 /* FctBase */ +
		4 /* FctLimit */ +
		1 /* Status */ +
		3 /* reserved bytes */
	if len(b) != minlen && len(b) != maxlen {
		return nil, fmt.Errorf("size mismatch, want %d/%d bytes, got %d", minlen, maxlen, len(b))
	}
	copy(resp.Header[:], b[:4])
	if len(b) == minlen {
		// don't parse the rest, we got a partial response
		return &resp, nil
	}
	// TODO this could use u-root's pkg/uio
	resp.FctBase = binary.LittleEndian.Uint32(b[4:8])
	resp.FctLimit = binary.LittleEndian.Uint32(b[8:12])
	resp.Status = b[12]
	return &resp, nil
}

func getEOPStateResponseFromBytes(b []byte) (*getEOPStateResponse, error) {
	var resp getEOPStateResponse
	minlen := len(resp.Header)
	maxlen := minlen +
		1 /* Status */ +
		3 /* reserved bytes */
	if len(b) != minlen && len(b) != maxlen {
		return nil, fmt.Errorf("size mismatch, want %d/%d bytes, got %d", minlen, maxlen, len(b))
	}
	copy(resp.Header[:], b[:4])
	if len(b) == minlen {
		// don't parse the rest, we got a partial response
		return &resp, nil
	}
	// TODO this could use u-root's pkg/uio
	resp.Status = b[4]
	return &resp, nil
}

// HmrfpoEnable enables the HMRFPO (Host ME Region Flash Protection Override) via CSE,
// see cse_hmrfpo_enable at
// https://github.com/coreboot/coreboot/blob/b8b8ec832360ada5a313f10938bb6cfc310a11eb/src/soc/intel/common/block/include/intelblocks/cse.h#L64
func (m MKHIClient) HmrfpoEnable() error {

	var hdr MKHIHdr
	hdr.SetGroupID(MKHIGroupIDHmrfpo)
	hdr.SetCommand(MKHIHmrfpoEnable)
	canEnable, err := m.IsHmrfpoEnableAllowed()
	if err != nil {
		return fmt.Errorf("Enabling HMRFPO failed: %w", err)
	}
	if !canEnable {
		return fmt.Errorf("Enabling HMRFPO is not allowed")
	}
	msg := hmrfpoEnableMsg{
		header: hdr,
		nonce:  0,
	}
	if _, err := m.MEI.Write(msg.ToBytes()); err != nil {
		return fmt.Errorf("write to MEI failed: %w", err)
	}
	// TODO get the size value from the client properties returned by MEI.OpenMKHI
	buf := make([]byte, 2048)
	n, err := m.MEI.Read(buf)
	if err != nil {
		return fmt.Errorf("read from MEI failed: %w", err)
	}
	resp, err := hmrfpoEnableResponseFromBytes(buf[:n])
	if err != nil {
		return fmt.Errorf("failed to parse HMRFPOEnableResponse: %w", err)
	}
	// TODO remove these debug prints
	log.Printf("GroupID   : %d", resp.Header.GroupID())
	log.Printf("Command   : %d", resp.Header.Command())
	log.Printf("IsResponse: %v", resp.Header.IsResponse())
	log.Printf("RSVD      : %d", resp.Header.RSVD())
	log.Printf("Result    : %d", resp.Header.Result())
	if resp.Header.Result() != 0 {
		return fmt.Errorf("failed to enable HMRFPO, request result is 0x%02x, want 0x0", resp.Header.Result())
	}
	if resp.Status != 0 {
		return fmt.Errorf("failed to enable HMRFPO, request status is 0x%02x, want 0x0", resp.Status)
	}
	return nil
}

// GetMeiPciDevice will return the MEI PCI device object after scanning the PCI
// bus.
func GetMeiPciDevice() (*ghw.PCIDevice, error) {
	pci, err := ghw.PCI()
	if err != nil {
		return nil, fmt.Errorf("failed to get PCI devices: %w", err)
	}
	for _, device := range pci.ListDevices() {
		// look for vendor ID 8086 (Intel)
		if device.Vendor.ID != "8086" {
			continue
		}
		productID, err := strconv.ParseInt(device.Product.ID, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse device ID '%s' as hex: %w", device.Product.ID, err)
		}
		// look for a known MEI product ID
		for _, devID := range meiDevIDs {
			if int64(devID) == productID {
				// there is only one MEI device, right?
				return device, nil
			}
		}
	}
	return nil, errors.New("no MEI device found")
}

func (m MKHIClient) GetEOPState() error {
	var hdr MKHIHdr
	hdr.SetGroupID(MKHIGroupIDGen)
	hdr.SetCommand(MKHIGetEOPState)
	msg := getEOPStateMsg{
		header: hdr,
		nonce:  0,
	}
	if _, err := m.MEI.Write(msg.ToBytes()); err != nil {
		return fmt.Errorf("write to MEI failed: %w", err)
	}
	// TODO get the size value from the client properties returned by MEI.OpenMKHI
	buf := make([]byte, 2048)
	n, err := m.MEI.Read(buf)
	if err != nil {
		return fmt.Errorf("read from MEI failed: %w", err)
	}
	resp, err := getEOPStateResponseFromBytes(buf[:n])
	if err != nil {
		return fmt.Errorf("failed to parse GetEOPStateResponse: %w", err)
	}
	// TODO remove these debug prints
	log.Printf("GroupID   : %d", resp.Header.GroupID())
	log.Printf("Command   : %d", resp.Header.Command())
	log.Printf("IsResponse: %v", resp.Header.IsResponse())
	log.Printf("RSVD      : %d", resp.Header.RSVD())
	log.Printf("Result    : %d", resp.Header.Result())
	if resp.Header.Result() != 0 {
		return fmt.Errorf("failed to get EOP status, request result is 0x%02x, want 0x0", resp.Header.Result())
	}
	log.Printf("EOP Status: %d\n", resp.Status)

	return nil
}
