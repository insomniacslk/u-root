// Copyright 2020 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mei

// this file contains a few ioctl-related constants and reimplementations of
// macros from Linux's include/uapi/asm-generic/ioctl.h .

const (
	IOC_NRBITS   = 8
	IOC_TYPEBITS = 8
	IOC_SIZEBITS = 14
	IOC_DIRBITS  = 2

	IOC_NRMASK   = (1 << IOC_NRBITS) - 1
	IOC_TYPEMASK = (1 << IOC_TYPEBITS) - 1
	IOC_SIZEMASK = (1 << IOC_SIZEBITS) - 1
	IOC_DIRMASK  = (1 << IOC_DIRBITS) - 1

	IOC_NRSHIFT   = 0
	IOC_TYPESHIFT = (IOC_NRSHIFT + IOC_NRBITS)
	IOC_SIZESHIFT = (IOC_TYPESHIFT + IOC_TYPEBITS)
	IOC_DIRSHIFT  = (IOC_SIZESHIFT + IOC_SIZEBITS)

	IOC_NONE  = 0x0
	IOC_WRITE = 0x1
	IOC_READ  = 0x2
)

// IOC is an implementation of Linux's _IOC macro.
func IOC(dir, typ, nr, size uintptr) uintptr {
	return (dir << IOC_DIRSHIFT) |
		(typ << IOC_TYPESHIFT) |
		(nr << IOC_NRSHIFT) |
		(size << IOC_SIZESHIFT)
}

// IO is an implementation of Linux's _IO macro.
func IO(typ, nr, size uintptr) uintptr {
	return IOC(IOC_NONE, typ, nr, size)
}

// IOR is an implementation of Linux's _IOR macro.
func IOR(typ, nr, size uintptr) uintptr {
	return IOC(IOC_READ, typ, nr, size)
}

// IOW is an implementation of Linux's _IOW macro.
func IOW(typ, nr, size uintptr) uintptr {
	return IOC(IOC_WRITE, typ, nr, size)
}

// IOWR is an implementation of Linux's _IOWR macro.
func IOWR(typ, nr, size uintptr) uintptr {
	return IOC(IOC_READ|IOC_WRITE, typ, nr, size)
}

// IOC_DIR is an implementation of Linux's _IOC_DIR macro.
func IOC_DIR(nr uintptr) uintptr {
	return (nr >> IOC_DIRSHIFT) & IOC_DIRMASK
}

// IOC_TYPE is an implementation of Linux's _IOC_TYPE macro.
func IOC_TYPE(nr uintptr) uintptr {
	return (IOC_TYPESHIFT) & IOC_TYPEMASK
}

// IOC_NR is an implementation of Linux's _IOC_NR macro.
func IOC_NR(nr uintptr) uintptr {
	return (nr >> IOC_NRSHIFT) & IOC_NRMASK
}

// IOC_SIZE is an implementation of Linux's _IOC_SIZE macro.
func IOC_SIZE(nr uintptr) uintptr {
	return (nr >> IOC_SIZESHIFT) & IOC_SIZEMASK
}
