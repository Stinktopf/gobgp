//go:build windows

package table

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// memoryStatusEx is MEMORYSTATUSEX of the Windows API.
type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

var globalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

// SystemMemoryAvailableMiB is the physical memory Windows has available, 0 if it cannot tell.
func SystemMemoryAvailableMiB() uint64 {
	status := memoryStatusEx{}
	status.length = uint32(unsafe.Sizeof(status))
	if ok, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status))); ok == 0 {
		return 0
	}
	return status.availPhys / (1024 * 1024)
}
