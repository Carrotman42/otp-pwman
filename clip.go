package main

import (
	"log"
	"syscall"
	"unsafe"
)

const (
	CF_TEXT        = 1
	CF_UNICODETEXT = 13
	
	GMEM_MOVEABLE  = 0x0002
)

var (
	user32           = syscall.MustLoadDLL("user32")
	openClipboard    = user32.MustFindProc("OpenClipboard")
	closeClipboard   = user32.MustFindProc("CloseClipboard")
	emptyClipboard   = user32.MustFindProc("EmptyClipboard")
	getClipboardData = user32.MustFindProc("GetClipboardData")
	setClipboardData = user32.MustFindProc("SetClipboardData")
	
	kernel32         = syscall.MustLoadDLL("kernel32")
	globalAlloc      = kernel32.MustFindProc("GlobalAlloc")
	globalLock       = kernel32.MustFindProc("GlobalLock")
	globalUnlock     = kernel32.MustFindProc("GlobalUnlock")
)


func setClipboard(s string) (err error) {
	var r uintptr
	if r, _, err = openClipboard.Call(0); r == 0 { return err }
	defer closeClipboard.Call()
	if r, _, err = emptyClipboard.Call(); r == 0 { return err }
	
	size := 2 * (1 + len(s))
	if r, _, err = globalAlloc.Call(GMEM_MOVEABLE, uintptr(size)); r == 0 { return err }
	if r, _, err = globalLock.Call(r); r == 0 { return err }
	val := ((*[1<<20]uint16)(unsafe.Pointer(r)))[:]
	for i,v := range s {
		val[i] = uint16(v)
	}
	val[len(s)] = 0
	if a, _, err := globalUnlock.Call(r); a == 0 { return err }

	if r, _, err = setClipboardData.Call(CF_UNICODETEXT, r); r == 0 { return err }
	
	return nil
}



func getClipboard() string {
	r, _, err := openClipboard.Call(0)
	if r == 0 {
		log.Fatalf("OpenClipboard failed: %v", err)
	}
	defer closeClipboard.Call()

	r, _, err = getClipboardData.Call(CF_UNICODETEXT)
	if r == 0 {
		log.Fatalf("GetClipboardData failed: %v", err)
	}
	return syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(r))[:])
}




