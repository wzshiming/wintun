// Package wintun is a Wintun binding with the API of golang.zx2c4.com/wintun that loads the signed wintun.dll it
// embeds for windows/386, windows/amd64 and windows/arm64 straight from memory, on first use. It exports nothing
// outside Windows.
//
// No function panics: every function with an error result returns a failure to load the DLL, and a DLL call that fails
// without a last error returns syscall.EINVAL. Close and End may be called more than once, also concurrently, and hand
// their handle to the DLL once. A closed, zero or nil Adapter's Close returns nil, LUID 0 and StartSession
// windows.ERROR_INVALID_HANDLE; an ended, zero or nil Session's ReceivePacket and AllocateSendPacket return
// windows.ERROR_HANDLE_EOF, ReadWaitEvent 0, and ReleaseReceivePacket and SendPacket do nothing. AllocateSendPacket
// returns windows.ERROR_INVALID_PARAMETER for a size outside 0 to PacketSizeMax. As the driver requires, readers must be
// stopped before End, by setting ReadWaitEvent's event and waiting for them.
package wintun
