// Package e2e holds the end-to-end test, which creates a Wintun adapter through the package's API, with the embedded
// wintun.dll loaded from memory, and carries packets through it.
//
// TestE2EAdapter skips unless WINTUN_E2E=1 and the process is elevated, as it installs the Wintun driver when missing
// and creates an adapter, which Wintun removes once the test closes it or the process exits.
package e2e
