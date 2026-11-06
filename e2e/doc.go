// Package e2e holds the end-to-end tests, which load the real wintun.dll through the public API and, when elevated,
// create a Wintun adapter and carry packets through it.
//
// Every test skips unless WINTUN_E2E=1. TestE2ELoad and TestE2ESignature need no privileges. TestE2EAdapter needs an
// elevated process, as it installs the Wintun driver when missing and creates an adapter, which Wintun removes once
// the test closes it or the process exits.
package e2e
