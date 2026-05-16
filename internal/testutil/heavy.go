// Package testutil holds tiny cross-package test helpers.
package testutil

import (
	"os"
	"testing"
)

// RequireHeavy skips the test unless PPIAV_RUN_HEAVY=1 is set. Used to gate
// LogN=15 round-trip tests (which OOM modest dev boxes) and a known-flaky
// LogN=14 noise-boundary case in vagent (see TestFinalizeRejectsZeroLogit).
// Pass a non-empty reason to make the skip message more specific; an empty
// reason falls back to the generic "heavy/flaky" message.
func RequireHeavy(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("PPIAV_RUN_HEAVY") == "1" {
		return
	}
	if reason == "" {
		reason = "heavy or flaky test"
	}
	t.Skipf("skipping %s; set PPIAV_RUN_HEAVY=1 to enable", reason)
}
