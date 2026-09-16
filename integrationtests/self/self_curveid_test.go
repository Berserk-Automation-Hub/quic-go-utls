package self_test

import (
	"reflect"
	"testing"

	tls "github.com/Berserk-Automation-Hub/utls"
)

// getCurveID reports the key-exchange group the handshake actually negotiated.
//
// Upstream splits this helper across a `//go:build go1.25` pair because the standard library's
// crypto/tls only exported ConnectionState.CurveID in Go 1.25. This fork does not use crypto/tls:
// it uses utls, whose ConnectionState keeps the same value in the unexported field
// `testingOnlyCurveID` (set for both peers in utls conn.go, `state.testingOnlyCurveID = c.curveID`)
// and exports nothing. The availability therefore has nothing to do with the Go toolchain version,
// so there is one helper and no build tag, and it reads the field reflectively rather than
// asserting a curve nobody measured. Reading an unexported numeric field through reflect.Value.Uint
// is allowed (the read-only flag blocks Interface and Set, not Uint), and adding an exported
// accessor to utls would be an API change to a TLS library for the benefit of one integration test.
//
// If utls ever renames or re-types the field this loud-fails (HR-6) instead of returning a zero
// CurveID that would make the caller's require.Equal fail with an unexplained 0.
func getCurveID(t *testing.T, connState tls.ConnectionState) tls.CurveID {
	t.Helper()
	f := reflect.ValueOf(connState).FieldByName("testingOnlyCurveID")
	if !f.IsValid() {
		t.Fatalf("utls tls.ConnectionState has no testingOnlyCurveID field: the negotiated curve is no longer observable from this fork, fix getCurveID rather than asserting an unmeasured value")
	}
	if f.Kind() != reflect.Uint16 {
		t.Fatalf("utls tls.ConnectionState.testingOnlyCurveID has kind %s, want uint16", f.Kind())
	}
	return tls.CurveID(f.Uint())
}
