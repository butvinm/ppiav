package protocol

import (
	"testing"
)

// Binary round-trip tests for wire messages are deferred to Phase 3
// (HTTP transport). The Phase 1–2 in-process orchestrator passes these
// structs by value/pointer and never marshals. Tests are kept as skipped
// placeholders so the gap remains visible.

func TestSessionOpenBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVerificationSessionBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVClientPKShareBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVAgentPKShareBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVClientRLKRound1BinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVAgentRLKRound1BinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVClientRLKRound2BinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVClientGaloisKeyShareBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestInferEvalKeysBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestEncryptedImageBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestAuthenticatedResultBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestPartialDecryptionBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}

func TestVerdictNotificationBinaryRoundTrip(t *testing.T) {
	t.Skip("binary round-trip is a Phase-3 HTTP-transport concern; Phase 1–2 pass these structs in-process")
}
