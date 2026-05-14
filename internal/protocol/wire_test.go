package protocol

import (
	"testing"
)

// Binary round-trip tests for wire messages are deferred to Task 9 when
// the CLI actually serialises them; the in-process Phase-1 runner passes
// these structs by value/pointer and never marshals. Tests are kept as
// skipped placeholders so the gap is visible.

func TestSessionOpenBinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestVerificationSessionBinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestVClientPKShareBinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestVAgentPKShareBinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestVClientRLKRound1BinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestVAgentRLKRound1BinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestVClientRLKRound2BinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestVClientGaloisKeyShareBinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestInferEvalKeysBinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestEncryptedImageBinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestAuthenticatedResultBinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestPartialDecryptionBinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}

func TestVerdictNotificationBinaryRoundTrip(t *testing.T) {
	t.Skip("wire round-trip lands with CLI serialisation in Task 9")
}
