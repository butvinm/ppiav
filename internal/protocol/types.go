// Package protocol defines the domain types, wire messages, parameter
// sets, and CRS construction shared by VClient, VAgent, VService and
// RService. See docs/DESIGN.md §`internal/protocol`.
package protocol

type SessionID string

type Verdict uint8

const (
	VerdictUnknown Verdict = iota
	VerdictAccept
	VerdictReject
	// VerdictResultAuthFailed denotes that MPD-Auth `Ver` returned false:
	// the joint decryption produced a plaintext whose injected verification
	// values do not match the per-session authKey. Distinct from
	// VerdictReject (which is a clean negative classifier outcome) so that
	// operators and RService can distinguish a misbehaving client from a
	// legitimately-rejected one.
	VerdictResultAuthFailed
)

func (v Verdict) String() string {
	switch v {
	case VerdictUnknown:
		return "unknown"
	case VerdictAccept:
		return "accept"
	case VerdictReject:
		return "reject"
	case VerdictResultAuthFailed:
		return "result_auth_failed"
	default:
		return "invalid"
	}
}
