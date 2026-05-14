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
)

func (v Verdict) String() string {
	switch v {
	case VerdictUnknown:
		return "unknown"
	case VerdictAccept:
		return "accept"
	case VerdictReject:
		return "reject"
	default:
		return "invalid"
	}
}
