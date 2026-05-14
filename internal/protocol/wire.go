package protocol

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
)

// Wire messages exchanged by VClient, VAgent, VService and RService.
// Direction is implicit in the HTTP route; payload names are nouns.
// See docs/DESIGN.md §`internal/protocol`.

// Stage 1: session open.
type SessionOpen struct{}

type VerificationSession struct {
	SessionID SessionID
}

// Stage 2b: pk share exchange (VClient ↔ VAgent).
type VClientPKShare struct {
	Share multiparty.PublicKeyGenShare
}

type VAgentPKShare struct {
	Share multiparty.PublicKeyGenShare
}

// Stage 2c: rlk share exchange, two rounds (VClient ↔ VAgent). Round 2
// has no reply share — it just acks completion.
type VClientRLKRound1 struct {
	Share multiparty.RelinearizationKeyGenShare
}

type VAgentRLKRound1 struct {
	Share multiparty.RelinearizationKeyGenShare
}

type VClientRLKRound2 struct {
	Share multiparty.RelinearizationKeyGenShare
}

// Stage 2d: Galois-key share exchange (VClient → VAgent) and forward to
// VService. Phase 1–3 emits one share per rotation; Phase 4 collapses
// these into a single gks_master share via lattigo-hierkeys.
type VClientGaloisKeyShare struct {
	Shares []multiparty.GaloisKeyGenShare
}

// InferEvalKeys carries the aggregated relinearization key and the full
// per-rotation Galois key set from VAgent to VService. Lattigo v6.2.0
// does not expose a `GaloisKeySet` type — we ship the slice directly,
// which is what `rlwe.NewMemEvaluationKeySet` consumes. Phase 4 replaces
// `GKS` with `GKSMaster` (lattigo-hierkeys).
type InferEvalKeys struct {
	RLK *rlwe.RelinearizationKey
	GKS []*rlwe.GaloisKey
}

// Stage 3: image.
type EncryptedImage struct {
	Ct *rlwe.Ciphertext
}

// Stage 4a: VAgent → VClient — result ct with verification values folded in.
type AuthenticatedResult struct {
	Ct *rlwe.Ciphertext
}

// Stage 4a: VClient → VAgent — partial-decryption share with noise flooding applied.
type PartialDecryption struct {
	Share multiparty.KeySwitchShare
}

// Stage 4b: VAgent → RService.
type VerdictNotification struct {
	Verdict Verdict
}
