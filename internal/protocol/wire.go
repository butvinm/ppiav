package protocol

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/utils/structs"
)

// Wire messages exchanged by VClient, VAgent, VService and RService.
// Payload names are nouns; direction is documented on each message via
// its stage label. Phase 1–2 pass these types in-process (no marshaling);
// Phase 3 will serialise them across HTTP routes — at that point the
// route name will carry direction explicitly.
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

// MarshalBinary serialises InferEvalKeys by delegating to Lattigo's
// MemEvaluationKeySet, which already knows how to write a RelinearizationKey
// and a Galois key set. Phase 4 will replace this with a hierkeys master.
func (k InferEvalKeys) MarshalBinary() ([]byte, error) {
	galois := structs.Map[uint64, rlwe.GaloisKey]{}
	for _, gk := range k.GKS {
		if gk == nil {
			continue
		}
		galois[gk.GaloisElement] = gk
	}
	evk := &rlwe.MemEvaluationKeySet{
		RelinearizationKey: k.RLK,
		GaloisKeys:         galois,
	}
	return evk.MarshalBinary()
}

// UnmarshalBinary inverts MarshalBinary; the resulting GKS slice is
// ordered by ascending Galois element so two round-trips of the same
// payload are byte-identical.
func (k *InferEvalKeys) UnmarshalBinary(data []byte) error {
	evk := &rlwe.MemEvaluationKeySet{}
	if err := evk.UnmarshalBinary(data); err != nil {
		return err
	}
	k.RLK = evk.RelinearizationKey
	k.GKS = nil
	if len(evk.GaloisKeys) == 0 {
		return nil
	}
	elements := make([]uint64, 0, len(evk.GaloisKeys))
	for el := range evk.GaloisKeys {
		elements = append(elements, el)
	}
	// Sort ascending for deterministic order. Avoid a sort import — this
	// loop is O(n²) over ≤Lambda+|extra| ≈ low hundreds.
	for i := 1; i < len(elements); i++ {
		for j := i; j > 0 && elements[j-1] > elements[j]; j-- {
			elements[j-1], elements[j] = elements[j], elements[j-1]
		}
	}
	out := make([]*rlwe.GaloisKey, 0, len(elements))
	for _, el := range elements {
		gk := evk.GaloisKeys[el]
		out = append(out, gk)
	}
	k.GKS = out
	return nil
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
