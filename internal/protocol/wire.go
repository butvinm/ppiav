package protocol

import (
	"encoding/binary"
	"fmt"
	"sort"

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

func (s VClientPKShare) MarshalBinary() ([]byte, error)     { return s.Share.MarshalBinary() }
func (s *VClientPKShare) UnmarshalBinary(data []byte) error { return s.Share.UnmarshalBinary(data) }

type VAgentPKShare struct {
	Share multiparty.PublicKeyGenShare
}

func (s VAgentPKShare) MarshalBinary() ([]byte, error)     { return s.Share.MarshalBinary() }
func (s *VAgentPKShare) UnmarshalBinary(data []byte) error { return s.Share.UnmarshalBinary(data) }

// Stage 2c: rlk share exchange, two rounds (VClient ↔ VAgent). Round 2
// has no reply share — it just acks completion.
type VClientRLKRound1 struct {
	Share multiparty.RelinearizationKeyGenShare
}

func (s VClientRLKRound1) MarshalBinary() ([]byte, error)     { return s.Share.MarshalBinary() }
func (s *VClientRLKRound1) UnmarshalBinary(data []byte) error { return s.Share.UnmarshalBinary(data) }

type VAgentRLKRound1 struct {
	Share multiparty.RelinearizationKeyGenShare
}

func (s VAgentRLKRound1) MarshalBinary() ([]byte, error)     { return s.Share.MarshalBinary() }
func (s *VAgentRLKRound1) UnmarshalBinary(data []byte) error { return s.Share.UnmarshalBinary(data) }

type VClientRLKRound2 struct {
	Share multiparty.RelinearizationKeyGenShare
}

func (s VClientRLKRound2) MarshalBinary() ([]byte, error)     { return s.Share.MarshalBinary() }
func (s *VClientRLKRound2) UnmarshalBinary(data []byte) error { return s.Share.UnmarshalBinary(data) }

// Stage 2d: Galois-key share exchange (VClient → VAgent) and forward to
// VService. Phase 1–3 emits one share per rotation; Phase 4 collapses
// these into a single gks_master share via lattigo-hierkeys.
//
// The wire layout is: 4-byte big-endian count, then for each share a
// 4-byte big-endian length prefix followed by the share's MarshalBinary
// bytes. Counts and lengths are uint32; the protocol uses on the order of
// ~hundreds of rotation keys at most.
type VClientGaloisKeyShare struct {
	Shares []multiparty.GaloisKeyGenShare
}

func (s VClientGaloisKeyShare) MarshalBinary() ([]byte, error) {
	parts := make([][]byte, len(s.Shares))
	total := 4
	for i := range s.Shares {
		b, err := s.Shares[i].MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("VClientGaloisKeyShare: marshal share %d: %w", i, err)
		}
		parts[i] = b
		total += 4 + len(b)
	}
	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint32(out, uint32(len(s.Shares)))
	for _, p := range parts {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out, nil
}

func (s *VClientGaloisKeyShare) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("VClientGaloisKeyShare: short header")
	}
	count := binary.BigEndian.Uint32(data[0:4])
	off := 4
	shares := make([]multiparty.GaloisKeyGenShare, count)
	for i := uint32(0); i < count; i++ {
		if off+4 > len(data) {
			return fmt.Errorf("VClientGaloisKeyShare: short length prefix at share %d", i)
		}
		n := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+n > len(data) {
			return fmt.Errorf("VClientGaloisKeyShare: short body at share %d", i)
		}
		if err := shares[i].UnmarshalBinary(data[off : off+n]); err != nil {
			return fmt.Errorf("VClientGaloisKeyShare: unmarshal share %d: %w", i, err)
		}
		off += n
	}
	s.Shares = shares
	return nil
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
	sort.Slice(elements, func(i, j int) bool { return elements[i] < elements[j] })
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

func (s PartialDecryption) MarshalBinary() ([]byte, error)     { return s.Share.MarshalBinary() }
func (s *PartialDecryption) UnmarshalBinary(data []byte) error { return s.Share.UnmarshalBinary(data) }

// Stage 4b: VAgent → RService.
type VerdictNotification struct {
	Verdict Verdict
}
