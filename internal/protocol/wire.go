package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
)

// Wire messages exchanged by VClient, VAgent, VService and RService.
// Payload names are nouns; direction is documented on each message via
// its stage label. The in-process orchestrator passes these types without
// marshaling; the HTTP services serialise them across routes — there the
// route name carries direction explicitly.
// See docs/DESIGN.md §`internal/protocol`.

// Stage 1: session open.
type SessionOpen struct{}

type VerificationSession struct {
	SessionID SessionID
}

// Stage 2b: dual pk share exchange (VClient ↔ VAgent). Each party emits
// two shares — one at eval level (`ShareEval`, used for the encryption PK)
// and one at top level (`ShareTop`, used to seed VService's
// `hierkeys.PubToRot` LevelExpansion). The two shares are independent
// multi-party `PublicKeyGenShare`s run against different `rlwe.Parameters`;
// the wire layout length-prefixes each so the receiver can decode them
// without knowing per-level CRP shapes ahead of time.
type VClientPKShare struct {
	ShareEval multiparty.PublicKeyGenShare
	ShareTop  multiparty.PublicKeyGenShare
}

func (s VClientPKShare) MarshalBinary() ([]byte, error)     { return marshalDualPKShare(s.ShareEval, s.ShareTop) }
func (s *VClientPKShare) UnmarshalBinary(data []byte) error { return unmarshalDualPKShare(data, &s.ShareEval, &s.ShareTop) }

type VAgentPKShare struct {
	ShareEval multiparty.PublicKeyGenShare
	ShareTop  multiparty.PublicKeyGenShare
}

func (s VAgentPKShare) MarshalBinary() ([]byte, error)     { return marshalDualPKShare(s.ShareEval, s.ShareTop) }
func (s *VAgentPKShare) UnmarshalBinary(data []byte) error { return unmarshalDualPKShare(data, &s.ShareEval, &s.ShareTop) }

// marshalDualPKShare emits `ShareEval` and `ShareTop` length-prefixed in
// fixed order: 4-byte big-endian length, eval bytes, 4-byte big-endian
// length, top bytes. Both shares carry their own structural metadata so
// the receiver decodes each against the appropriate `rlwe.Parameters`.
func marshalDualPKShare(eval, top multiparty.PublicKeyGenShare) ([]byte, error) {
	evalBytes, err := eval.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("dual pk share: marshal eval share: %w", err)
	}
	topBytes, err := top.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("dual pk share: marshal top share: %w", err)
	}
	out := make([]byte, 0, 8+len(evalBytes)+len(topBytes))
	out = binary.BigEndian.AppendUint32(out, uint32(len(evalBytes)))
	out = append(out, evalBytes...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(topBytes)))
	out = append(out, topBytes...)
	return out, nil
}

func unmarshalDualPKShare(data []byte, eval, top *multiparty.PublicKeyGenShare) error {
	if len(data) < 4 {
		return fmt.Errorf("dual pk share: short header (got %d bytes)", len(data))
	}
	n := int(binary.BigEndian.Uint32(data[0:4]))
	off := 4
	if off+n > len(data) {
		return fmt.Errorf("dual pk share: short eval body (need %d, have %d)", n, len(data)-off)
	}
	if err := eval.UnmarshalBinary(data[off : off+n]); err != nil {
		return fmt.Errorf("dual pk share: unmarshal eval share: %w", err)
	}
	off += n
	if off+4 > len(data) {
		return fmt.Errorf("dual pk share: short top length prefix")
	}
	m := int(binary.BigEndian.Uint32(data[off : off+4]))
	off += 4
	if off+m > len(data) {
		return fmt.Errorf("dual pk share: short top body (need %d, have %d)", m, len(data)-off)
	}
	if err := top.UnmarshalBinary(data[off : off+m]); err != nil {
		return fmt.Errorf("dual pk share: unmarshal top share: %w", err)
	}
	off += m
	if off != len(data) {
		return fmt.Errorf("dual pk share: trailing bytes (%d unread)", len(data)-off)
	}
	return nil
}

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

// Stage 2d: Galois-key share exchange (VClient → VAgent). Single master
// atom set: one share per atom in `Params.MasterAtoms()` (e.g.
// `{1,4,16,...,16384}` at LogN=16, base=4). Top-level handshake,
// **positive** Galois elements (`params.LLKN.Top().GaloisElement(+atom)`).
// VAgent aggregates and converts each share via
// `hierkeys.GaloisKeyToMasterKey` into the master-key bundle that powers
// both: (a) the local LevelExpansion derivation of the auth-atom keys
// (negative direction) consumed by VAgent's authenticator, and (b) the
// wire payload shipped to VService for its inference-side rotation set.
//
// Wire layout: 4-byte big-endian count, then for each share a 4-byte
// big-endian length prefix followed by the share bytes. Order is the
// ascending atom order `MasterAtoms()` pins.
type VClientGaloisShares struct {
	MasterShares []multiparty.GaloisKeyGenShare
}

func (s VClientGaloisShares) MarshalBinary() ([]byte, error) {
	parts := make([][]byte, len(s.MasterShares))
	total := 4
	for i := range s.MasterShares {
		b, err := s.MasterShares[i].MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("VClientGaloisShares: marshal master share %d: %w", i, err)
		}
		parts[i] = b
		total += 4 + len(b)
	}
	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint32(out, uint32(len(s.MasterShares)))
	for _, p := range parts {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out, nil
}

func (s *VClientGaloisShares) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("VClientGaloisShares: short header")
	}
	count := binary.BigEndian.Uint32(data[0:4])
	off := 4
	// Bound the count against the remaining payload so a malformed
	// header cannot trigger a multi-GiB allocation (matches the existing
	// reject-on-short-body guard).
	if uint64(count) > uint64((len(data)-off)/4) {
		return fmt.Errorf("VClientGaloisShares: master count %d exceeds remaining bytes %d", count, len(data)-off)
	}
	shares := make([]multiparty.GaloisKeyGenShare, count)
	for i := uint32(0); i < count; i++ {
		if off+4 > len(data) {
			return fmt.Errorf("VClientGaloisShares: short length prefix at master share %d", i)
		}
		n := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+n > len(data) {
			return fmt.Errorf("VClientGaloisShares: short body at master share %d", i)
		}
		if err := shares[i].UnmarshalBinary(data[off : off+n]); err != nil {
			return fmt.Errorf("VClientGaloisShares: unmarshal master share %d: %w", i, err)
		}
		off += n
	}
	if off != len(data) {
		return fmt.Errorf("VClientGaloisShares: trailing bytes (%d unread)", len(data)-off)
	}
	s.MasterShares = shares
	return nil
}

// InferEvalKeys carries VAgent → VService Stage-2d forward payload: the
// aggregated eval-level relinearization key, the aggregated top-level
// public key (consumed by `hierkeys.PubToRot` to seed VService's
// `LevelExpansion`), and the master Galois-key bundle keyed by ascending
// positive master atom. VAgent and VService both consume the same master
// bundle (VAgent for auth-atom derivation, VService for the inference
// rotation set); the wire payload is identical.
//
// Wire layout (length-prefixed sections, all big-endian unsigned):
//
//   - 4-byte RLK length, RLK bytes
//   - 4-byte PKTop length, PKTop bytes
//   - 4-byte atom count, then for each atom in ascending order:
//   - 4-byte signed atom (`int32` cast to `uint32`)
//   - 4-byte master-key length, master-key bytes
type InferEvalKeys struct {
	RLK       *rlwe.RelinearizationKey
	PKTop     *rlwe.PublicKey
	GKSMaster map[int]*hierkeys.MasterKey
}

func (k InferEvalKeys) MarshalBinary() ([]byte, error) {
	if k.RLK == nil {
		return nil, fmt.Errorf("InferEvalKeys: RLK is nil")
	}
	if k.PKTop == nil {
		return nil, fmt.Errorf("InferEvalKeys: PKTop is nil")
	}
	rlkBytes, err := k.RLK.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("InferEvalKeys: marshal RLK: %w", err)
	}
	pkBytes, err := k.PKTop.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("InferEvalKeys: marshal PKTop: %w", err)
	}

	atoms := make([]int, 0, len(k.GKSMaster))
	for a := range k.GKSMaster {
		atoms = append(atoms, a)
	}
	sort.Ints(atoms)

	type masterBytes struct {
		atom int
		data []byte
	}
	parts := make([]masterBytes, 0, len(atoms))
	total := 4 + len(rlkBytes) + 4 + len(pkBytes) + 4
	for _, a := range atoms {
		mk := k.GKSMaster[a]
		if mk == nil {
			return nil, fmt.Errorf("InferEvalKeys: nil MasterKey for atom %d", a)
		}
		b, err := mk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("InferEvalKeys: marshal MasterKey for atom %d: %w", a, err)
		}
		parts = append(parts, masterBytes{atom: a, data: b})
		total += 4 + 4 + len(b)
	}

	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint32(out, uint32(len(rlkBytes)))
	out = append(out, rlkBytes...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(pkBytes)))
	out = append(out, pkBytes...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(parts)))
	for _, p := range parts {
		out = binary.BigEndian.AppendUint32(out, uint32(int32(p.atom)))
		out = binary.BigEndian.AppendUint32(out, uint32(len(p.data)))
		out = append(out, p.data...)
	}
	return out, nil
}

func (k *InferEvalKeys) UnmarshalBinary(data []byte) error {
	off := 0
	if off+4 > len(data) {
		return fmt.Errorf("InferEvalKeys: short RLK length prefix")
	}
	rlkLen := int(binary.BigEndian.Uint32(data[off : off+4]))
	off += 4
	if off+rlkLen > len(data) {
		return fmt.Errorf("InferEvalKeys: short RLK body (need %d, have %d)", rlkLen, len(data)-off)
	}
	rlk := &rlwe.RelinearizationKey{}
	if err := rlk.UnmarshalBinary(data[off : off+rlkLen]); err != nil {
		return fmt.Errorf("InferEvalKeys: unmarshal RLK: %w", err)
	}
	off += rlkLen

	if off+4 > len(data) {
		return fmt.Errorf("InferEvalKeys: short PKTop length prefix")
	}
	pkLen := int(binary.BigEndian.Uint32(data[off : off+4]))
	off += 4
	if off+pkLen > len(data) {
		return fmt.Errorf("InferEvalKeys: short PKTop body (need %d, have %d)", pkLen, len(data)-off)
	}
	pk := &rlwe.PublicKey{}
	if err := pk.UnmarshalBinary(data[off : off+pkLen]); err != nil {
		return fmt.Errorf("InferEvalKeys: unmarshal PKTop: %w", err)
	}
	off += pkLen

	if off+4 > len(data) {
		return fmt.Errorf("InferEvalKeys: short atom count header")
	}
	count := binary.BigEndian.Uint32(data[off : off+4])
	off += 4
	// Each atom entry contributes at least 8 bytes (4-byte atom +
	// 4-byte length prefix) before its master-key body, so reject any
	// count that exceeds the remaining payload on its face.
	if uint64(count) > uint64((len(data)-off)/8) {
		return fmt.Errorf("InferEvalKeys: atom count %d exceeds remaining bytes %d", count, len(data)-off)
	}

	out := make(map[int]*hierkeys.MasterKey, count)
	var (
		prevAtom int
		first    = true
	)
	for i := uint32(0); i < count; i++ {
		if off+4 > len(data) {
			return fmt.Errorf("InferEvalKeys: short atom int at entry %d", i)
		}
		atom := int(int32(binary.BigEndian.Uint32(data[off : off+4])))
		off += 4
		if !first && atom <= prevAtom {
			return fmt.Errorf("InferEvalKeys: atoms not strictly ascending at entry %d (got %d, prev %d)", i, atom, prevAtom)
		}
		prevAtom = atom
		first = false
		if off+4 > len(data) {
			return fmt.Errorf("InferEvalKeys: short MasterKey length prefix at entry %d", i)
		}
		n := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+n > len(data) {
			return fmt.Errorf("InferEvalKeys: short MasterKey body at entry %d", i)
		}
		mk := &hierkeys.MasterKey{}
		if err := mk.UnmarshalBinary(data[off : off+n]); err != nil {
			return fmt.Errorf("InferEvalKeys: unmarshal MasterKey at entry %d (atom %d): %w", i, atom, err)
		}
		off += n
		out[atom] = mk
	}
	if off != len(data) {
		return fmt.Errorf("InferEvalKeys: trailing bytes (%d unread)", len(data)-off)
	}

	k.RLK = rlk
	k.PKTop = pk
	k.GKSMaster = out
	return nil
}

// Stage 3: image.
type EncryptedImage struct {
	Ct *rlwe.Ciphertext
}

// Stage 3: VService → VAgent — raw inference ciphertext before MAC.
type InferenceResult struct {
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

// Stage 4b: VAgent → VClient — JSON terminator pointing at the protected resource.
type FinalizeRedirect struct {
	Redirect string `json:"redirect"`
}

// Stage 4b: VAgent → RService.
type VerdictNotification struct {
	Verdict Verdict
}

// Manifest is the public parameter declaration VService publishes over
// /params (proxied through VAgent). Each party uses it to rebuild its
// local Params runtime structure. CKKS rides as `json.RawMessage` through
// Lattigo's codec; the rest survives encoding/json untouched. LLKNBase
// and LLKNLogPHK are serialized explicitly so the WASM bridge fails loud
// if either side ever diverges from the canonical schedule — see
// web/ppiav/bridge/ppiav/core.go ParseManifestJSON.
type Manifest struct {
	CKKS                 json.RawMessage `json:"ckks"`
	LLKNBase             int             `json:"llkn_base"`
	LLKNLogPHK           []int           `json:"llkn_log_phk"`
	AuthenticatorLambda  int             `json:"authenticator_lambda"`
	AuthenticatorEpsilon float64         `json:"authenticator_epsilon"`
	FloodSigma           float64         `json:"flood_sigma"`
	ExtraRotationIndices []int           `json:"extra_rotation_indices,omitempty"`
	InputLevel           int             `json:"input_level"`
}
