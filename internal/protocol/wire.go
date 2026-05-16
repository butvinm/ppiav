package protocol

import (
	"encoding/binary"
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

// Stage 2d: Galois-key share exchange (VClient → VAgent). The dual-atom-set
// design splits the emitted shares per consumer:
//
//   - `AuthAtomShares` — one share per atom in `Params.AuthAtoms()` (e.g.
//     `{1,2,4,8,16,32,64}` for λ=128). Eval-level handshake, **negative**
//     Galois elements (`params.CKKS.GaloisElement(-atom)`). Aggregated into
//     raw `*rlwe.GaloisKey`s that VAgent's authenticator chain-rotates over.
//   - `InferAtomShares` — one share per atom in `Params.InferAtoms()` (e.g.
//     `{1,4,16,...,16384}` at LogN=16, base=4). Top-level handshake,
//     **positive** Galois elements (`params.LLKN.Top().GaloisElement(+atom)`).
//     Aggregated and converted via `hierkeys.GaloisKeyToMasterKey` into the
//     master-key bundle VAgent forwards to VService.
//
// Wire layout: 4-byte big-endian auth count, then for each auth share a
// 4-byte big-endian length prefix followed by the share bytes; then 4-byte
// big-endian infer count, then for each infer share a 4-byte big-endian
// length prefix followed by the share bytes. Order within each list is the
// ascending order Tasks 2/3 pin (`AuthAtoms()`/`InferAtoms()`).
type VClientGaloisShares struct {
	AuthAtomShares  []multiparty.GaloisKeyGenShare
	InferAtomShares []multiparty.GaloisKeyGenShare
}

func (s VClientGaloisShares) MarshalBinary() ([]byte, error) {
	authParts, authTotal, err := marshalGaloisShareList(s.AuthAtomShares, "auth")
	if err != nil {
		return nil, err
	}
	inferParts, inferTotal, err := marshalGaloisShareList(s.InferAtomShares, "infer")
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 8+authTotal+inferTotal)
	out = binary.BigEndian.AppendUint32(out, uint32(len(s.AuthAtomShares)))
	for _, p := range authParts {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(s.InferAtomShares)))
	for _, p := range inferParts {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out, nil
}

func (s *VClientGaloisShares) UnmarshalBinary(data []byte) error {
	auth, off, err := unmarshalGaloisShareList(data, 0, "auth")
	if err != nil {
		return err
	}
	infer, off, err := unmarshalGaloisShareList(data, off, "infer")
	if err != nil {
		return err
	}
	if off != len(data) {
		return fmt.Errorf("VClientGaloisShares: trailing bytes (%d unread)", len(data)-off)
	}
	s.AuthAtomShares = auth
	s.InferAtomShares = infer
	return nil
}

// marshalGaloisShareList returns the per-share marshaled bytes (so the
// caller can length-prefix them inline) plus the total byte count
// including the 4-byte count header that prefixes the list.
func marshalGaloisShareList(shares []multiparty.GaloisKeyGenShare, label string) ([][]byte, int, error) {
	parts := make([][]byte, len(shares))
	total := 4
	for i := range shares {
		b, err := shares[i].MarshalBinary()
		if err != nil {
			return nil, 0, fmt.Errorf("VClientGaloisShares: marshal %s share %d: %w", label, i, err)
		}
		parts[i] = b
		total += 4 + len(b)
	}
	return parts, total, nil
}

// unmarshalGaloisShareList decodes one length-prefixed share list starting
// at `off` and returns the decoded slice, the new offset, and any error.
// Each list is preceded by a 4-byte big-endian count and followed by
// `count` length-prefixed shares. The count is bounded against the
// remaining payload so a malformed header cannot trigger a multi-GiB
// allocation (see `TestVClientGaloisSharesUnmarshalCountExceedsPayload`).
func unmarshalGaloisShareList(data []byte, off int, label string) ([]multiparty.GaloisKeyGenShare, int, error) {
	if off+4 > len(data) {
		return nil, 0, fmt.Errorf("VClientGaloisShares: short %s header", label)
	}
	count := binary.BigEndian.Uint32(data[off : off+4])
	off += 4
	if uint64(count) > uint64((len(data)-off)/4) {
		return nil, 0, fmt.Errorf("VClientGaloisShares: %s count %d exceeds remaining bytes %d", label, count, len(data)-off)
	}
	shares := make([]multiparty.GaloisKeyGenShare, count)
	for i := uint32(0); i < count; i++ {
		if off+4 > len(data) {
			return nil, 0, fmt.Errorf("VClientGaloisShares: short %s length prefix at share %d", label, i)
		}
		n := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+n > len(data) {
			return nil, 0, fmt.Errorf("VClientGaloisShares: short %s body at share %d", label, i)
		}
		if err := shares[i].UnmarshalBinary(data[off : off+n]); err != nil {
			return nil, 0, fmt.Errorf("VClientGaloisShares: unmarshal %s share %d: %w", label, i, err)
		}
		off += n
	}
	return shares, off, nil
}

// InferEvalKeys carries VAgent → VService Stage-2d forward payload: the
// aggregated eval-level relinearization key, the aggregated top-level
// public key (consumed by `hierkeys.PubToRot` to seed VService's
// `LevelExpansion`), and the master Galois-key bundle keyed by ascending
// positive infer atom. VAgent's auth-side raw `*rlwe.GaloisKey`s are NOT
// included — they stay inside the VAgent session.
//
// Wire layout (length-prefixed sections, all big-endian unsigned):
//
//   - 4-byte RLK length, RLK bytes
//   - 4-byte PKTop length, PKTop bytes
//   - 4-byte atom count, then for each atom in ascending order:
//   - 4-byte signed atom (`int32` cast to `uint32`)
//   - 4-byte master-key length, master-key bytes
type InferEvalKeys struct {
	RLK            *rlwe.RelinearizationKey
	PKTop          *rlwe.PublicKey
	GKSMasterInfer map[int]*hierkeys.MasterKey
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

	atoms := make([]int, 0, len(k.GKSMasterInfer))
	for a := range k.GKSMasterInfer {
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
		mk := k.GKSMasterInfer[a]
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
	k.GKSMasterInfer = out
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
