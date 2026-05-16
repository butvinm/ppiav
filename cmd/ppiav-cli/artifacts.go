package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/structs"
)

// Canonical artifact filenames written into a workdir. The bench Python
// aggregator pulls byte sizes from os.Stat against these names — single
// source of truth lives here.
//
// The lattigo-hierkeys split breaks the keygen output into three Galois-key
// artifacts:
//
//   - gks_auth.bin         — 7 raw *rlwe.GaloisKey at eval level, negative
//     galEls. Consumed by `mac` to drive authchain.Evaluator.
//   - gks_master_infer.bin — VAgent's 8 *hierkeys.MasterKey wire artifact
//     (the wire-size comparison reads this).
//   - gks_infer.bin        — VService's expand-fully derived set, eval level.
//     Cached at keygen because per-sample derivation is multi-minute at LogN=16.
//
// The pre-hierkeys pk.bin is split into pk_eval.bin (encryption + Auth's
// encrypt-v step) and pk_top.bin (seeds hierkeys.PubToRot inside infer).
const (
	artifactSID            = "sid.txt"
	artifactParams         = "params.json"
	artifactPKEval         = "pk_eval.bin"
	artifactPKTop          = "pk_top.bin"
	artifactSKClient       = "sk_c.bin"
	artifactSKAgent        = "sk_a.bin"
	artifactRLK            = "rlk.bin"
	artifactGKSAuth        = "gks_auth.bin"
	artifactGKSMasterInfer = "gks_master_infer.bin"
	artifactGKSInfer       = "gks_infer.bin"
	artifactMacKey         = "mac_key.bin"
	artifactInputCt        = "input_ct.bin"
	artifactResultCt       = "result_ct.bin"
	artifactAuthCt         = "auth_ct.bin"
	artifactClientShare    = "client_share.bin"
)

// writeBytes atomically writes data to <workdir>/<name>. Thin wrapper over
// writeBytesPath so all atomic-write logic lives in one place.
func writeBytes(workdir, name string, data []byte) error {
	return writeBytesPath(filepath.Join(workdir, name), data)
}

// readBytes reads <workdir>/<name> with a descriptive error wrap.
func readBytes(workdir, name string) ([]byte, error) {
	path := filepath.Join(workdir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("artifacts: read %s: %w", name, err)
	}
	return data, nil
}

// writeSID writes the session ID as plain UTF-8 text (no trailing newline).
func writeSID(workdir string, sid protocol.SessionID) error {
	return writeBytes(workdir, artifactSID, []byte(sid))
}

// readSID reads the session ID written by writeSID.
func readSID(workdir string) (protocol.SessionID, error) {
	data, err := readBytes(workdir, artifactSID)
	if err != nil {
		return "", err
	}
	return protocol.SessionID(data), nil
}

// paramsFile is the on-disk JSON envelope written by writeParams: the
// binary-marshalled CKKS parameters plus the InputLevel. The Authenticator
// config and FloodSigma are reconstructed from `protocol.Defaults()` at
// load time — they're not session-dependent — while ExtraRotationIndices
// is recoverable from the persisted gks_infer.bin. InputLevel IS persisted
// because EncryptImage uses it to pick the plaintext level; Orion manifests
// can set it below CKKS.MaxLevel() and silently using MaxLevel would
// desync Orion's level accounting.
type paramsFile struct {
	CKKS       []byte `json:"ckks"`
	InputLevel int    `json:"input_level"`
}

// writeParams persists the CKKS parameters + InputLevel as a JSON envelope.
// The Authenticator config, FloodSigma, and ExtraRotationIndices are NOT
// persisted here: the per-step CLI rebuilds them from `protocol.Defaults`
// (no --orion) or `protocol.LoadOrionParams` (--orion).
func writeParams(workdir string, params protocol.Params) error {
	ckksBytes, err := params.CKKS.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal CKKS params: %w", err)
	}
	data, err := json.Marshal(paramsFile{CKKS: ckksBytes, InputLevel: params.InputLevel})
	if err != nil {
		return fmt.Errorf("artifacts: marshal params envelope: %w", err)
	}
	return writeBytes(workdir, artifactParams, data)
}

// readParamsFile reconstructs the CKKS parameters + InputLevel from params.json.
func readParamsFile(workdir string) (ckks.Parameters, int, error) {
	data, err := readBytes(workdir, artifactParams)
	if err != nil {
		return ckks.Parameters{}, 0, err
	}
	var pf paramsFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return ckks.Parameters{}, 0, fmt.Errorf("artifacts: unmarshal params envelope: %w", err)
	}
	var p ckks.Parameters
	if err := p.UnmarshalBinary(pf.CKKS); err != nil {
		return ckks.Parameters{}, 0, fmt.Errorf("artifacts: unmarshal CKKS params: %w", err)
	}
	return p, pf.InputLevel, nil
}

// writeSecretKey serialises a SecretKey via its MarshalBinary.
func writeSecretKey(workdir, name string, sk *rlwe.SecretKey) error {
	if sk == nil {
		return fmt.Errorf("artifacts: writeSecretKey %s: sk is nil", name)
	}
	data, err := sk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal sk %s: %w", name, err)
	}
	return writeBytes(workdir, name, data)
}

// readSecretKey inverts writeSecretKey.
func readSecretKey(workdir, name string) (*rlwe.SecretKey, error) {
	data, err := readBytes(workdir, name)
	if err != nil {
		return nil, err
	}
	sk := &rlwe.SecretKey{}
	if err := sk.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("artifacts: unmarshal sk %s: %w", name, err)
	}
	return sk, nil
}

// writePublicKey serialises a PublicKey via its MarshalBinary. `name` is
// either artifactPKEval or artifactPKTop — the two collective PKs persisted
// at keygen for the dual-level handshake under the lattigo-hierkeys split.
func writePublicKey(workdir, name string, pk *rlwe.PublicKey) error {
	if pk == nil {
		return fmt.Errorf("artifacts: writePublicKey %s: pk is nil", name)
	}
	data, err := pk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal pk %s: %w", name, err)
	}
	return writeBytes(workdir, name, data)
}

// readPublicKey inverts writePublicKey.
func readPublicKey(workdir, name string) (*rlwe.PublicKey, error) {
	data, err := readBytes(workdir, name)
	if err != nil {
		return nil, err
	}
	pk := &rlwe.PublicKey{}
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("artifacts: unmarshal pk %s: %w", name, err)
	}
	return pk, nil
}

// writeRelinearizationKey serialises an RLK via its embedded
// EvaluationKey.MarshalBinary.
func writeRelinearizationKey(workdir string, rlk *rlwe.RelinearizationKey) error {
	if rlk == nil {
		return fmt.Errorf("artifacts: writeRelinearizationKey: rlk is nil")
	}
	data, err := rlk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal rlk: %w", err)
	}
	return writeBytes(workdir, artifactRLK, data)
}

// readRelinearizationKey inverts writeRelinearizationKey.
func readRelinearizationKey(workdir string) (*rlwe.RelinearizationKey, error) {
	data, err := readBytes(workdir, artifactRLK)
	if err != nil {
		return nil, err
	}
	rlk := &rlwe.RelinearizationKey{}
	if err := rlk.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("artifacts: unmarshal rlk: %w", err)
	}
	return rlk, nil
}

// writeGaloisKeys serialises the GKS slice into a deterministic byte
// blob using Lattigo's MemEvaluationKeySet container, then writes it to
// `name`. The container is keyed by Galois element so two round-trips of
// the same payload are byte-identical (sort by element on emit). RLK is
// left nil — the container shape stays well-formed and the GKS files
// carry only Galois material (no relin bytes).
//
// Used for both `gks_auth.bin` (eval-level negative-galEl auth atoms,
// consumed by `mac`) and `gks_infer.bin` (VService's eval-level derived
// rotation set, consumed by `infer`). The two files differ only in their
// galEl sign convention and atom set; the on-disk shape is identical.
func writeGaloisKeys(workdir, name string, gks []*rlwe.GaloisKey) error {
	galois := structs.Map[uint64, rlwe.GaloisKey]{}
	for _, gk := range gks {
		if gk == nil {
			continue
		}
		galois[gk.GaloisElement] = gk
	}
	evk := &rlwe.MemEvaluationKeySet{
		RelinearizationKey: nil,
		GaloisKeys:         galois,
	}
	data, err := evk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal galois set %s: %w", name, err)
	}
	return writeBytes(workdir, name, data)
}

// readGaloisKeys inverts writeGaloisKeys. The returned slice is sorted
// ascending by GaloisElement so two consecutive (read, write) round-trips
// yield byte-identical files.
func readGaloisKeys(workdir, name string) ([]*rlwe.GaloisKey, error) {
	data, err := readBytes(workdir, name)
	if err != nil {
		return nil, err
	}
	evk := &rlwe.MemEvaluationKeySet{}
	if err := evk.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("artifacts: unmarshal galois set %s: %w", name, err)
	}
	if len(evk.GaloisKeys) == 0 {
		return nil, nil
	}
	elements := make([]uint64, 0, len(evk.GaloisKeys))
	for el := range evk.GaloisKeys {
		elements = append(elements, el)
	}
	sort.Slice(elements, func(i, j int) bool { return elements[i] < elements[j] })
	out := make([]*rlwe.GaloisKey, 0, len(elements))
	for _, el := range elements {
		out = append(out, evk.GaloisKeys[el])
	}
	return out, nil
}

// writeMasterKeys serialises a map[int]*hierkeys.MasterKey to a single
// blob. Atoms are emitted in strictly-ascending order so two round-trips
// of the same payload are byte-identical.
//
// Layout: u32(count) || repeated { i32(atom) || u32(mkLen) || mkBytes }.
// The atom int is the positive top-level Galois atom (e.g. {1,4,16,...}
// at LogN=16, base=4); the MasterKey bytes come from
// hierkeys.MasterKey.MarshalBinary.
func writeMasterKeys(workdir, name string, mks map[int]*hierkeys.MasterKey) error {
	atoms := make([]int, 0, len(mks))
	for a := range mks {
		atoms = append(atoms, a)
	}
	sort.Ints(atoms)
	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.BigEndian, uint32(len(atoms))); err != nil {
		return fmt.Errorf("artifacts: write master-keys count for %s: %w", name, err)
	}
	for _, a := range atoms {
		mk := mks[a]
		if mk == nil {
			return fmt.Errorf("artifacts: writeMasterKeys %s: nil MasterKey for atom %d", name, a)
		}
		mkBytes, err := mk.MarshalBinary()
		if err != nil {
			return fmt.Errorf("artifacts: marshal MasterKey atom %d in %s: %w", a, name, err)
		}
		if err := binary.Write(buf, binary.BigEndian, int32(a)); err != nil {
			return fmt.Errorf("artifacts: write atom %d in %s: %w", a, name, err)
		}
		if err := binary.Write(buf, binary.BigEndian, uint32(len(mkBytes))); err != nil {
			return fmt.Errorf("artifacts: write MasterKey length atom %d in %s: %w", a, name, err)
		}
		if _, err := buf.Write(mkBytes); err != nil {
			return fmt.Errorf("artifacts: write MasterKey body atom %d in %s: %w", a, name, err)
		}
	}
	return writeBytes(workdir, name, buf.Bytes())
}

// readMasterKeys inverts writeMasterKeys.
func readMasterKeys(workdir, name string) (map[int]*hierkeys.MasterKey, error) {
	data, err := readBytes(workdir, name)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("artifacts: readMasterKeys %s: short count header", name)
	}
	count := binary.BigEndian.Uint32(data[0:4])
	off := 4
	out := make(map[int]*hierkeys.MasterKey, count)
	for i := uint32(0); i < count; i++ {
		if off+8 > len(data) {
			return nil, fmt.Errorf("artifacts: readMasterKeys %s: short entry header at %d", name, i)
		}
		atom := int(int32(binary.BigEndian.Uint32(data[off : off+4])))
		off += 4
		mkLen := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+mkLen > len(data) {
			return nil, fmt.Errorf("artifacts: readMasterKeys %s: short MasterKey body at entry %d (need %d, have %d)", name, i, mkLen, len(data)-off)
		}
		mk := &hierkeys.MasterKey{}
		if err := mk.UnmarshalBinary(data[off : off+mkLen]); err != nil {
			return nil, fmt.Errorf("artifacts: unmarshal MasterKey at entry %d (atom %d) in %s: %w", i, atom, name, err)
		}
		off += mkLen
		out[atom] = mk
	}
	if off != len(data) {
		return nil, fmt.Errorf("artifacts: readMasterKeys %s: trailing bytes (%d unread)", name, len(data)-off)
	}
	return out, nil
}

// writeMacKey serialises the per-session MPD-Auth Key.
func writeMacKey(workdir string, key authenticator.Key) error {
	data, err := key.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal mac key: %w", err)
	}
	return writeBytes(workdir, artifactMacKey, data)
}

// readMacKey inverts writeMacKey.
func readMacKey(workdir string) (authenticator.Key, error) {
	data, err := readBytes(workdir, artifactMacKey)
	if err != nil {
		return authenticator.Key{}, err
	}
	var k authenticator.Key
	if err := k.UnmarshalBinary(data); err != nil {
		return authenticator.Key{}, fmt.Errorf("artifacts: unmarshal mac key: %w", err)
	}
	return k, nil
}

// writeCiphertextPath serialises a Ciphertext to an arbitrary absolute or
// relative path. Used by encrypt/infer/mac when the output ciphertext lives
// in a per-image directory outside the keygen workdir.
func writeCiphertextPath(path string, ct *rlwe.Ciphertext) error {
	if ct == nil {
		return fmt.Errorf("artifacts: writeCiphertextPath %s: ct is nil", path)
	}
	data, err := ct.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal ct %s: %w", path, err)
	}
	return writeBytesPath(path, data)
}

// readCiphertextPath inverts writeCiphertextPath.
func readCiphertextPath(path string) (*rlwe.Ciphertext, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("artifacts: read ct %s: %w", path, err)
	}
	ct := &rlwe.Ciphertext{}
	if err := ct.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("artifacts: unmarshal ct %s: %w", path, err)
	}
	return ct, nil
}

// writeKeySwitchShare serialises a multiparty.KeySwitchShare to an arbitrary
// path. The bench `partial-decrypt` subcommand emits one of these per
// image into a per-image directory outside the keygen workdir.
func writeKeySwitchShare(path string, share multiparty.KeySwitchShare) error {
	data, err := share.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal client share %s: %w", path, err)
	}
	return writeBytesPath(path, data)
}

// readKeySwitchShare inverts writeKeySwitchShare.
func readKeySwitchShare(path string) (multiparty.KeySwitchShare, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return multiparty.KeySwitchShare{}, fmt.Errorf("artifacts: read client share %s: %w", path, err)
	}
	var share multiparty.KeySwitchShare
	if err := share.UnmarshalBinary(data); err != nil {
		return multiparty.KeySwitchShare{}, fmt.Errorf("artifacts: unmarshal client share %s: %w", path, err)
	}
	return share, nil
}

// writeBytesPath atomically writes data to path: temp file in the same
// directory then rename. Mirrors writeBytes's contract but for paths that
// may live outside the keygen workdir (per-image artifacts).
func writeBytesPath(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("artifacts: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("artifacts: create tmp for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("artifacts: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("artifacts: close tmp for %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("artifacts: rename tmp -> %s: %w", path, err)
	}
	return nil
}

// loadParams reconstructs a full protocol.Params from the workdir's
// params.json + protocol.Defaults() for non-CKKS fields (Authenticator,
// FloodSigma, LLKN). InputLevel comes from the persisted envelope so
// EncryptImage honours Orion manifests where InputLevel < MaxLevel.
// ExtraRotationIndices is left empty because the rotation set is encoded
// in the persisted gks_infer.bin via Galois elements and no caller of
// loadParams runs the keygen handshake. Orion callers that need the full
// rotation label set additionally pass --orion <dir>.
func loadParams(workdir string) (protocol.Params, error) {
	ckksParams, inputLevel, err := readParamsFile(workdir)
	if err != nil {
		return protocol.Params{}, err
	}
	defaults, err := protocol.Defaults()
	if err != nil {
		return protocol.Params{}, fmt.Errorf("artifacts: build default params: %w", err)
	}
	defaults.CKKS = ckksParams
	defaults.InputLevel = inputLevel
	// Rebuild LLKN against the persisted CKKS — Defaults() stamps an LLKN
	// hierarchy on top of the default CKKS, but the persisted CKKS may
	// differ (Orion manifest override). The hierarchy must match.
	llknParams, err := protocol.BuildLLKNParams(ckksParams)
	if err != nil {
		return protocol.Params{}, fmt.Errorf("artifacts: rebuild LLKN: %w", err)
	}
	defaults.LLKN = llknParams
	return defaults, nil
}
