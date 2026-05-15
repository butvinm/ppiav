package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/structs"
)

// Canonical artifact filenames written into a workdir. The bench Python
// aggregator pulls byte sizes from os.Stat against these names — single
// source of truth lives here. glk_master.bin and glk_full.bin currently
// hold identical bytes; Phase-4 lattigo-hierkeys will diverge them.
const (
	artifactSID         = "sid.txt"
	artifactParams      = "params.json"
	artifactPK          = "pk.bin"
	artifactSKClient    = "sk_c.bin"
	artifactSKAgent     = "sk_a.bin"
	artifactRLK         = "rlk.bin"
	artifactGLKMaster   = "glk_master.bin"
	artifactGLKFull     = "glk_full.bin"
	artifactMacKey      = "mac_key.bin"
	artifactInputCt     = "input_ct.bin"
	artifactResultCt    = "result_ct.bin"
	artifactAuthCt      = "auth_ct.bin"
	artifactClientShare = "client_share.bin"
)

// writeBytes atomically writes data to <workdir>/<name>: write a sibling
// tmp file then rename. Mirrors bench.Run.WriteJSON's atomicity contract
// so partial writes never land in the workdir on a crashed run.
func writeBytes(workdir, name string, data []byte) error {
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		return fmt.Errorf("artifacts: mkdir %s: %w", workdir, err)
	}
	path := filepath.Join(workdir, name)
	tmp, err := os.CreateTemp(workdir, name+".tmp-*")
	if err != nil {
		return fmt.Errorf("artifacts: create tmp for %s: %w", name, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("artifacts: write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("artifacts: close tmp for %s: %w", name, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("artifacts: rename tmp -> %s: %w", path, err)
	}
	return nil
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

// writeParams serialises the CKKS parameters as JSON. The Authenticator
// config, FloodSigma, ExtraRotationIndices, and InputLevel are NOT
// persisted here: the per-step CLI rebuilds them from `protocol.Defaults`
// (Phase-1) or `protocol.LoadOrionParams` (Phase-2 via --orion). params.json
// captures only the CKKS knobs because they are the only fields callers
// cannot reconstruct from --orion + Defaults at load time.
func writeParams(workdir string, params protocol.Params) error {
	data, err := params.CKKS.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal CKKS params: %w", err)
	}
	return writeBytes(workdir, artifactParams, data)
}

// readCKKSParams reconstructs the CKKS parameters from params.json.
func readCKKSParams(workdir string) (ckks.Parameters, error) {
	data, err := readBytes(workdir, artifactParams)
	if err != nil {
		return ckks.Parameters{}, err
	}
	var p ckks.Parameters
	if err := p.UnmarshalBinary(data); err != nil {
		return ckks.Parameters{}, fmt.Errorf("artifacts: unmarshal CKKS params: %w", err)
	}
	return p, nil
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

// writePublicKey serialises a PublicKey via its MarshalBinary.
func writePublicKey(workdir string, pk *rlwe.PublicKey) error {
	if pk == nil {
		return fmt.Errorf("artifacts: writePublicKey: pk is nil")
	}
	data, err := pk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal pk: %w", err)
	}
	return writeBytes(workdir, artifactPK, data)
}

// readPublicKey inverts writePublicKey.
func readPublicKey(workdir string) (*rlwe.PublicKey, error) {
	data, err := readBytes(workdir, artifactPK)
	if err != nil {
		return nil, err
	}
	pk := &rlwe.PublicKey{}
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("artifacts: unmarshal pk: %w", err)
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
// the same payload are byte-identical (sort by element on emit). RLK
// is intentionally stuffed with a zero-valued placeholder so the container
// stays well-formed without bloating the GLK files with relin material.
//
// glk_master.bin and glk_full.bin both currently receive the same payload;
// Phase-4 lattigo-hierkeys will produce a smaller master that
// reconstructs the full set on the VService side.
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

// writeCiphertext serialises a Ciphertext to <workdir>/<name>.
func writeCiphertext(workdir, name string, ct *rlwe.Ciphertext) error {
	if ct == nil {
		return fmt.Errorf("artifacts: writeCiphertext %s: ct is nil", name)
	}
	data, err := ct.MarshalBinary()
	if err != nil {
		return fmt.Errorf("artifacts: marshal ct %s: %w", name, err)
	}
	return writeBytes(workdir, name, data)
}

// readCiphertext inverts writeCiphertext. The path is `<workdir>/<name>`
// when `name` is a bare filename; callers passing an explicit path
// outside the workdir should use the absolute form via filepath.Join
// upstream.
func readCiphertext(workdir, name string) (*rlwe.Ciphertext, error) {
	data, err := readBytes(workdir, name)
	if err != nil {
		return nil, err
	}
	ct := &rlwe.Ciphertext{}
	if err := ct.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("artifacts: unmarshal ct %s: %w", name, err)
	}
	return ct, nil
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
// FloodSigma). InputLevel is left at the Defaults() value (0 → EncryptImage
// builds at MaxLevel); ExtraRotationIndices is left empty because the
// rotation set is encoded in the persisted glk_full.bin via Galois elements
// and no caller of loadParams runs the keygen handshake. Phase-2 callers
// that need Orion's InputLevel or rotation labels reload via LoadOrionParams
// from --orion <dir> in addition.
func loadParams(workdir string) (protocol.Params, error) {
	ckksParams, err := readCKKSParams(workdir)
	if err != nil {
		return protocol.Params{}, err
	}
	defaults, err := protocol.Defaults()
	if err != nil {
		return protocol.Params{}, fmt.Errorf("artifacts: build default params: %w", err)
	}
	defaults.CKKS = ckksParams
	return defaults, nil
}
