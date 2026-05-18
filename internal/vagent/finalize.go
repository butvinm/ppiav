package vagent

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// FinalizeDecryption runs Stage 4a/b: derives VAgent's KeySwitchShare for
// the authenticated ciphertext (sk_a → 0, σ=0 — VAgent does NOT smudge,
// per docs/DESIGN.md §`Joint decryption + Ver`; the eFresh component
// folded in by `NewKeySwitchProtocol` from `NoiseFreshSK` is the only
// noise contribution required from this side), aggregates with VClient's
// share, applies the key-switch, decrypts under the zero sk, decodes to a
// slot vector, and runs `Ver` against the session's authKey.
//
// Verdict logic (docs/DESIGN.md §`Auth/Ver`):
//   - Ver returns (m, true) → Accept iff m > 0, else Reject.
//   - Ver returns (_, false) → ResultAuthFailed (authenticity check failed).
//
// The authKey is single-use: regardless of the verdict, the session entry
// is dropped after this call so a replay cannot reuse the same authKey.
//
// Production wrapper around FinalizeDecryptionVerbose: discards the
// decoded slot vector. The bench `finalize` subcommand calls Verbose
// directly to expose noise-per-slot for the eval pipeline.
func (a *Agent) FinalizeDecryption(
	sid protocol.SessionID,
	authenticatedCt *rlwe.Ciphertext,
	clientShare multiparty.KeySwitchShare,
) (protocol.Verdict, error) {
	verdict, _, err := a.FinalizeDecryptionVerbose(sid, authenticatedCt, clientShare)
	return verdict, err
}

// FinalizeDecryptionVerbose is the sibling that additionally returns the
// decoded slot vector (length = params.CKKS.MaxSlots()) alongside the
// verdict. Same semantics as FinalizeDecryption: single source of truth
// for joint-decrypt + Ver, single-use authKey eviction, identical error
// paths. The slot vector is the post-keyswitch decoded plaintext under
// the zero sk; benchmarks compute noise_per_slot = slots[i] - ref_logit
// over non-S slots.
func (a *Agent) FinalizeDecryptionVerbose(
	sid protocol.SessionID,
	authenticatedCt *rlwe.Ciphertext,
	clientShare multiparty.KeySwitchShare,
) (protocol.Verdict, []float64, error) {
	if authenticatedCt == nil {
		return protocol.VerdictReject, nil, fmt.Errorf("vagent: FinalizeDecryption authenticatedCt is nil")
	}

	a.mu.Lock()
	sess, err := a.sessionLocked(sid)
	if err != nil {
		a.mu.Unlock()
		return protocol.VerdictReject, nil, err
	}
	// `sess.skTop` is populated by OpenSession; the projected `skEval`
	// (computed lazily) is what the KeySwitchProtocol consumes — same
	// eval-level secret share VClient holds.
	skEval, err := a.sessionSkEvalLocked(sess)
	a.mu.Unlock()
	if err != nil {
		return protocol.VerdictReject, nil, err
	}

	// authKey is single-use: drop the session now, before any work that
	// might fail. A deferred eviction guarantees the same replay
	// protection on every exit path (AggregateShares error, Decode
	// error, verdict-true accept, verdict-false reject). Without this,
	// errors in proto.AggregateShares / encoder.Decode left the entry
	// in place and let an adversary re-attack the same authKey with
	// fresh shares.
	defer func() {
		a.mu.Lock()
		delete(a.sessions, sid)
		a.mu.Unlock()
	}()

	// VAgent's KeySwitchProtocol with σ=0 smudging. The NoiseFreshSK term
	// is folded in automatically by Lattigo; per DESIGN.md eFresh is
	// sufficient because VClient (the only other party that sees a share)
	// never observes both VAgent's share and the recovered plaintext.
	proto, err := multiparty.NewKeySwitchProtocol(a.params.CKKS, ring.DiscreteGaussian{Sigma: 0, Bound: 0})
	if err != nil {
		return protocol.VerdictReject, nil, fmt.Errorf("vagent: build KeySwitchProtocol: %w", err)
	}

	zeroSk := rlwe.NewSecretKey(a.params.CKKS)
	agentShare := proto.AllocateShare(authenticatedCt.Level())
	proto.GenShare(skEval, zeroSk, authenticatedCt, &agentShare)

	combined := proto.AllocateShare(authenticatedCt.Level())
	if err := proto.AggregateShares(clientShare, agentShare, &combined); err != nil {
		return protocol.VerdictReject, nil, fmt.Errorf("vagent: aggregate KeySwitch shares: %w", err)
	}

	// Key-switch the ciphertext from (sk_c, sk_a) to (0, 0). Output decrypts
	// under zeroSk; we use a fresh ciphertext at the same shape as the input.
	ksOut := rlwe.NewCiphertext(a.params.CKKS, authenticatedCt.Degree(), authenticatedCt.Level())
	proto.KeySwitch(authenticatedCt, combined, ksOut)

	// Decryptor is bound to zeroSk (a fresh per-call key), so it stays
	// per-call. The encoder is params-only and lives on the Agent — reusing
	// it avoids one ckks.NewEncoder per FinalizeDecryption.
	dec := rlwe.NewDecryptor(a.params.CKKS, zeroSk)
	slots := make([]float64, a.params.CKKS.MaxSlots())
	if err := a.encoder.Decode(dec.DecryptNew(ksOut), slots); err != nil {
		return protocol.VerdictReject, nil, fmt.Errorf("vagent: decode plaintext: %w", err)
	}

	m, ok := a.auth.Ver(sess.authKey, slots)
	if !ok {
		return protocol.VerdictResultAuthFailed, slots, nil
	}
	if m > 0 {
		return protocol.VerdictAccept, slots, nil
	}
	return protocol.VerdictReject, slots, nil
}
