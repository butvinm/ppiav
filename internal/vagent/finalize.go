package vagent

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
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
//   - Ver returns (_, false) → Reject (authenticity failed).
//
// The authKey is single-use: regardless of the verdict, the session entry
// is dropped after this call so a replay cannot reuse the same authKey.
func (a *Agent) FinalizeDecryption(
	sid protocol.SessionID,
	authenticatedCt *rlwe.Ciphertext,
	clientShare multiparty.KeySwitchShare,
) (protocol.Verdict, error) {
	if authenticatedCt == nil {
		return protocol.VerdictReject, fmt.Errorf("vagent: FinalizeDecryption authenticatedCt is nil")
	}

	a.mu.Lock()
	sess, err := a.sessionLocked(sid)
	a.mu.Unlock()
	if err != nil {
		return protocol.VerdictReject, err
	}
	if sess.skShare == nil {
		return protocol.VerdictReject, fmt.Errorf("vagent: session %q has no sk_a", sid)
	}

	// VAgent's KeySwitchProtocol with σ=0 smudging. The NoiseFreshSK term
	// is folded in automatically by Lattigo; per DESIGN.md eFresh is
	// sufficient because VClient (the only other party that sees a share)
	// never observes both VAgent's share and the recovered plaintext.
	proto, err := multiparty.NewKeySwitchProtocol(a.params.CKKS, ring.DiscreteGaussian{Sigma: 0, Bound: 0})
	if err != nil {
		return protocol.VerdictReject, fmt.Errorf("vagent: build KeySwitchProtocol: %w", err)
	}

	zeroSk := rlwe.NewSecretKey(a.params.CKKS)
	agentShare := proto.AllocateShare(authenticatedCt.Level())
	proto.GenShare(sess.skShare, zeroSk, authenticatedCt, &agentShare)

	combined := proto.AllocateShare(authenticatedCt.Level())
	if err := proto.AggregateShares(clientShare, agentShare, &combined); err != nil {
		return protocol.VerdictReject, fmt.Errorf("vagent: aggregate KeySwitch shares: %w", err)
	}

	// Key-switch the ciphertext from (sk_c, sk_a) to (0, 0). Output decrypts
	// under zeroSk; we use a fresh ciphertext at the same shape as the input.
	ksOut := rlwe.NewCiphertext(a.params.CKKS, authenticatedCt.Degree(), authenticatedCt.Level())
	proto.KeySwitch(authenticatedCt, combined, ksOut)

	dec := rlwe.NewDecryptor(a.params.CKKS, zeroSk)
	encoder := ckks.NewEncoder(a.params.CKKS)
	slots := make([]float64, a.params.CKKS.MaxSlots())
	if err := encoder.Decode(dec.DecryptNew(ksOut), slots); err != nil {
		return protocol.VerdictReject, fmt.Errorf("vagent: decode plaintext: %w", err)
	}

	// authKey is single-use: drop the session before returning regardless of
	// the verdict (a replay of the same authKey would let an adversary
	// re-attack the same `v` values).
	a.mu.Lock()
	delete(a.sessions, sid)
	a.mu.Unlock()

	m, ok := a.auth.Ver(sess.authKey, slots)
	if !ok {
		return protocol.VerdictReject, nil
	}
	if m > 0 {
		return protocol.VerdictAccept, nil
	}
	return protocol.VerdictReject, nil
}
