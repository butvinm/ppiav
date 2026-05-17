package vagent

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// BuildAuthenticatedCt runs Stage 4a — the §MPD-Auth/Auth construction.
// Looks up the session, then delegates to the shared `Authenticator` with
// the session's authKey, encryptor (pkAgg-backed), and the chain
// evaluator built by AggregateGaloisShares (rlk + per-auth-atom raw
// `*rlwe.GaloisKey`s, eval level, negative galEls). Returns ct_M (the
// authenticated ciphertext) ready to be streamed to VClient for partial
// decryption.
//
// Preconditions enforced by the underlying Authenticator: the chain
// evaluator's inner key set must carry `params.GaloisElement(-atom)` for
// every auth atom (powers of two strictly less than Lambda); pkAgg must
// be non-nil (AggregatePK has been called); rlkAgg must be non-nil
// (AggregateRLKRound2 has been called). The chain evaluator built by
// AggregateGaloisShares satisfies all three.
func (a *Agent) BuildAuthenticatedCt(
	sid protocol.SessionID,
	resultCt *rlwe.Ciphertext,
) (*rlwe.Ciphertext, error) {
	a.mu.Lock()
	sess, err := a.sessionLocked(sid)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if resultCt == nil {
		return nil, fmt.Errorf("vagent: BuildAuthenticatedCt resultCt is nil")
	}
	if sess.encryptor == nil {
		return nil, fmt.Errorf("vagent: BuildAuthenticatedCt before AggregatePK for sid %q", sid)
	}
	if sess.authchain == nil {
		return nil, fmt.Errorf("vagent: BuildAuthenticatedCt before AggregateGaloisShares for sid %q", sid)
	}
	ctM, err := a.auth.Auth(sess.authKey, sess.encryptor, sess.authchain, resultCt)
	if err != nil {
		return nil, fmt.Errorf("vagent: Auth: %w", err)
	}
	return ctM, nil
}
