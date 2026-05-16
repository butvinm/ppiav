package vclient

import (
	"fmt"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// ExportedState is the per-session VClient state needed to rebuild a Client
// in a separate process — the bench `encrypt` and `partial-decrypt` CLI
// subcommands consume it. The CRS is NOT serialized: NewWithState rebuilds
// it deterministically from SID via protocol.NewSessionCRS (mirroring New).
//
// PkAgg is needed for EncryptImage (powers the per-session encryptor);
// PartialDecrypt uses only SkShare. Carrying PkAgg unconditionally keeps
// the bench `encrypt` subcommand viable from a single export+import.
type ExportedState struct {
	SID     protocol.SessionID
	SkShare *rlwe.SecretKey
	PkAgg   *rlwe.PublicKey
}

// ExportState snapshots the per-session state. Returns an error if sk_c is
// missing (impossible for a Client built via New, but guards against zero
// values). PkAgg may be nil — only encrypt requires it; partial-decrypt
// does not.
func (c *Client) ExportState() (*ExportedState, error) {
	if c.skShare == nil {
		return nil, fmt.Errorf("vclient: ExportState skShare is nil")
	}
	return &ExportedState{
		SID:     c.sid,
		SkShare: c.skShare,
		PkAgg:   c.pkAgg,
	}, nil
}

// NewWithState constructs a fresh Client seeded from `state`. The CRS is
// rebuilt deterministically from state.SID — the same construction New
// uses. When PkAgg is non-nil the rebuilt Client is encrypt-ready; when
// nil it is partial-decrypt-only (encryptor is left unwired).
func NewWithState(params protocol.Params, state *ExportedState) (*Client, error) {
	if state == nil {
		return nil, fmt.Errorf("vclient: NewWithState state is nil")
	}
	if state.SkShare == nil {
		return nil, fmt.Errorf("vclient: NewWithState SkShare is nil")
	}
	crs, err := protocol.NewSessionCRS(state.SID)
	if err != nil {
		return nil, fmt.Errorf("vclient: NewWithState build CRS: %w", err)
	}
	c := &Client{
		params:  params,
		sid:     state.SID,
		crs:     crs,
		skShare: state.SkShare,
		encoder: ckks.NewEncoder(params.CKKS),
	}
	if state.PkAgg != nil {
		c.pkAgg = state.PkAgg
		c.encryptor = rlwe.NewEncryptor(params.CKKS, state.PkAgg)
	}
	return c, nil
}
