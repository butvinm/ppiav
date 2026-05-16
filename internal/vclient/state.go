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
// SkTop is the top-level secret-key share. The eval-level projection is
// re-derived on demand inside the rebuilt Client; persisting both would
// duplicate state and risk drift.
//
// PkAgg (eval level) is needed for EncryptImage (powers the per-session
// encryptor); PartialDecrypt uses only the projected sk. Carrying PkAgg
// unconditionally keeps the bench `encrypt` subcommand viable from a
// single export+import. pk_top is NOT included — VClient does not retain
// it (VAgent owns the wire path that ships pk_top to VService).
type ExportedState struct {
	SID   protocol.SessionID
	SkTop *rlwe.SecretKey
	PkAgg *rlwe.PublicKey
}

// ExportState snapshots the per-session state. Returns an error if sk_c
// (top level) is missing (impossible for a Client built via New, but
// guards against zero values). PkAgg may be nil — only encrypt requires
// it; partial-decrypt does not.
func (c *Client) ExportState() (*ExportedState, error) {
	if c.skTop == nil {
		return nil, fmt.Errorf("vclient: ExportState skTop is nil")
	}
	return &ExportedState{
		SID:   c.sid,
		SkTop: c.skTop,
		PkAgg: c.pkAgg,
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
	if state.SkTop == nil {
		return nil, fmt.Errorf("vclient: NewWithState SkTop is nil")
	}
	crs, err := protocol.NewSessionCRS(state.SID)
	if err != nil {
		return nil, fmt.Errorf("vclient: NewWithState build CRS: %w", err)
	}
	c := &Client{
		params:  params,
		sid:     state.SID,
		crs:     crs,
		skTop:   state.SkTop,
		encoder: ckks.NewEncoder(params.CKKS),
	}
	if state.PkAgg != nil {
		c.pkAgg = state.PkAgg
		c.encryptor = rlwe.NewEncryptor(params.CKKS, state.PkAgg)
	}
	return c, nil
}
