// Package ppiav exposes ppiav protocol APIs to browser JS via WASM.
// The package is split into two layers:
//   - core.go (host-buildable, no build tag): pure-Go wrappers around
//     internal/vclient that marshal/unmarshal wire bytes. Tests live here.
//   - ppiav.go (//go:build js && wasm): syscall/js wiring on top of core.
//
// The split lets Go-only tests run on the host without dragging in WASM
// machinery, while keeping the bridge surface minimal and easy to audit.
package ppiav

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/butvinm/ppiav/internal/vclient"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// paramsWire mirrors the JSON shape VService writes from
// internal/vservice/http.go's paramsWire. Keeping a separate copy here
// avoids pulling vservice into the WASM bridge (it imports net/http).
type paramsWire struct {
	CKKS                 json.RawMessage `json:"ckks"`
	AuthenticatorLambda  int             `json:"authenticator_lambda"`
	AuthenticatorEpsilon float64         `json:"authenticator_epsilon"`
	FloodSigma           float64         `json:"flood_sigma"`
	ExtraRotationIndices []int           `json:"extra_rotation_indices,omitempty"`
	InputLevel           int             `json:"input_level"`
}

// ParseParamsJSON decodes the JSON written by vservice.writeParams into a
// protocol.Params. Exported for tests.
func ParseParamsJSON(data []byte) (protocol.Params, error) {
	var pw paramsWire
	if err := json.Unmarshal(data, &pw); err != nil {
		return protocol.Params{}, fmt.Errorf("ppiav: decode params: %w", err)
	}
	var ckksParams ckks.Parameters
	if err := ckksParams.UnmarshalJSON(pw.CKKS); err != nil {
		return protocol.Params{}, fmt.Errorf("ppiav: decode CKKS params: %w", err)
	}
	return protocol.Params{
		CKKS: ckksParams,
		Authenticator: authenticator.Config{
			Lambda:  pw.AuthenticatorLambda,
			Epsilon: pw.AuthenticatorEpsilon,
		},
		FloodSigma:           pw.FloodSigma,
		ExtraRotationIndices: pw.ExtraRotationIndices,
		InputLevel:           pw.InputLevel,
	}, nil
}

// handles stores *vclient.Client instances keyed by an integer handle
// returned to JS as a Number. A sync.Mutex guards mutation; Go WASM is
// single-threaded but the host-side test path may exercise the API from
// multiple goroutines, so guarding is cheap insurance.
var (
	handles    sync.Map // map[uint64]*vclient.Client
	nextHandle atomic.Uint64
)

// NewClient parses the params JSON, constructs a vclient.Client with a
// fresh sk_c, stores it under a new handle, and returns the handle.
func NewClient(paramsJSON []byte, sid string) (uint64, error) {
	params, err := ParseParamsJSON(paramsJSON)
	if err != nil {
		return 0, err
	}
	c, err := vclient.New(params, protocol.SessionID(sid))
	if err != nil {
		return 0, fmt.Errorf("ppiav: construct client: %w", err)
	}
	h := nextHandle.Add(1)
	handles.Store(h, c)
	return h, nil
}

// DeleteClient frees the handle. Idempotent.
func DeleteClient(h uint64) {
	handles.Delete(h)
}

// loadClient retrieves the client for a handle.
func loadClient(h uint64) (*vclient.Client, error) {
	v, ok := handles.Load(h)
	if !ok {
		return nil, fmt.Errorf("ppiav: unknown client handle %d", h)
	}
	return v.(*vclient.Client), nil
}

// GenPKShare runs Stage 2b on the client and returns the marshaled
// VClientPKShare bytes.
func GenPKShare(h uint64) ([]byte, error) {
	c, err := loadClient(h)
	if err != nil {
		return nil, err
	}
	share, err := c.GenPKShare()
	if err != nil {
		return nil, fmt.Errorf("ppiav: GenPKShare: %w", err)
	}
	out, err := protocol.VClientPKShare{Share: share}.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ppiav: marshal VClientPKShare: %w", err)
	}
	return out, nil
}

// AggregatePK consumes the agent's marshaled VAgentPKShare bytes and
// finalises the aggregated pk on the client.
func AggregatePK(h uint64, agentShareBytes []byte) error {
	c, err := loadClient(h)
	if err != nil {
		return err
	}
	var msg protocol.VAgentPKShare
	if err := msg.UnmarshalBinary(agentShareBytes); err != nil {
		return fmt.Errorf("ppiav: unmarshal VAgentPKShare: %w", err)
	}
	if err := c.AggregatePK(msg.Share); err != nil {
		return fmt.Errorf("ppiav: AggregatePK: %w", err)
	}
	return nil
}

// GenRLKShareRound1 runs Stage 2c round 1 and returns the marshaled
// VClientRLKRound1 bytes.
func GenRLKShareRound1(h uint64) ([]byte, error) {
	c, err := loadClient(h)
	if err != nil {
		return nil, err
	}
	share, err := c.GenRLKShareRound1()
	if err != nil {
		return nil, fmt.Errorf("ppiav: GenRLKShareRound1: %w", err)
	}
	out, err := protocol.VClientRLKRound1{Share: share}.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ppiav: marshal VClientRLKRound1: %w", err)
	}
	return out, nil
}

// AggregateRLKRound1 consumes the agent's marshaled VAgentRLKRound1 bytes
// and folds them into the client's round-1 aggregate.
func AggregateRLKRound1(h uint64, agentShareBytes []byte) error {
	c, err := loadClient(h)
	if err != nil {
		return err
	}
	var msg protocol.VAgentRLKRound1
	if err := msg.UnmarshalBinary(agentShareBytes); err != nil {
		return fmt.Errorf("ppiav: unmarshal VAgentRLKRound1: %w", err)
	}
	if err := c.AggregateRLKRound1(msg.Share); err != nil {
		return fmt.Errorf("ppiav: AggregateRLKRound1: %w", err)
	}
	return nil
}

// GenRLKShareRound2 runs Stage 2c round 2 and returns the marshaled
// VClientRLKRound2 bytes.
func GenRLKShareRound2(h uint64) ([]byte, error) {
	c, err := loadClient(h)
	if err != nil {
		return nil, err
	}
	share, err := c.GenRLKShareRound2()
	if err != nil {
		return nil, fmt.Errorf("ppiav: GenRLKShareRound2: %w", err)
	}
	out, err := protocol.VClientRLKRound2{Share: share}.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ppiav: marshal VClientRLKRound2: %w", err)
	}
	return out, nil
}

// GenGaloisShares runs Stage 2d and returns the marshaled
// VClientGaloisKeyShare bytes (length-prefixed concatenation of all
// per-rotation shares in canonical label order).
func GenGaloisShares(h uint64) ([]byte, error) {
	c, err := loadClient(h)
	if err != nil {
		return nil, err
	}
	shares, _, err := c.GenGaloisShares()
	if err != nil {
		return nil, fmt.Errorf("ppiav: GenGaloisShares: %w", err)
	}
	// vclient.GenGaloisShares can legitimately return (nil, nil, nil) when
	// the canonical rotation set is empty (Lambda<=1). Allow that — the
	// resulting marshal is a 4-byte zero count.
	msg := protocol.VClientGaloisKeyShare{Shares: shares}
	out, err := msg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ppiav: marshal VClientGaloisKeyShare: %w", err)
	}
	return out, nil
}

// EncryptImage encrypts the preprocessed image tensor and returns the
// marshaled ciphertext bytes. The tensor length must be vclient.ImageLen.
func EncryptImage(h uint64, tensor []float64) ([]byte, error) {
	c, err := loadClient(h)
	if err != nil {
		return nil, err
	}
	ct, err := c.EncryptImage(tensor)
	if err != nil {
		return nil, fmt.Errorf("ppiav: EncryptImage: %w", err)
	}
	out, err := ct.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ppiav: marshal ciphertext: %w", err)
	}
	return out, nil
}

// PartialDecrypt consumes the SSE-delivered ct_M bytes (a raw
// rlwe.Ciphertext.MarshalBinary blob — AuthenticatedResult has no
// codec, so the wire payload is the ciphertext itself, matching
// internal/vagent/http.go's SSE handler) and returns the marshaled
// PartialDecryption.
func PartialDecrypt(h uint64, authenticatedCtBytes []byte) ([]byte, error) {
	c, err := loadClient(h)
	if err != nil {
		return nil, err
	}
	var ct rlwe.Ciphertext
	if err := ct.UnmarshalBinary(authenticatedCtBytes); err != nil {
		return nil, fmt.Errorf("ppiav: unmarshal authenticated ciphertext: %w", err)
	}
	share, err := c.PartialDecrypt(&ct)
	if err != nil {
		return nil, fmt.Errorf("ppiav: PartialDecrypt: %w", err)
	}
	out, err := protocol.PartialDecryption{Share: share}.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ppiav: marshal PartialDecryption: %w", err)
	}
	return out, nil
}

// Compile-time check that multiparty share types we rely on satisfy the
// expected interfaces. If Lattigo ever drops MarshalBinary on these the
// build breaks here rather than at runtime.
var (
	_ interface{ MarshalBinary() ([]byte, error) } = multiparty.PublicKeyGenShare{}
	_ interface{ MarshalBinary() ([]byte, error) } = multiparty.RelinearizationKeyGenShare{}
	_ interface{ MarshalBinary() ([]byte, error) } = multiparty.GaloisKeyGenShare{}
	_ interface{ MarshalBinary() ([]byte, error) } = multiparty.KeySwitchShare{}
)
