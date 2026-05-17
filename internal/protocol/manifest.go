package protocol

import (
	"encoding/json"
	"fmt"

	"github.com/butvinm/ppiav/internal/authenticator"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// ParseManifestJSON decodes the wire `Manifest` published by VService at
// /params into a full `Params` struct. LLKN hierarchy is reconstructed
// locally from the decoded CKKS params; LLKNBase and LLKNLogPHK are
// validated against the canonical defaults so any silent drift between
// peers fails loud here.
func ParseManifestJSON(data []byte) (Params, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Params{}, fmt.Errorf("protocol: decode manifest: %w", err)
	}
	if m.LLKNBase != DefaultLLKNBase {
		return Params{}, fmt.Errorf("protocol: LLKNBase mismatch (wire=%d, expected %d)", m.LLKNBase, DefaultLLKNBase)
	}
	if !equalIntSlice(m.LLKNLogPHK, DefaultLLKNLogPHK) {
		return Params{}, fmt.Errorf("protocol: LLKNLogPHK mismatch (wire=%v, expected %v)", m.LLKNLogPHK, DefaultLLKNLogPHK)
	}
	var ckksParams ckks.Parameters
	if err := ckksParams.UnmarshalJSON(m.CKKS); err != nil {
		return Params{}, fmt.Errorf("protocol: decode CKKS params: %w", err)
	}
	llknParams, err := BuildLLKNParams(ckksParams)
	if err != nil {
		return Params{}, fmt.Errorf("protocol: build LLKN parameters: %w", err)
	}
	return Params{
		CKKS:     ckksParams,
		LLKN:     llknParams,
		LLKNBase: m.LLKNBase,
		Authenticator: authenticator.Config{
			Lambda:  m.AuthenticatorLambda,
			Epsilon: m.AuthenticatorEpsilon,
		},
		FloodSigma:           m.FloodSigma,
		ExtraRotationIndices: m.ExtraRotationIndices,
		InputLevel:           m.InputLevel,
	}, nil
}

func equalIntSlice(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
