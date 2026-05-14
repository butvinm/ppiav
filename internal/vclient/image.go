package vclient

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// imageLen is the exact length of the preprocessed image tensor consumed
// by EncryptImage: 3 channels × 64 × 64 pixels = 12288 float64. See
// docs/DESIGN.md §`internal/vclient` "Image preprocessing contract".
const imageLen = 3 * 64 * 64

// EncryptImage encodes and encrypts the preprocessed image tensor under
// the aggregated session pk. Zero-padding is applied to fill the slot
// vector up to `params.CKKS.MaxSlots()` (32768 at LogN=16, 8192 at
// LogN=14). Wrong-length input is a HARD error — silent padding of a
// wrong-shape tensor would yield syntactically valid but semantically
// garbage inference output. See docs/DESIGN.md §`internal/vclient`.
//
// Encryption level: Phase 1 uses `params.CKKS.MaxLevel()` because no
// compiled circuit is involved (the synthetic `x²` consumes a single
// level out of 15 — see §`Level budget — Phase 1`). Phase 2 will swap to
// the Orion manifest's `inputLevel`.
func (c *Client) EncryptImage(image []float64) (*rlwe.Ciphertext, error) {
	if len(image) != imageLen {
		return nil, fmt.Errorf("vclient: image length must be %d, got %d", imageLen, len(image))
	}
	if c.encryptor == nil {
		return nil, fmt.Errorf("vclient: encryptor not ready (call AggregatePK first)")
	}
	if c.encoder == nil {
		// Defensive: New always wires the encoder; this guard catches a
		// future refactor that forgets to.
		return nil, fmt.Errorf("vclient: encoder not initialised")
	}

	maxSlots := c.params.CKKS.MaxSlots()
	values := make([]float64, maxSlots)
	copy(values, image)

	pt := ckks.NewPlaintext(c.params.CKKS, c.params.CKKS.MaxLevel())
	if err := c.encoder.Encode(values, pt); err != nil {
		return nil, fmt.Errorf("vclient: encode image: %w", err)
	}
	ct, err := c.encryptor.EncryptNew(pt)
	if err != nil {
		return nil, fmt.Errorf("vclient: encrypt image: %w", err)
	}
	return ct, nil
}
