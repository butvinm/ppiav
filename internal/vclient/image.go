package vclient

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// ImageLen is the exact length of the preprocessed image tensor consumed
// by EncryptImage: 3 channels × 64 × 64 pixels = 12288 float64. See
// docs/DESIGN.md §`internal/vclient` "Image preprocessing contract".
const ImageLen = 3 * 64 * 64

// EncryptImage encodes and encrypts the preprocessed image tensor under
// the aggregated session pk. Zero-padding is applied to fill the slot
// vector up to `params.CKKS.MaxSlots()` (32768 at LogN=16, 8192 at
// LogN=14). Wrong-length input is a HARD error — silent padding of a
// wrong-shape tensor would yield syntactically valid but semantically
// garbage inference output. See docs/DESIGN.md §`internal/vclient`.
//
// Encryption level: when `params.InputLevel == 0` the plaintext is built
// at `MaxLevel` (synthetic-x² default — no compiled circuit constrains
// the budget). When `InputLevel > 0` we encrypt at exactly that level so
// Orion's compiled circuit sees the input at the level it was compiled
// for; encrypting higher would desync Orion's level accounting.
func (c *Client) EncryptImage(image []float64) (*rlwe.Ciphertext, error) {
	if len(image) != ImageLen {
		return nil, fmt.Errorf("vclient: image length must be %d, got %d", ImageLen, len(image))
	}
	if c.encryptor == nil {
		return nil, fmt.Errorf("vclient: encryptor not ready (call AggregatePK first)")
	}

	maxSlots := c.params.CKKS.MaxSlots()
	values := make([]float64, maxSlots)
	copy(values, image)

	level := c.params.InputLevel
	if level <= 0 {
		level = c.params.CKKS.MaxLevel()
	}
	pt := ckks.NewPlaintext(c.params.CKKS, level)
	if err := c.encoder.Encode(values, pt); err != nil {
		return nil, fmt.Errorf("vclient: encode image: %w", err)
	}
	ct, err := c.encryptor.EncryptNew(pt)
	if err != nil {
		return nil, fmt.Errorf("vclient: encrypt image: %w", err)
	}
	return ct, nil
}
