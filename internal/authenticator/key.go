package authenticator

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// keyMagic identifies the MarshalBinary format.
var keyMagic = [4]byte{'P', 'P', 'A', 'K'}

// keyHeaderSize is the fixed-size header: magic(4) + version(2) + lambda(4)
// + |S|(4).
const keyHeaderSize = 4 + 2 + 4 + 4

// keySerVersion is the on-wire version of the Key encoding.
const keySerVersion uint16 = 1

// Key is the per-authentication secret: the verification-slot index set S
// (|S| = Lambda/2) and the PRG seed for F. S is stored sorted ascending so
// equality testing is deterministic.
type Key struct {
	S     []int
	SeedF [32]byte
}

// MarshalBinary serialises Key as: header (magic|version|Lambda|len(S)),
// S as little-endian uint32s in ascending order, then SeedF. Lambda is
// inferred from len(S) (|S| = Lambda/2) — UnmarshalBinary uses the embedded
// Lambda to validate that len(S) matches.
func (k Key) MarshalBinary() ([]byte, error) {
	if len(k.S) == 0 {
		return nil, fmt.Errorf("authenticator: Key.S is empty")
	}
	lambda := 2 * len(k.S)
	sorted := make([]int, len(k.S))
	copy(sorted, k.S)
	sort.Ints(sorted)
	if sorted[0] < 0 || sorted[len(sorted)-1] >= lambda {
		return nil, fmt.Errorf("authenticator: Key.S indices out of [0, %d)", lambda)
	}
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return nil, fmt.Errorf("authenticator: Key.S has duplicate index %d", sorted[i])
		}
	}

	out := make([]byte, 0, keyHeaderSize+4*len(sorted)+32)
	out = append(out, keyMagic[:]...)
	out = binary.LittleEndian.AppendUint16(out, keySerVersion)
	out = binary.LittleEndian.AppendUint32(out, uint32(lambda))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(sorted)))
	for _, idx := range sorted {
		out = binary.LittleEndian.AppendUint32(out, uint32(idx))
	}
	out = append(out, k.SeedF[:]...)
	return out, nil
}

// UnmarshalBinary inverts MarshalBinary and validates len(S) == Lambda/2
// and S ⊂ [0, Lambda) with no duplicates.
func (k *Key) UnmarshalBinary(data []byte) error {
	if len(data) < keyHeaderSize {
		return fmt.Errorf("authenticator: Key truncated header: need %d bytes, got %d", keyHeaderSize, len(data))
	}
	if [4]byte{data[0], data[1], data[2], data[3]} != keyMagic {
		return fmt.Errorf("authenticator: Key bad magic")
	}
	ver := binary.LittleEndian.Uint16(data[4:6])
	if ver != keySerVersion {
		return fmt.Errorf("authenticator: Key unsupported version %d", ver)
	}
	lambda := int(binary.LittleEndian.Uint32(data[6:10]))
	sLen := int(binary.LittleEndian.Uint32(data[10:14]))
	if lambda <= 0 || lambda%2 != 0 {
		return fmt.Errorf("authenticator: Key invalid Lambda %d", lambda)
	}
	if sLen != lambda/2 {
		return fmt.Errorf("authenticator: Key len(S)=%d does not match Lambda/2=%d", sLen, lambda/2)
	}
	want := keyHeaderSize + 4*sLen + 32
	if len(data) != want {
		return fmt.Errorf("authenticator: Key truncated body: want %d bytes, got %d", want, len(data))
	}

	s := make([]int, sLen)
	off := keyHeaderSize
	var prev int = -1
	for i := 0; i < sLen; i++ {
		v := int(binary.LittleEndian.Uint32(data[off : off+4]))
		off += 4
		if v < 0 || v >= lambda {
			return fmt.Errorf("authenticator: Key S[%d]=%d out of [0, %d)", i, v, lambda)
		}
		if i > 0 && v <= prev {
			return fmt.Errorf("authenticator: Key S not strictly ascending at index %d", i)
		}
		s[i] = v
		prev = v
	}

	var seed [32]byte
	copy(seed[:], data[off:off+32])

	k.S = s
	k.SeedF = seed
	return nil
}

// KeyGen samples a fresh Key from the supplied randomness source. S is
// |cfg.Lambda/2| distinct indices drawn without replacement from
// [0, Lambda) via partial Fisher-Yates; SeedF is 32 bytes from rand.
// Returned S is sorted ascending for deterministic equality.
func KeyGen(cfg Config, rand io.Reader) (Key, error) {
	if err := cfg.validate(); err != nil {
		return Key{}, err
	}
	if rand == nil {
		return Key{}, fmt.Errorf("authenticator: KeyGen rand is nil")
	}
	lambda := cfg.Lambda
	half := lambda / 2

	pool := make([]int, lambda)
	for i := range pool {
		pool[i] = i
	}

	// Partial Fisher-Yates: for i in [0, half), pick j in [i, lambda) and swap.
	for i := 0; i < half; i++ {
		span := uint64(lambda - i)
		j, err := readBoundedUint64(rand, span)
		if err != nil {
			return Key{}, fmt.Errorf("authenticator: KeyGen sample S: %w", err)
		}
		idx := i + int(j)
		pool[i], pool[idx] = pool[idx], pool[i]
	}

	s := make([]int, half)
	copy(s, pool[:half])
	sort.Ints(s)

	var seed [32]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return Key{}, fmt.Errorf("authenticator: KeyGen seedF: %w", err)
	}
	return Key{S: s, SeedF: seed}, nil
}

// readBoundedUint64 returns a uniformly random integer in [0, bound) using
// rejection sampling. bound must be > 0.
func readBoundedUint64(rand io.Reader, bound uint64) (uint64, error) {
	if bound == 0 {
		return 0, fmt.Errorf("authenticator: bound must be > 0")
	}
	// Largest multiple of bound that fits in uint64.
	limit := (^uint64(0) / bound) * bound
	var buf [8]byte
	for {
		if _, err := io.ReadFull(rand, buf[:]); err != nil {
			return 0, err
		}
		v := binary.LittleEndian.Uint64(buf[:])
		if v < limit {
			return v % bound, nil
		}
	}
}
