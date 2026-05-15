package authenticator

import (
	"bytes"
	"crypto/rand"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyGenShape(t *testing.T) {
	cfg := Config{Lambda: 16, Epsilon: 1024}
	k, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	assert.Len(t, k.S, cfg.Lambda/2)
	// distinct
	seen := map[int]bool{}
	for _, idx := range k.S {
		assert.False(t, seen[idx], "duplicate index %d", idx)
		seen[idx] = true
		assert.GreaterOrEqual(t, idx, 0)
		assert.Less(t, idx, cfg.Lambda)
	}
	// sorted ascending
	sorted := append([]int(nil), k.S...)
	sort.Ints(sorted)
	assert.Equal(t, sorted, k.S, "S must be sorted ascending")

	// SeedF is 32 bytes; not all zeros with crypto/rand source.
	assert.NotEqual(t, [32]byte{}, k.SeedF)
}

func TestKeyGenInvalidCfg(t *testing.T) {
	_, err := KeyGen(Config{Lambda: 7, Epsilon: 1}, rand.Reader)
	require.Error(t, err)
	_, err = KeyGen(Config{Lambda: 0, Epsilon: 1}, rand.Reader)
	require.Error(t, err)
}

func TestKeyGenNilRand(t *testing.T) {
	_, err := KeyGen(Config{Lambda: 16, Epsilon: 1}, nil)
	require.Error(t, err)
}

func TestKeyRoundTrip(t *testing.T) {
	cfg := Config{Lambda: 32, Epsilon: 1024}
	k, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)

	data, err := k.MarshalBinary()
	require.NoError(t, err)

	var got Key
	require.NoError(t, got.UnmarshalBinary(data))
	assert.Equal(t, k.S, got.S)
	assert.Equal(t, k.SeedF, got.SeedF)
}

func TestKeyUnmarshalTruncated(t *testing.T) {
	cfg := Config{Lambda: 16, Epsilon: 1024}
	k, err := KeyGen(cfg, rand.Reader)
	require.NoError(t, err)
	data, err := k.MarshalBinary()
	require.NoError(t, err)

	t.Run("header-only", func(t *testing.T) {
		var got Key
		require.Error(t, got.UnmarshalBinary(data[:keyHeaderSize-1]))
	})
	t.Run("missing seed", func(t *testing.T) {
		var got Key
		require.Error(t, got.UnmarshalBinary(data[:len(data)-1]))
	})
	t.Run("bad magic", func(t *testing.T) {
		tampered := append([]byte(nil), data...)
		tampered[0] ^= 0xFF
		var got Key
		require.Error(t, got.UnmarshalBinary(tampered))
	})
}

func TestKeyUnmarshalLenMismatch(t *testing.T) {
	// Construct a payload where the header says |S| != Lambda/2.
	k := Key{S: []int{0, 1, 2, 3, 4, 5, 6, 7}}
	for i := range k.SeedF {
		k.SeedF[i] = byte(i)
	}
	data, err := k.MarshalBinary()
	require.NoError(t, err)

	// Round-trip works.
	var got Key
	require.NoError(t, got.UnmarshalBinary(data))

	// Tamper the |S| field to claim 9 instead of 8.
	bad := append([]byte(nil), data...)
	bad[10] = 9
	bad[11], bad[12], bad[13] = 0, 0, 0
	require.Error(t, got.UnmarshalBinary(bad))
}

func TestKeyMarshalSortsAscending(t *testing.T) {
	// Even if caller stores S out of order, the wire form is sorted.
	k := Key{S: []int{3, 0, 1, 2}}
	for i := range k.SeedF {
		k.SeedF[i] = byte(i)
	}
	data, err := k.MarshalBinary()
	require.NoError(t, err)

	var got Key
	require.NoError(t, got.UnmarshalBinary(data))
	assert.Equal(t, []int{0, 1, 2, 3}, got.S)

	// Two keys with the same S in different order produce equal bytes.
	k2 := Key{S: []int{2, 3, 0, 1}, SeedF: k.SeedF}
	data2, err := k2.MarshalBinary()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, data2))
}

func TestKeyMarshalRejectsBadS(t *testing.T) {
	t.Run("duplicate", func(t *testing.T) {
		k := Key{S: []int{0, 0, 1, 2}}
		_, err := k.MarshalBinary()
		require.Error(t, err)
	})
	t.Run("out of range", func(t *testing.T) {
		// |S|=4 implies Lambda=8; index 8 is out of [0, 8).
		k := Key{S: []int{0, 1, 2, 8}}
		_, err := k.MarshalBinary()
		require.Error(t, err)
	})
	t.Run("empty", func(t *testing.T) {
		k := Key{}
		_, err := k.MarshalBinary()
		require.Error(t, err)
	})
}
