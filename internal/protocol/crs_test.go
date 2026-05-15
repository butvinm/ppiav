package protocol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionCRSDeterministic(t *testing.T) {
	sid := SessionID("abc123")

	prng1, err := NewSessionCRS(sid)
	require.NoError(t, err)
	prng2, err := NewSessionCRS(sid)
	require.NoError(t, err)

	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)
	_, err = prng1.Read(buf1)
	require.NoError(t, err)
	_, err = prng2.Read(buf2)
	require.NoError(t, err)

	assert.Equal(t, buf1, buf2)
}

func TestNewSessionCRSDifferentSids(t *testing.T) {
	prng1, err := NewSessionCRS("aaaaaaaa")
	require.NoError(t, err)
	prng2, err := NewSessionCRS("bbbbbbbb")
	require.NoError(t, err)

	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)
	_, err = prng1.Read(buf1)
	require.NoError(t, err)
	_, err = prng2.Read(buf2)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(buf1, buf2), "different sids must produce different CRS output")
}

func TestCanonicalRotationIndices(t *testing.T) {
	cases := []struct {
		lambda int
		want   []int
	}{
		{0, nil},
		{1, nil},
		{2, []int{1}},
		{4, []int{1, 2, 3}},
		{128, nil}, // checked below
	}
	for _, c := range cases {
		if c.lambda == 128 {
			got := CanonicalRotationIndices(128)
			assert.Len(t, got, 127)
			assert.Equal(t, 1, got[0])
			assert.Equal(t, 127, got[126])
			continue
		}
		assert.Equal(t, c.want, CanonicalRotationIndices(c.lambda))
	}
}
