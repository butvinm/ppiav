package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerdictString(t *testing.T) {
	cases := []struct {
		v    Verdict
		want string
	}{
		{VerdictUnknown, "unknown"},
		{VerdictAccept, "accept"},
		{VerdictReject, "reject"},
		{Verdict(99), "invalid"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			assert.Equal(t, c.want, c.v.String())
		})
	}
}

func TestVerdictConstants(t *testing.T) {
	// Pin the iota ordering — wire-format stability.
	assert.Equal(t, Verdict(0), VerdictUnknown)
	assert.Equal(t, Verdict(1), VerdictAccept)
	assert.Equal(t, Verdict(2), VerdictReject)
}
