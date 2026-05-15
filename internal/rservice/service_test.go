package rservice

import (
	"fmt"
	"sync"
	"testing"

	"github.com/butvinm/ppiav/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAccess_Missing(t *testing.T) {
	s := New()
	assert.Equal(t, protocol.VerdictUnknown, s.CheckAccess("nope"))
}

func TestAcceptVerdict_Accept(t *testing.T) {
	s := New()
	require.NoError(t, s.AcceptVerdict("sid-1", protocol.VerdictAccept))
	assert.Equal(t, protocol.VerdictAccept, s.CheckAccess("sid-1"))
}

func TestAcceptVerdict_Reject(t *testing.T) {
	s := New()
	require.NoError(t, s.AcceptVerdict("sid-1", protocol.VerdictReject))
	assert.Equal(t, protocol.VerdictReject, s.CheckAccess("sid-1"))
}

func TestAcceptVerdict_UpsertLatestWins(t *testing.T) {
	cases := []struct {
		name  string
		first protocol.Verdict
		last  protocol.Verdict
	}{
		{"accept-then-reject", protocol.VerdictAccept, protocol.VerdictReject},
		{"reject-then-accept", protocol.VerdictReject, protocol.VerdictAccept},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New()
			require.NoError(t, s.AcceptVerdict("sid", tc.first))
			require.NoError(t, s.AcceptVerdict("sid", tc.last))
			assert.Equal(t, tc.last, s.CheckAccess("sid"))
		})
	}
}

func TestAcceptVerdict_UnknownRejected(t *testing.T) {
	s := New()
	// First land a real verdict to confirm it survives an Unknown attempt.
	require.NoError(t, s.AcceptVerdict("sid", protocol.VerdictAccept))

	err := s.AcceptVerdict("sid", protocol.VerdictUnknown)
	require.Error(t, err)

	// State must not have been mutated.
	assert.Equal(t, protocol.VerdictAccept, s.CheckAccess("sid"))

	// Also confirm a fresh sid stays absent rather than landing as Unknown.
	err = s.AcceptVerdict("fresh", protocol.VerdictUnknown)
	require.Error(t, err)
	assert.Equal(t, protocol.VerdictUnknown, s.CheckAccess("fresh"))
}

func TestAcceptVerdict_Concurrent(t *testing.T) {
	const n = 100
	s := New()

	var wg sync.WaitGroup
	wg.Add(2 * n)

	for i := 0; i < n; i++ {
		sid := protocol.SessionID(fmt.Sprintf("writer-%d", i))
		go func(sid protocol.SessionID) {
			defer wg.Done()
			if err := s.AcceptVerdict(sid, protocol.VerdictAccept); err != nil {
				t.Errorf("AcceptVerdict(%q): %v", sid, err)
			}
		}(sid)
	}

	for i := 0; i < n; i++ {
		sid := protocol.SessionID(fmt.Sprintf("reader-%d", i))
		go func(sid protocol.SessionID) {
			defer wg.Done()
			_ = s.CheckAccess(sid)
		}(sid)
	}

	wg.Wait()

	// Verify each writer's verdict landed.
	for i := 0; i < n; i++ {
		sid := protocol.SessionID(fmt.Sprintf("writer-%d", i))
		assert.Equal(t, protocol.VerdictAccept, s.CheckAccess(sid), sid)
	}
}
