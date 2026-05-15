// Package rservice owns the gated resource and receives verdicts from
// VAgent. Missing sids resolve to VerdictUnknown — indistinguishable
// from "verification still in flight". See docs/DESIGN.md
// §`internal/rservice`.
package rservice

import (
	"fmt"
	"sync"

	"github.com/butvinm/ppiav/internal/protocol"
)

// Service stores the latest verdict per session id. Concurrency-safe.
type Service struct {
	sessions map[protocol.SessionID]protocol.Verdict
	mu       sync.Mutex
}

// New constructs a Service with an empty verdict table.
func New() *Service {
	return &Service{
		sessions: map[protocol.SessionID]protocol.Verdict{},
	}
}

// AcceptVerdict upserts the verdict for sid. VerdictUnknown is rejected:
// deny-by-default belongs to absent entries, not stored ones.
func (s *Service) AcceptVerdict(sid protocol.SessionID, v protocol.Verdict) error {
	if v == protocol.VerdictUnknown {
		return fmt.Errorf("rservice: refuse to store VerdictUnknown for sid %q", sid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sid] = v
	return nil
}

// CheckAccess returns the stored verdict for sid, or VerdictUnknown if
// none was recorded yet.
func (s *Service) CheckAccess(sid protocol.SessionID) protocol.Verdict {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[sid]
	if !ok {
		return protocol.VerdictUnknown
	}
	return v
}
