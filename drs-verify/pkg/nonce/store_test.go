package nonce

import (
	"testing"
	"time"
)

func TestCheck_FirstCallSucceeds(t *testing.T) {
	s := New(100, time.Hour)
	if err := s.Check("inv:abc123"); err != nil {
		t.Fatalf("first Check should succeed, got: %v", err)
	}
}
