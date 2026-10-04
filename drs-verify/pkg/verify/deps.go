package verify

import (
	"errors"
	"fmt"
	"time"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/resolver"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/revocation"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/store"
)

// Defaults used by NewDefaultDeps. They match the drs-verify service defaults.
const (
	defaultDIDCacheSize     = 10_000
	defaultDIDCacheTTL      = time.Hour
	defaultBreakerThreshold = 5
	defaultBreakerCooldown  = time.Minute
	defaultMaxInvocationAge = 15 * time.Minute
)

// NewDefaultDeps builds the dependencies an embedded verifier needs: an
// LRU-bounded DID resolver with circuit breaker, in-memory local revocation,
// and an in-memory receipt store. serverIdentity is required — without it an
// invocation addressed to a different tool server would be accepted.
func NewDefaultDeps(serverIdentity string) (Deps, error) {
	if serverIdentity == "" {
		return Deps{}, errors.New("serverIdentity is required")
	}
	res, err := resolver.NewWithCircuitBreaker(defaultDIDCacheSize, defaultDIDCacheTTL,
		defaultBreakerThreshold, defaultBreakerCooldown)
	if err != nil {
		return Deps{}, fmt.Errorf("resolver: %w", err)
	}
	memStore, err := store.NewMemoryStore(0)
	if err != nil {
		return Deps{}, fmt.Errorf("store: %w", err)
	}
	return Deps{
		Resolver:         res,
		LocalRevocation:  revocation.NewLocalRevocationStore(),
		Store:            memStore,
		ServerIdentity:   serverIdentity,
		MaxInvocationAge: defaultMaxInvocationAge,
	}, nil
}
