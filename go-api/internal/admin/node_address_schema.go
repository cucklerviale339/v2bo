package admin

import (
	"context"
	"fmt"

	platformpostgres "forest/go-api/internal/platform/postgres"
)

func (s *DBService) ensureNodeAddressSchema(ctx context.Context) error {
	if s.db == nil {
		return ErrUnavailable
	}
	s.nodeAddressEnsureOnce.Do(func() {
		if err := platformpostgres.EnsureNodeAddressSchema(ctx, s.db); err != nil {
			s.nodeAddressEnsureErr = fmt.Errorf("ensure node address schema: %w", err)
		}
	})
	return s.nodeAddressEnsureErr
}
