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
	s.nodeAddressEnsureMu.Lock()
	defer s.nodeAddressEnsureMu.Unlock()
	if s.nodeAddressSchemaOK {
		return nil
	}
	if err := platformpostgres.EnsureNodeAddressSchema(ctx, s.db); err != nil {
		return fmt.Errorf("ensure node address schema: %w", err)
	}
	s.nodeAddressSchemaOK = true
	return nil
}
