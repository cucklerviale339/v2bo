package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"forest/go-api/internal/config"
	"github.com/DATA-DOG/go-sqlmock"
)

func TestAuthenticateFreshRechecksCachedAdministrator(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		admin, staff                      int64
		absent, unavailable, requireAdmin bool
		want                              error
	}{
		{name: "administrator", admin: 1, requireAdmin: true},
		{name: "demoted", requireAdmin: true, want: ErrUnauthorized},
		{name: "demoted to staff", staff: 1, requireAdmin: true, want: ErrUnauthorized},
		{name: "updated operator identity", staff: 1},
		{name: "revoked expired or banned", absent: true, requireAdmin: true, want: ErrUnauthorized},
		{name: "database unavailable fails closed", unavailable: true, requireAdmin: true, want: ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			cfg := config.Config{AppKey: "fresh-auth-unit-key"}
			token := signedAuthToken(t, cfg.AppKey, 9, "fresh-session")
			cache := NewAuthCache(time.Minute)
			cache.Store(token, "fresh-session", &Identity{ID: 9, Email: "cached@example.test", IsAdmin: 1})
			service := NewDBService(cfg, db).WithAuthCache(cache)
			if _, err := service.Authenticate(context.Background(), token, true); err != nil {
				t.Fatal(err)
			}
			rows := sqlmock.NewRows([]string{"id", "email", "is_admin", "is_staff"})
			if !tc.absent {
				rows.AddRow(9, "current@example.test", tc.admin, tc.staff)
			}
			query := mock.ExpectQuery("SELECT u.id, u.email, u.is_admin, u.is_staff").WithArgs(int64(9), "fresh-session", sqlmock.AnyArg())
			if tc.unavailable {
				query.WillReturnError(errors.New("db failed"))
			} else {
				query.WillReturnRows(rows)
			}
			identity, err := service.AuthenticateFresh(context.Background(), "Bearer "+token, tc.requireAdmin)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if tc.want != nil && identity != nil {
				t.Fatalf("failure returned identity: %#v", identity)
			}
			if tc.want == nil && (identity == nil || identity.Email != "current@example.test" || identity.IsAdmin != tc.admin || identity.IsStaff != tc.staff) {
				t.Fatalf("stale identity: %#v", identity)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthenticateFreshValidatesJWTDespiteCache(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cache := NewAuthCache(time.Minute)
	cache.Store("invalid-token", "session", &Identity{ID: 9, IsAdmin: 1})
	service := NewDBService(config.Config{AppKey: "fresh-auth-unit-key"}, db).WithAuthCache(cache)
	if identity, err := service.AuthenticateFresh(context.Background(), "invalid-token", true); !errors.Is(err, ErrUnauthorized) || identity != nil {
		t.Fatalf("identity=%#v err=%v", identity, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
