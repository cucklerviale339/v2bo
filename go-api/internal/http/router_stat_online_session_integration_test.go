package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/session"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
)

type onlineSessionIntegrationService struct {
	*fakeAdminService
	statsCalls int
	usersCalls int
}

func (s *onlineSessionIntegrationService) GetOnlineStats(context.Context) (admin.OnlineStats, error) {
	s.statsCalls++
	return admin.OnlineStats{}, nil
}

func (s *onlineSessionIntegrationService) GetOnlineUsers(context.Context, admin.OnlineUsersRequest) (admin.OnlineUsers, error) {
	s.usersCalls++
	return admin.OnlineUsers{}, nil
}

func TestOnlineHTTPRealSessionRejectsRevocationDespiteWarmAdminCache(t *testing.T) {
	const identityQuery = `SELECT u.id, u.email, u.is_admin, u.is_staff
FROM v2_auth_session s
JOIN v2_user u ON u.id = s.user_id
WHERE s.user_id = $1 AND s.session_id = $2 AND (s.expire_at = 0 OR s.expire_at > $3) AND u.banned = 0
LIMIT 1`
	for _, endpoint := range []string{"/stat/online", "/stat/online/users"} {
		for _, scenario := range []struct {
			name       string
			hasSession bool
			isStaff    int64
		}{
			{name: "demoted_to_user", hasSession: true},
			{name: "demoted_to_staff", hasSession: true, isStaff: 1},
			{name: "session_revoked"},
		} {
			t.Run(endpoint+"/"+scenario.name, func(t *testing.T) {
				db, mock, err := sqlmock.New()
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()

				cfg := config.Config{AppKey: "online-session-integration-secret", AdminPath: "online-admin"}
				const userID int64 = 7
				const sessionID = "online-admin-session"
				token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"id": userID, "session": sessionID, "exp": time.Now().Add(time.Hour).Unix(),
				}).SignedString([]byte(cfg.AppKey))
				if err != nil {
					t.Fatal(err)
				}
				cache := session.NewAuthCache(time.Hour)
				sessions := session.NewDBService(cfg, db).WithAuthCache(cache)
				columns := []string{"id", "email", "is_admin", "is_staff"}

				// Populate the real cache through the production authentication path.
				mock.ExpectQuery(regexp.QuoteMeta(identityQuery)).
					WithArgs(userID, sessionID, sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows(columns).AddRow(userID, "admin@example.test", int64(1), int64(0)))
				if identity, err := sessions.Authenticate(context.Background(), token, true); err != nil || identity == nil || identity.IsAdmin != 1 {
					t.Fatalf("warm administrator cache: identity=%+v err=%v", identity, err)
				}
				if identity, ok := cache.Get(token); !ok || identity.IsAdmin != 1 {
					t.Fatalf("administrator cache was not populated: identity=%+v hit=%v", identity, ok)
				}
				// No database expectation: ordinary authentication must still accept
				// the stale cached administrator, making the regression deterministic.
				if identity, err := sessions.Authenticate(context.Background(), token, true); err != nil || identity == nil || identity.IsAdmin != 1 {
					t.Fatalf("cached administrator unavailable: identity=%+v err=%v", identity, err)
				}

				// The HTTP request must query current database state despite that cache.
				currentRows := sqlmock.NewRows(columns)
				if scenario.hasSession {
					currentRows.AddRow(userID, "admin@example.test", int64(0), scenario.isStaff)
				}
				mock.ExpectQuery(regexp.QuoteMeta(identityQuery)).
					WithArgs(userID, sessionID, sqlmock.AnyArg()).WillReturnRows(currentRows)

				business := &onlineSessionIntegrationService{fakeAdminService: &fakeAdminService{}}
				router := NewRouter(cfg, WithSessionService(sessions), WithAdminService(business))
				request := httptest.NewRequest(http.MethodGet, "/api/v1/online-admin"+endpoint, nil)
				request.Header.Set("Authorization", "Bearer "+token)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)

				if response.Code != http.StatusForbidden {
					t.Errorf("revoked administrator: status=%d want=%d body=%s", response.Code, http.StatusForbidden, response.Body.String())
				}
				if business.statsCalls != 0 || business.usersCalls != 0 {
					t.Errorf("revoked administrator reached business methods: stats=%d users=%d", business.statsCalls, business.usersCalls)
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Errorf("fresh database identity lookup: %v", err)
				}
			})
		}
	}
}
