package relay

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// DeriveRelayURLForTest exposes deriveRelayURL for url-derivation unit tests.
func DeriveRelayURLForTest(r *http.Request) string { return deriveRelayURL(r) }

// DeriveWSURLForTest exposes deriveWSURL for url-derivation unit tests.
func DeriveWSURLForTest(r *http.Request) string { return deriveWSURL(r) }

// ExecForTest exposes raw SQL execution for tests only. Do not use in production code.
func (s *Store) ExecForTest(query string, args ...interface{}) (sql.Result, error) {
	return s.db.Exec(query, args...)
}

// EncodeStateForTest exposes encodeState for oauth_test.go.
func EncodeStateForTest(userCode, nonce, clientSecret string) string {
	return encodeState(userCode, nonce, clientSecret)
}

// OAuthStateCookieName exposes the per-flow nonce cookie name for oauth_test.go.
func OAuthStateCookieName() string { return oauthStateCookie }

// IssueWsTicketForTest exposes issueWsTicket for white-box unit tests.
func IssueWsTicketForTest(userID, deviceID string) string {
	return issueWsTicket(userID, deviceID)
}

// ConsumeWsTicketForTest exposes consumeWsTicket for white-box unit tests.
func ConsumeWsTicketForTest(ticket string) (userID, deviceID string, ok bool) {
	return consumeWsTicket(ticket)
}

// InsertTombstoneAt inserts a tombstone with a specific deleted_at timestamp.
// Used only in tests to simulate aged tombstones for sweep verification.
func (s *Store) InsertTombstoneAt(userID, clipID string, deletedAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO clip_tombstones (clip_id, user_id, deleted_at) VALUES ($1, $2, $3) ON CONFLICT(clip_id) DO NOTHING`,
		clipID, userID, deletedAt.UTC(),
	)
	return err
}

// NewTestStore creates a Store backed by TEST_DATABASE_URL for external package tests.
// Skips the test if TEST_DATABASE_URL is not set.
func NewTestStore(t *testing.T) *Store { return newTestStore(t) }

// DB exposes the underlying *sql.DB for tests.
func (s *Store) DB() *sql.DB { return s.db }

// FetchOAuthIdentityForTest exposes fetchOAuthIdentity for unit tests that stub
// the provider HTTP endpoints via httptest. Callers inject a custom http.Client
// (with a host-rewriting transport) into ctx via context.WithValue and the
// oauth2.HTTPClient key so that provider API calls are redirected to a local
// httptest.Server.
func FetchOAuthIdentityForTest(ctx context.Context, providerName string, cfg *oauth2.Config, tok *oauth2.Token) (subject, email, displayName string, emailVerified bool, err error) {
	return fetchOAuthIdentity(ctx, providerName, cfg, tok)
}

// NewTestOAuthProvider creates an OAuthProvider with a fake token endpoint and
// an injected identityFetcher — no real OAuth round-trip needed in tests.
// The fetcher signature matches identityFetcher: (ctx, providerName, cfg, tok).
// To keep existing call sites concise, callers supply a legacy 4-return closure
// (subject, email, emailVerified, err) and this wrapper adapts it to the new 5-return
// signature with an empty displayName.
func NewTestOAuthProvider(clientSecret, tokenURL, redirectURL string, fetcher func(string, *oauth2.Config, *oauth2.Token) (string, string, bool, error)) *OAuthProvider {
	adapted := func(ctx context.Context, providerName string, cfg *oauth2.Config, tok *oauth2.Token) (string, string, string, bool, error) {
		subject, email, emailVerified, err := fetcher(providerName, cfg, tok)
		return subject, email, "", emailVerified, err
	}
	return &OAuthProvider{
		clientSecret: clientSecret,
		cfg: &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				TokenURL:  tokenURL,
				AuthURL:   tokenURL + "/auth",
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL: redirectURL,
		},
		identityFetcher: adapted,
	}
}
