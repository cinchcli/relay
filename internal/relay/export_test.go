package relay

import (
	"database/sql"
	"net/http"
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
func EncodeStateForTest(userCode, clientSecret string) string {
	return encodeState(userCode, clientSecret)
}

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
		`INSERT OR IGNORE INTO clip_tombstones (clip_id, user_id, deleted_at) VALUES (?, ?, ?)`,
		clipID, userID, deletedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// DB exposes the underlying *sql.DB for tests.
func (s *Store) DB() *sql.DB { return s.db }

// NewTestOAuthProvider creates an OAuthProvider with a fake token endpoint and
// an injected subjectFetcher — no real OAuth round-trip needed in tests.
func NewTestOAuthProvider(clientSecret, tokenURL, redirectURL string, fetcher func(string, *oauth2.Config, *oauth2.Token) (string, error)) *OAuthProvider {
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
		subjectFetcher: fetcher,
	}
}
