package relay

import (
	"database/sql"

	"golang.org/x/oauth2"
)

// ExecForTest exposes raw SQL execution for tests only. Do not use in production code.
func (s *Store) ExecForTest(query string, args ...interface{}) (sql.Result, error) {
	return s.db.Exec(query, args...)
}

// EncodeStateForTest exposes encodeState for oauth_test.go.
func EncodeStateForTest(userCode, clientSecret string) string {
	return encodeState(userCode, clientSecret)
}

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
