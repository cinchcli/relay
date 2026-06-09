package relay

import "testing"

// TestNewOAuthProviders_ScopesIncludeName guards the OAuth scopes needed to
// fetch the user's display name. GitHub needs read:user (so /user returns the
// "name" field; user:email stays for the verified address) and Google needs
// profile (so userinfo returns "name"; openid+email alone yield only sub+email).
//
// Lives in the internal (package relay) test set because it inspects the
// unexported OAuthProvider.cfg.Scopes directly.
func TestNewOAuthProviders_ScopesIncludeName(t *testing.T) {
	p := NewOAuthProviders("https://relay.example.com", "gh-id", "gh-secret", "g-id", "g-secret")
	hasScope := func(scopes []string, want string) bool {
		for _, s := range scopes {
			if s == want {
				return true
			}
		}
		return false
	}
	if p.GitHub == nil || p.Google == nil {
		t.Fatal("expected both GitHub and Google providers to be configured")
	}
	if !hasScope(p.GitHub.cfg.Scopes, "read:user") || !hasScope(p.GitHub.cfg.Scopes, "user:email") {
		t.Errorf("GitHub scopes = %v, want both read:user and user:email", p.GitHub.cfg.Scopes)
	}
	if !hasScope(p.Google.cfg.Scopes, "profile") {
		t.Errorf("Google scopes = %v, want profile included", p.Google.cfg.Scopes)
	}
}
