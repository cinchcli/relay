package relay

import (
	"fmt"
	"os"
	"testing"
)

// TestMain fails loudly when TEST_DATABASE_URL is unset instead of letting the
// DB-backed tests silently t.Skip(). Roughly 80% of this package's tests need
// Postgres; a "PASS" with most of them skipped is a false green that has hidden
// regressions before. CI always provisions Postgres (see .github/workflows/ci.yml),
// and local runs should go through `make test-db`, which starts a container and
// exports TEST_DATABASE_URL.
func TestMain(m *testing.M) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		fmt.Fprint(os.Stderr,
			"\nERROR: TEST_DATABASE_URL is not set — the relay test suite requires Postgres.\n"+
				"Run `make test-db` (starts a container and sets TEST_DATABASE_URL), or set it manually:\n"+
				"  TEST_DATABASE_URL=postgres://cinch:cinch@localhost:5432/cinch?sslmode=disable go test ./internal/relay/...\n")
		os.Exit(1)
	}
	os.Exit(m.Run())
}
