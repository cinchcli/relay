package relay

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// ApplyBootstrapInvite installs the env-provided invite code as a single-use
// 7-day invite IFF the relay has zero users. Safe to call on every startup.
// Writes a status line to log.
func ApplyBootstrapInvite(s *Store, code string, log io.Writer) error {
	if code == "" {
		return nil
	}
	n, err := s.CountUsers()
	if err != nil {
		return fmt.Errorf("counting users: %w", err)
	}
	if n > 0 {
		fmt.Fprintln(log, "RELAY_BOOTSTRAP_INVITE_CODE ignored — users already exist; bootstrap already complete")
		return nil
	}
	hash := HashInviteCode(code)
	exp := time.Now().Add(7 * 24 * time.Hour)
	if err := s.CreateInvite(hash, nil, "bootstrap", 1, exp); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			fmt.Fprintln(log, "bootstrap invite already present in DB (restart before redemption)")
			return nil
		}
		return fmt.Errorf("creating bootstrap invite: %w", err)
	}
	fmt.Fprintf(log, "bootstrap invite installed; expires %s\n", exp.UTC().Format(time.RFC3339))
	return nil
}
