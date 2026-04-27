package relay

import "database/sql"

// ExecForTest exposes raw SQL execution for tests only. Do not use in production code.
func (s *Store) ExecForTest(query string, args ...interface{}) (sql.Result, error) {
	return s.db.Exec(query, args...)
}
