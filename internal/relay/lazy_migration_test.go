// Lazy-migration tests removed in the OAuth-only migration. The
// users.token / token_migrated_at / grace-sweeper machinery they
// exercised was retired. Task 5 deletes this file (and grace_sweeper.go)
// outright; it is left empty here so the package builds in the meantime.

package relay
