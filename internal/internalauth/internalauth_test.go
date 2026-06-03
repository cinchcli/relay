package internalauth

import "testing"

func TestCheck(t *testing.T) {
	const (
		legacy = "legacy-shared-secret"
		write  = "write-only-secret"
	)
	tests := []struct {
		name   string
		header string
		specs  []string
		want   Result
	}{
		{"no secret configured is disabled", "Bearer anything", []string{"", ""}, Disabled},
		{"only empty candidates is disabled", "Bearer x", []string{" , , "}, Disabled},
		{"configured but missing token is denied", "", []string{legacy}, Denied},
		{"configured but wrong token is denied", "Bearer wrong", []string{legacy}, Denied},
		{"matches specific write secret", "Bearer " + write, []string{write, legacy}, OK},
		{"matches legacy fallback secret", "Bearer " + legacy, []string{write, legacy}, OK},
		{"dual-accept matches new", "Bearer new", []string{"new,prev"}, OK},
		{"dual-accept matches prev", "Bearer prev", []string{"new,prev"}, OK},
		{"candidates are whitespace-trimmed", "Bearer s3cret", []string{"  s3cret , other "}, OK},
		{"raw header without Bearer prefix is still compared", legacy, []string{legacy}, OK},
		{"write-only secret does not accept a read-only token", "Bearer read-only", []string{write}, Denied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Check(tt.header, tt.specs...); got != tt.want {
				t.Fatalf("Check(%q, %v) = %v, want %v", tt.header, tt.specs, got, tt.want)
			}
		})
	}
}
