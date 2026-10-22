package relay

import "testing"

func TestLoadConfigHTTPAddress(t *testing.T) {
	for _, tc := range []struct {
		name, port, addr, portFlag, want string
	}{
		{"default", "", "", "", ":8080"},
		{"port env", "4243", "", "", ":4243"},
		{"port flag", "8080", "", "9000", ":9000"},
		{"explicit interface", "8080", "100.72.59.53:4243", "", "100.72.59.53:4243"},
		{"explicit interface overrides port flag", "8080", "100.72.59.53:4243", "9000", "100.72.59.53:4243"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PORT", tc.port)
			t.Setenv("LISTEN_ADDR", tc.addr)
			cfg := LoadConfig()
			if tc.portFlag != "" {
				cfg.Port = tc.portFlag
			}
			if got := cfg.HTTPAddress(); got != tc.want {
				t.Fatalf("HTTPAddress = %q, want %q", got, tc.want)
			}
		})
	}
}
