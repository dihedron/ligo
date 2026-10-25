package version

import "testing"

func TestRelevantEnv(t *testing.T) {
	tests := []struct {
		env, want string
		ok        bool
	}{
		{"LIGO_DOTENV=/etc/ligo/.env", "LIGO_DOTENV=/etc/ligo/.env", true},
		{"LIGO_LOG_LEVEL=debug", "LIGO_LOG_LEVEL=debug", true},
		{"LIGO_TRUST_PASSWORD=hunter2", "LIGO_TRUST_PASSWORD=********", true},
		{"LIGO_CLIENT_SECRET=s3cr3t", "LIGO_CLIENT_SECRET=********", true},
		{"OS_AUTH_URL=https://keystone:5000/v3", "", false},
		{"HOME=/root", "", false},
		{"MIDPOINT_PASSWORD=x", "", false},
	}
	for _, tt := range tests {
		got, ok := relevantEnv(tt.env)
		if got != tt.want || ok != tt.ok {
			t.Errorf("relevantEnv(%q) = %q, %v; want %q, %v", tt.env, got, ok, tt.want, tt.ok)
		}
	}
}
