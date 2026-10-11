// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

func TestParseOAuthCredentials(t *testing.T) {
	tests := []struct {
		name         string
		secretValue  string
		wantClientID string
		wantSecret   string
		wantErr      bool
		errContains  string
	}{
		{
			name:         "valid credentials",
			secretValue:  `{"client_id":"my-client","client_secret":"my-secret"}`,
			wantClientID: "my-client",
			wantSecret:   "my-secret",
		},
		{
			name:        "missing client_id",
			secretValue: `{"client_secret":"my-secret"}`,
			wantErr:     true,
			errContains: "client_id is required",
		},
		{
			name:        "missing client_secret",
			secretValue: `{"client_id":"my-client"}`,
			wantErr:     true,
			errContains: "client_secret is required",
		},
		{
			name:        "empty client_id",
			secretValue: `{"client_id":"","client_secret":"my-secret"}`,
			wantErr:     true,
			errContains: "client_id is required",
		},
		{
			name:        "empty client_secret",
			secretValue: `{"client_id":"my-client","client_secret":""}`,
			wantErr:     true,
			errContains: "client_secret is required",
		},
		{
			name:        "both fields missing",
			secretValue: `{}`,
			wantErr:     true,
			errContains: "client_id is required",
		},
		{
			name:        "invalid JSON",
			secretValue: `{not valid json`,
			wantErr:     true,
			errContains: "failed to parse OAuth credentials JSON",
		},
		{
			name:        "empty string",
			secretValue: ``,
			wantErr:     true,
			errContains: "failed to parse OAuth credentials JSON",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			creds, err := ParseOAuthCredentials(tc.secretValue)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseOAuthCredentials(%q) returned nil error; want error containing %q", tc.secretValue, tc.errContains)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("ParseOAuthCredentials(%q) error = %q; want error containing %q", tc.secretValue, err, tc.errContains)
				}
				if creds != nil {
					t.Fatalf("ParseOAuthCredentials(%q) returned non-nil credentials on error", tc.secretValue)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOAuthCredentials(%q) returned unexpected error: %v", tc.secretValue, err)
			}
			if creds.ClientID != tc.wantClientID {
				t.Fatalf("ClientID = %q; want %q", creds.ClientID, tc.wantClientID)
			}
			if creds.ClientSecret != tc.wantSecret {
				t.Fatalf("ClientSecret = %q; want %q", creds.ClientSecret, tc.wantSecret)
			}
		})
	}
}
