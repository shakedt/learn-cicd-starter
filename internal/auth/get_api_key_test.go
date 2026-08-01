package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		wantKey string
		wantErr error
	}{
		{
			name:    "returns key from valid ApiKey authorization header",
			header:  "ApiKey abc123",
			wantKey: "abc123",
		},
		{
			name:    "returns error when authorization header is missing",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "returns error when authorization header is malformed",
			header:  "Bearer abc123",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			gotKey, err := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}
			if tt.wantErr == nil && err != nil {
				t.Errorf("GetAPIKey() unexpected error: %v", err)
			}
			if tt.wantErr != nil && (err == nil || err.Error() != tt.wantErr.Error()) {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
