package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedAPIKey string
		expectedError  error
	}{
		{
			name:           "Valid Authorization Header",
			headers:        http.Header{"Authorization": {"ApiKey my-secret-key"}},
			expectedAPIKey: "my-secret-key",
			expectedError:  nil,
		},
		{
			name:           "Missing Authorization Header",
			headers:        http.Header{},
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
		{
			name:           "Malformed Authorization Header - Missing ApiKey",
			headers:        http.Header{"Authorization": {"my-secret-key"}},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name:           "Malformed Authorization Header - Empty ApiKey",
			headers:        http.Header{"Authorization": {"ApiKey"}},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name:           "Invalid Authorization Scheme",
			headers:        http.Header{"Authorization": {"Bearer my-secret-key"}},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			if apiKey != tt.expectedAPIKey {
				t.Errorf("expected API key %q, got %q", tt.expectedAPIKey, apiKey)
			}

			if (err == nil && tt.expectedError != nil) || (err != nil && tt.expectedError == nil) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			} else if err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("expected error message %q, got %q", tt.expectedError.Error(), err.Error())
			}
		})
	}
}
