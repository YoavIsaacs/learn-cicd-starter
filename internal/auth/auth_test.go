package auth_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/YoavIsaacs/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		wantErr     bool
		expectedErr error
	}{
		{
			name: "Valid ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123xyz"},
			},
			expectedKey: "abc123xyz",
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name:        "Missing Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			wantErr:     true,
			expectedErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "Wrong Authorization Type",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123xyz"},
			},
			expectedKey: "",
			wantErr:     true,
			expectedErr: nil, // We don't check for the exact error message here
		},
		{
			name: "Empty Authorization Header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey: "",
			wantErr:     true,
			expectedErr: nil, // We don't check for the exact error message here
		},
		{
			name: "Malformed Authorization Header - No Space",
			headers: http.Header{
				"Authorization": []string{"ApiKeyabc123xyz"},
			},
			expectedKey: "",
			wantErr:     true,
			expectedErr: nil, // We don't check for the exact error message here
		},
		{
			name: "Malformed Authorization Header - Empty Value",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey: "",
			wantErr:     false, // Function accepts this case
			expectedErr: nil,
		},
		{
			name: "Case Sensitive Type Check",
			headers: http.Header{
				"Authorization": []string{"apikey abc123xyz"},
			},
			expectedKey: "",
			wantErr:     true,
			expectedErr: nil, // We don't check for the exact error message here
		},
		{
			name: "Multiple Authorization Values - Takes First",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123xyz", "ApiKey def456uvw"},
			},
			expectedKey: "abc123xyz",
			wantErr:     false,
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := auth.GetAPIKey(tt.headers)

			// Check error state
			if tt.wantErr {
				assert.Error(t, err)
				if tt.expectedErr != nil {
					assert.Equal(t, tt.expectedErr, err)
				}
			} else {
				assert.NoError(t, err)
			}

			// Check key value
			assert.Equal(t, tt.expectedKey, key)
		})
	}
}

func TestGetAPIKeyWithCustomHeaders(t *testing.T) {
	// Test with headers that have custom cases to verify case sensitivity
	headers := make(http.Header)
	headers.Add("authorization", "ApiKey test123") // lowercase header name should still work

	key, err := auth.GetAPIKey(headers)
	assert.NoError(t, err)
	assert.Equal(t, "test123", key)
}

func TestGetAPIKeyWithMultipleSpaces(t *testing.T) {
	// Test with extra spaces to verify behavior
	headers := make(http.Header)
	headers.Add("Authorization", "ApiKey   test123")

	key, err := auth.GetAPIKey(headers)
	assert.NoError(t, err)
	assert.Equal(t, "", key) // The function only takes the first token after space
}
