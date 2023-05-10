// Copyright 2023 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authentication

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/exporter-toolkit/web/authentication/testhelpers"
)

func TestWithAuthentication(t *testing.T) {
	t.Parallel()

	logger := testhelpers.NewNoOpLogger()

	tt := []struct {
		Name               string
		Authenticator      Authenticator
		ExpectedStatusCode int
	}{
		{
			Name: "Accepting authenticator",
			Authenticator: AuthenticatorFunc(func(_ *http.Request) (bool, string, error) {
				return true, "", nil
			}),
			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name: "Denying authenticator",
			Authenticator: AuthenticatorFunc(func(_ *http.Request) (bool, string, error) {
				return false, "", nil
			}),
			ExpectedStatusCode: http.StatusUnauthorized,
		},
		{
			Name: "Erroring authenticator",
			Authenticator: AuthenticatorFunc(func(_ *http.Request) (bool, string, error) {
				return false, "", errors.New("error authenticating")
			}),
			ExpectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			req := testhelpers.MakeDefaultRequest(t)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			rr := httptest.NewRecorder()
			authHandler := WithAuthentication(handler, tc.Authenticator, logger)
			authHandler.ServeHTTP(rr, req)
			got := rr.Result()

			if tc.ExpectedStatusCode != got.StatusCode {
				t.Errorf("Expected status code %q, got %q", tc.ExpectedStatusCode, got.Status)
			}
		})
	}
}
