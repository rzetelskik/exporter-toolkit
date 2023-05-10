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

package chain

import (
	"errors"
	"net/http"
	"testing"

	"github.com/prometheus/exporter-toolkit/web/authentication"
	"github.com/prometheus/exporter-toolkit/web/authentication/testhelpers"
)

func TestChainAuthenticator_Authenticate(t *testing.T) {
	t.Parallel()

	firstAuthenticatorErr := errors.New("first authenticator error")
	secondAuthenticatorErr := errors.New("second authenticator error")

	tt := []struct {
		Name string

		AuthenticatorsFn func(t *testing.T) []authentication.Authenticator

		ExpectAuthenticated bool
		ExpectedResponse    string
		ExpectedError       error
	}{
		{
			Name: "First authenticator denies, the rest is not called, chain denies",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return false, "First authenticator denied the request.", nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						t.Fatalf("Expected second authenticator not to be called, it was.")
						return true, "", nil
					}),
				}
			},
			ExpectAuthenticated: false,
			ExpectedResponse:    "First authenticator denied the request.",
			ExpectedError:       nil,
		},
		{
			Name: "First authenticator accepts, second is called and denies, chain denies",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return true, "", nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return false, "Second authenticator denied the request.", nil
					}),
				}
			},
			ExpectAuthenticated: false,
			ExpectedResponse:    "Second authenticator denied the request.",
			ExpectedError:       nil,
		},
		{
			Name: "All authenticators accept, chain accepts",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return true, "", nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return true, "", nil
					}),
				}
			},
			ExpectAuthenticated: true,
			ExpectedError:       nil,
		},
		{
			Name: "First authenticator returns an error, the rest is not called, chain returns an error",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return false, "", firstAuthenticatorErr
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						t.Fatalf("Expected second authenticator not to be called, it was.")
						return true, "", nil
					}),
				}
			},
			ExpectAuthenticated: false,
			ExpectedError:       firstAuthenticatorErr,
		},
		{
			Name: "First authenticator accepts the request, second authenticator returns an error, chain returns an error",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return true, "", nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return false, "", secondAuthenticatorErr
					}),
				}
			},
			ExpectAuthenticated: false,
			ExpectedError:       secondAuthenticatorErr,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			req := testhelpers.MakeDefaultRequest(t)

			a := NewChainAuthenticator(tc.AuthenticatorsFn(t))
			authenticated, response, err := a.Authenticate(req)

			if err != nil && tc.ExpectedError == nil {
				t.Errorf("Got unexpected error: %v", err)
			}

			if err == nil && tc.ExpectedError != nil {
				t.Errorf("Expected error %v, got none", tc.ExpectedError)
			}

			if err != nil && tc.ExpectedError != nil && !errors.Is(err, tc.ExpectedError) {
				t.Errorf("Expected error %v, got %v", tc.ExpectedError, err)
			}

			if tc.ExpectedResponse != response {
				t.Errorf("Expected response %v, got %v", tc.ExpectedResponse, response)
			}

			if tc.ExpectAuthenticated != authenticated {
				t.Errorf("Expected authenticated %v, got %v", tc.ExpectAuthenticated, authenticated)
			}
		})
	}
}
