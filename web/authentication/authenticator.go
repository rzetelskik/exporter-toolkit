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
	"log/slog"
	"net/http"
)

type Authenticator interface {
	Authenticate(*http.Request) (bool, string, error)
}

type AuthenticatorFunc func(r *http.Request) (bool, string, error)

func (f AuthenticatorFunc) Authenticate(r *http.Request) (bool, string, error) {
	return f(r)
}

func WithAuthentication(handler http.Handler, authenticator Authenticator, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, reason, err := authenticator.Authenticate(r)
		if err != nil {
			logger.Error("Unable to authenticate", "URI", r.RequestURI, "err", err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if ok {
			handler.ServeHTTP(w, r)
			return
		}

		logger.Warn("Unauthenticated request", "URI", r.RequestURI, "reason", reason)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	})
}
