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

package web

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

type Decision int

const (
	DecisionDeny = iota
	DecisionNoDecision
	DecisionAllow
)

type Authorizer interface {
	Authorize(*http.Request) (Decision, string, error)
}

type AuthorizerFunc func(*http.Request) (Decision, string, error)

func (f AuthorizerFunc) Authorize(r *http.Request) (Decision, string, error) {
	return f(r)
}

func WithAuthorization(handler http.Handler, authorizer Authorizer, logger log.Logger) http.Handler {
	if authorizer == nil {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision, reason, err := authorizer.Authorize(r)
		// We check for DecisionAllow first in case the authorizer encountered errors but still allowed the request.
		if decision == DecisionAllow {
			handler.ServeHTTP(w, r)
			return
		}
		if err != nil {
			level.Error(logger).Log("msg", "Error authorizing a request", "URI", r.RequestURI, "err", err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		level.Debug(logger).Log("msg", "Unauthorized request", "URI", r.RequestURI, "reason", reason)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	})
}

type unionAuthorizer []Authorizer

func NewUnionAuthorizer(authorizers ...Authorizer) Authorizer {
	return unionAuthorizer(authorizers)
}

func (ua unionAuthorizer) Authorize(r *http.Request) (Decision, string, error) {
	var errs []error
	var reasons []string

	for _, a := range ua {
		decision, reason, err := a.Authorize(r)

		if err != nil {
			errs = append(errs, err)
		}
		if len(reason) != 0 {
			reasons = append(reasons, reason)
		}

		switch decision {
		case DecisionAllow, DecisionDeny:
			return decision, reason, err
		case DecisionNoDecision:
			continue
		}
	}

	reason := strings.Join(reasons, "\n")
	err := errors.Join(errs...)
	return DecisionNoDecision, reason, err
}

type TLSAuthorizationOptions struct {
	webConfigPath string
}

func (o *TLSAuthorizationOptions) ToAuthorizer() (Authorizer, error) {
	c, err := getConfig(o.webConfigPath)
	if err != nil {
		return nil, err
	}

	clientAuth, err := ParseClientAuth(c.TLSConfig.ClientAuth)
	if err != nil {
		return nil, err
	}

	clientCAs, err := GetClientCAs(c.TLSConfig.ClientCAs)
	if err != nil {
		return nil, err
	}

	var authorizers []Authorizer
	if len(c.AuthorizationExcludedPaths) > 0 {
		a := NewExcludedPathsAuthorizer(c.AuthorizationExcludedPaths)
		authorizers = append(authorizers, a)
	}

	clientCertAuthorizer := NewClientCertAuthorizer(clientAuth, clientCAs)
	authorizers = append(authorizers, clientCertAuthorizer)

	return NewUnionAuthorizer(authorizers...), nil
}

type clientCertAuthorizer struct {
	clientAuth tls.ClientAuthType
	clientCAs  *x509.CertPool
}

func isClientCertRequired(c tls.ClientAuthType) bool {
	switch c {
	case tls.RequireAnyClientCert, tls.RequireAndVerifyClientCert:
		return true
	}

	return false
}

func (c clientCertAuthorizer) Authorize(r *http.Request) (Decision, string, error) {
	if c.clientAuth <= tls.RequestClientCert {
		return DecisionAllow, "", nil
	}

	clientCerts := r.TLS.PeerCertificates
	if len(clientCerts) == 0 && isClientCertRequired(c.clientAuth) {
		return DecisionDeny, "A certificate is required to be sent by the client.", nil
	}

	if c.clientAuth >= tls.VerifyClientCertIfGiven && len(clientCerts) > 0 {
		opts := x509.VerifyOptions{
			Roots:         c.clientCAs,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		for _, cert := range clientCerts[1:] {
			opts.Intermediates.AddCert(cert)
		}

		_, err := clientCerts[0].Verify(opts)
		if err != nil {
			return DecisionDeny, fmt.Sprintf("Bad certificate: %v", err), nil
		}
	}

	return DecisionAllow, "", nil
}

func NewClientCertAuthorizer(clientAuth tls.ClientAuthType, clientCAs *x509.CertPool) Authorizer {
	return &clientCertAuthorizer{clientAuth: clientAuth, clientCAs: clientCAs}
}

func NewExcludedPathsAuthorizer(excludedPaths []string) Authorizer {
	excludedPathSet := make(map[string]bool, len(excludedPaths))

	for _, p := range excludedPaths {
		excludedPathSet[p] = true
	}

	return AuthorizerFunc(func(r *http.Request) (Decision, string, error) {
		path := r.URL.Path

		if excludedPathSet[path] {
			return DecisionAllow, "", nil
		}

		return DecisionNoDecision, "", nil
	})
}

func WithTLSAuthorization(handler http.Handler, tlsAuthorizationOptions TLSAuthorizationOptions, logger log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizer, err := tlsAuthorizationOptions.ToAuthorizer()
		if err != nil {
			level.Error(logger).Log("msg", "Error creating authorizer from TLSAuthorizerOptions", "err", err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		WithAuthorization(handler, authorizer, logger).ServeHTTP(w, r)
	})
}
