package middleware

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	k8serrors "k8s.io/apimachinery/pkg/util/errors"
)

const jwtRegexFormat = `^ey[a-zA-Z0-9_-]*\.ey[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+$`

func NewJwtSessionLoader(sessionLoaders []middlewareapi.TokenToSessionFunc, bearerTokenLoginFallback bool) alice.Constructor {
	js := &jwtSessionLoader{
		jwtRegex:        regexp.MustCompile(jwtRegexFormat),
		sessionLoaders:  sessionLoaders,
		denyInvalidJWTs: !bearerTokenLoginFallback,
	}
	return js.loadSession
}

// jwtSessionLoader is responsible for loading sessions from JWTs in
// Authorization headers.
type jwtSessionLoader struct {
	jwtRegex        *regexp.Regexp
	sessionLoaders  []middlewareapi.TokenToSessionFunc
	denyInvalidJWTs bool
}

// loadSession attempts to load a session from a JWT stored in an Authorization
// header within the request.
// If no authorization header is found, or the header is invalid, no session
// will be loaded and the request will be passed to the next handler.
// Or if the JWT is invalid and denyInvalidJWTs, return 403 now.
// If a session was loaded by a previous handler, it will not be replaced.
func (j *jwtSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		session, err := j.getJwtSession(req)
		if err != nil {
			// Decode the JWT payload without verifying the signature so we can log
			// identifying metadata (key_id=sub, iss, aud, exp) instead of the raw
			// Bearer token value. The claims are untrusted when the signature has
			// failed validation, but they still give triage signal (e.g., expired
			// token from a known key vs. completely malformed request) without
			// leaking a replayable secret into logs (MIG-11558).
			c := j.unverifiedClaimsFromHeader(req.Header.Get("Authorization"))
			logger.Errorf("Error retrieving session from token for endpoint: %s, key_id=%s iss=%s aud=%s exp=%d error=%v",
				req.URL.Path, c.sub, c.iss, c.aud, c.exp, err)
			if j.denyInvalidJWTs {
				http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getJwtSession loads a session based on a JWT token in the authorization header.
// (see the config options skip-jwt-bearer-tokens, extra-jwt-issuers, and bearer-token-login-fallback)
func (j *jwtSessionLoader) getJwtSession(req *http.Request) (*sessionsapi.SessionState, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		// No auth header provided, so don't attempt to load a session
		return nil, nil
	}

	token, err := j.findTokenFromHeader(auth)
	if err != nil {
		return nil, err
	}

	// This leading error message only occurs if all session loaders fail
	errs := []error{errors.New("unable to verify bearer token")}
	for _, loader := range j.sessionLoaders {
		session, err := loader(req.Context(), token)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return session, nil
	}

	return nil, k8serrors.NewAggregate(errs)
}

// findTokenFromHeader finds a valid JWT token from the Authorization header of a given request.
func (j *jwtSessionLoader) findTokenFromHeader(header string) (string, error) {
	tokenType, token, err := splitAuthHeader(header)
	if err != nil {
		return "", err
	}

	if tokenType == "Bearer" && j.jwtRegex.MatchString(token) {
		// Found a JWT as a bearer token
		return token, nil
	}

	if tokenType == "Basic" {
		// Check if we have a Bearer token masquerading in Basic
		return j.getBasicToken(token)
	}

	return "", fmt.Errorf("no valid bearer token found in authorization header")
}

// getBasicToken tries to extract a token from the basic value provided.
func (j *jwtSessionLoader) getBasicToken(token string) (string, error) {
	user, password, err := getBasicAuthCredentials(token)
	if err != nil {
		return "", err
	}

	// check user, user+password, or just password for a token
	if j.jwtRegex.MatchString(user) {
		if password == "x-oauth-basic" || // #nosec G101 -- Support blank passwords or magic `x-oauth-basic` passwords, nothing else
			password == "" {
			return user, nil
		}
	} else if j.jwtRegex.MatchString(password) {
		// support passwords and ignore user
		return password, nil
	}

	return "", fmt.Errorf("invalid basic auth token found in authorization header")
}

// unverifiedClaims holds JWT claims read without verifying the signature.
// Used for logging only — values are not trusted for authorization decisions.
type unverifiedClaims struct {
	sub string
	iss string
	aud string
	exp int64
}

// unverifiedClaimsFromHeader extracts and base64-decodes the JWT payload from
// an Authorization header without verifying the signature. Returns zero-valued
// fields if the header is empty, the token is not a JWT, or decoding fails.
func (j *jwtSessionLoader) unverifiedClaimsFromHeader(authHeader string) unverifiedClaims {
	var c unverifiedClaims
	if authHeader == "" {
		return c
	}
	token, err := j.findTokenFromHeader(authHeader)
	if err != nil || token == "" {
		return c
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c
	}
	// JWTs use base64url; payload may or may not be padded. Try raw first, then
	// padded as a fallback.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return c
		}
	}
	var raw struct {
		Sub string          `json:"sub"`
		Iss string          `json:"iss"`
		Aud json.RawMessage `json:"aud"` // can be string or []string per RFC 7519
		Exp int64           `json:"exp"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return c
	}
	c.sub = raw.Sub
	c.iss = raw.Iss
	c.exp = raw.Exp
	// aud may be either a string or an array of strings.
	if len(raw.Aud) > 0 {
		var s string
		if err := json.Unmarshal(raw.Aud, &s); err == nil {
			c.aud = s
		} else {
			var arr []string
			if err := json.Unmarshal(raw.Aud, &arr); err == nil && len(arr) > 0 {
				c.aud = arr[0]
			}
		}
	}
	return c
}
