package jwtmiddleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
)

// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
func UseJwtMiddleware(
	errorHandler func(http.ResponseWriter, *http.Request, error),
	verificationKeyGetter jwt.Keyfunc,
	reqCtxKey interface{},
	newClaims func() jwt.Claims,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwtToken, err := BearerExtractor(r)
			if err != nil {
				errorHandler(w, r, err)
				return
			}
			token, err := jwt.ParseWithClaims(jwtToken, newClaims(), verificationKeyGetter)
			if err != nil {
				errorHandler(w, r, err)
				return
			}
			// if signingMethod.Alg() != token.Header["alg"] {
			// 	errorHandler(w, r, errors.New(fmt.Sprintf("Expected %s signing method but token specified %s", signingMethod.Alg(), token.Header["alg"])))
			// 	return
			// }
			if !token.Valid {
				errorHandler(w, r, errors.New("Invalid token"))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reqCtxKey, token)))
		})
	}
}

// BearerExtractor gets the jwt token from the `Authorization` header
func BearerExtractor(r *http.Request) (string, error) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return "", errors.New("Unauthorized")
	}
	parts := strings.Split(token, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" || parts[1] == "" {
		return "", errors.New("Malformed Token")
	}
	return parts[1], nil
}

// QueryStringExtractor gets the jwt token from the query string defined on the given query param
func QueryStringExtractor(r *http.Request, param string) (string, error) {
	if query := r.URL.Query().Get(param); query != "" {
		return query, nil
	}
	return "", errors.New("Unauthorized")
}
