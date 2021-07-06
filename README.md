* Use it like this:

```go
type key int

const (
	JwtUserKey key = iota
)

jwtMiddleware := jwtmiddleware.UseJwtMiddleware(
	func(w http.ResponseWriter, r *http.Request, err error) {
		HttpError(backend.Log, w, r, http.StatusUnauthorized, err)
	},
	func(token *jwt.Token) (interface{}, error) {
		// NB! verify that we are dealing with the same signing method used when singning jwt token
		// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(SECRETKEY), nil
	},
	JwtUserKey,
	func() jwt.Claims {
		return JwtClaims{}
	},
)
```
