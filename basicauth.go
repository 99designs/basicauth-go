package basicauth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
)

// New returns a piece of middleware that will allow access only
// if the provided credentials match within the given service
// otherwise it will return a 401 and not call the next handler.
func New(realm string, credentials map[string][]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok {
				unauthorized(w, realm)
				return
			}

			validPasswords, userFound := credentials[username]
			if !userFound {
				unauthorized(w, realm)
				return
			}

			for _, validPassword := range validPasswords {
				validPasswordBytes := []byte(validPassword)
				passwordBytes := []byte(password)
				// take the same amount of time if the lengths are different
				// this is required since ConstantTimeCompare returns immediately when slices of different length are compared
				if len(password) != len(validPassword) {
					subtle.ConstantTimeCompare(validPasswordBytes, validPasswordBytes)
				} else {
					if subtle.ConstantTimeCompare(passwordBytes, validPasswordBytes) == 1 {
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			unauthorized(w, realm)
		})
	}
}

func unauthorized(w http.ResponseWriter, realm string) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	w.WriteHeader(http.StatusUnauthorized)
}
