package tgauth

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func LoginRequiredMiddleware(token string, ttl time.Duration) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := r.Header.Get("Authorization")
			user, err := FromTokenString(tokenString)

			// Invalid token string
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// Invalid data
			if !user.IsTelegramAuthorization(token) {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// Data expired
			if user.IsExpiredData(ttl) {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			// add user to context
			r = r.WithContext(context.WithValue(r.Context(), ContextUserKey, user))
			// All good
			next.ServeHTTP(w, r)
		})
	}
}

func LoginHandler(loginWay func(r *http.Request) (TelegramUserData, error), token string, ttl time.Duration) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := loginWay(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !data.IsTelegramAuthorization(token) {
			http.Error(w, "invalid telegram data", http.StatusBadRequest)
			return
		}

		if data.IsExpiredData(ttl) {
			http.Error(w, "data expired", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		token := data.TokenString()
		fmt.Fprintf(w, "{\"token\": \"%s\"}", token)

		w.WriteHeader(http.StatusOK)
	}
}
