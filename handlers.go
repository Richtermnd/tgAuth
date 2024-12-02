package tgauth

import (
	"context"
	"net/http"
	"time"
)

// TokenExtractor func that can extract TelegramUserData from request
type TokenExtractor func(r *http.Request) (TelegramUserData, error)

func LoginRequiredMiddleware(extractor TokenExtractor, token string, ttl time.Duration) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := extractor(r)
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

func LoginHandler(loginWay TokenExtractor, sendWay TokenSender, token string, ttl time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		sendWay(data, w)
		w.WriteHeader(http.StatusOK)
	})
}
