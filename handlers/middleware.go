package handlers

import (
	"net/http"
	"time"

	"github.com/Richtermnd/tgauth"
)

type MiddlewareConfig struct {
	Token string
	TTL   time.Duration

	Redirect string
}

func NewLoginRequiredMiddleware(cfg MiddlewareConfig) func(next http.HandlerFunc) http.HandlerFunc {

	var onUnauthorized func(w http.ResponseWriter, r *http.Request, code int)

	if cfg.Redirect != "" {
		onUnauthorized = func(w http.ResponseWriter, r *http.Request, code int) {
			http.Redirect(w, r, cfg.Redirect, code)
		}
	} else {
		onUnauthorized = func(w http.ResponseWriter, _ *http.Request, code int) {
			http.Error(w, http.StatusText(code), code)
		}
	}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			userData, err := tgauth.FromCookie(r)
			if err != nil {
				onUnauthorized(w, r, http.StatusUnauthorized)
				return
			}
			if !userData.IsTelegramAuthorization(cfg.Token) {
				onUnauthorized(w, r, http.StatusUnauthorized)
				return
			}
			if userData.IsExpiredData(cfg.TTL) {
				onUnauthorized(w, r, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
	}
}
