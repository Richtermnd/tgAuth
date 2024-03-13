package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Richtermnd/tgauth"
)

const token = "your token"

var ttl = time.Hour * 12

func main() {
	middleware := tgauth.LoginRequiredMiddleware(token, ttl)
	http.Handle("/me", middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := tgauth.FromContext(r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(user)
		w.WriteHeader(http.StatusOK)
	})))

	http.ListenAndServe(":8080", nil)
}
