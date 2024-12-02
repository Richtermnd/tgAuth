package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Richtermnd/tgauth"
)

var (
	token string
	ttl   time.Duration
)

func init() {
	flag.StringVar(&token, "token", "", "token")
	flag.DurationVar(&ttl, "ttl", 12*time.Hour, "ttl")
	flag.Parse()
	if token == "" {
		fmt.Println("token is empty")
		os.Exit(1)
	}
}

func main() {
	// Create a middleware
	middleware := tgauth.LoginRequiredMiddleware(tgauth.FromAuthorizationHeader, token, ttl)

	// HTML page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	// Login handler
	http.Handle("POST /login", tgauth.LoginHandler(tgauth.FromAuthorizationHeader, tgauth.SendJson, token, ttl))

	// User info from token.S
	http.Handle("GET /me", middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user from context
		user, err := tgauth.FromContext(r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Send user
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
		w.WriteHeader(http.StatusOK)
	})))

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("err: %v\n", err)
	}
}
