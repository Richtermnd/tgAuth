package main

import (
	"log"
	"net/http"
	"time"

	"github.com/Richtermnd/tgauth"
)

const token = "your token"

var ttl = time.Hour * 12

func main() {
	loginHandler := tgauth.LoginHandler(tgauth.FromURL, tgauth.SendCookie, token, ttl)
	// Simple use
	http.Handle("/login", loginHandler)
	// Wrapped
	http.HandleFunc("/login2", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Wrapped")
		loginHandler.ServeHTTP(w, r)
	})
	http.ListenAndServe(":8080", nil)
}
