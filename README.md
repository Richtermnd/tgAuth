# tgAuth

## Go package for work telegram login widget
Package provide structure, methods and functions for telegram login widget and imitate his work for non browser clients.

## Content
- [Installation](#installation)
- [Usage](#usage)
	- [Login](#login)
	- [Middleware](#middleware)


## Installation
```bash
go get github.com/Richtermnd/tgAuth
```

## Usage
### Login
How it works?
1. Telegram widget send data to server
2. Server check data and return token
3. Client send requests with token in Authorization header
4. MiddlewareTelegramAuth check token.

Package provides a handler for login. You can just use this handler or wrap it in your own handler.

``` go 
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
	loginHandler := tgauth.LoginHandler(tgauth.FromURL, token, ttl)
	// Simple use
	http.HandleFunc("/login", loginHandler)
	// Wrapped
	http.HandleFunc("/login2", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Wrapped")
		loginHandler(w, r)
	})
	http.ListenAndServe(":8080", nil)
}
```

### Middleware
Package also provides a middleware for telegram auth.
Middleware check token in header of request and add user to context if token is valid.

``` go
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
```