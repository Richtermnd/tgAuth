// senders.go Provide a ways to send token to client

package tgauth

import (
	"fmt"
	"net/http"
)

const CookieTokenName string = "tgauth-token"

// TokenSender func that write token in response
type TokenSender func(data TelegramUserData, w http.ResponseWriter)

// SendPlainText send token as a plain text in response body
func SendPlainText(data TelegramUserData, w http.ResponseWriter) {
	token := data.TokenString()
	fmt.Fprint(w, token)
}

// SendJson send token as a json {"token": "<token>"}
func SendJson(data TelegramUserData, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	token := data.TokenString()
	fmt.Fprintf(w, "{\"token\": \"%s\"}", token)
}

// SendCookie set cookie with name [CookieTokenName] and value token
func SendCookie(data TelegramUserData, w http.ResponseWriter) {
	token := data.TokenString()
	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: token,
		Path:  "/",
	})
}
