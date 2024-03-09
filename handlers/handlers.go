package handlers

import (
	"net/http"

	"github.com/Richtermnd/tgauth"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	tgauth.DeleteCookie(w)
}
