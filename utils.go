package tgauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var (
	CookieName      = "X-telegram-data"
	CookieSeparator = "&"
)

var (
	ErrNoData = errors.New("no telegram data")
)

// FromJSON TelegramUserData from json
// It doesn't check is data valid, all invalid fields will be ignored.
// If data is invalid, user will not pass authorisation check.
func FromJSON(body io.Reader) (data TelegramUserData) {
	json.NewDecoder(body).Decode(&data)
	return
}

// FromQuery TelegramUserData from query
// It doesn't check is data valid, all invalid fields will be ignored.
// If data is invalid, user will not pass authorisation check.
func FromQuery(query url.Values) (data TelegramUserData) {
	data.TGID, _ = strconv.ParseInt(query.Get("id"), 10, 64)
	data.FirstName = query.Get("first_name")
	data.LastName = query.Get("last_name")
	data.Username = query.Get("username")
	data.PhotoURL = query.Get("photo_url")
	data.AuthDate, _ = strconv.ParseInt(query.Get("auth_date"), 10, 64)
	data.Hash = query.Get("hash")
	return
}

func FromCookie(r *http.Request) (data TelegramUserData, err error) {
	// Get cookie
	cookie, err := r.Cookie(CookieName)
	// if cookie not found or empty
	if err != nil || cookie.Value == "" {
		return TelegramUserData{}, ErrNoData
	}

	// unescape cookie
	s, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return TelegramUserData{}, err
	}

	// Split by CookieSeparator (default `&`)
	splitted := strings.Split(s, CookieSeparator)
	for _, v := range splitted {
		// Cut by `=`
		key, value, _ := strings.Cut(v, "=")

		// Get field (it's cursed but stable)
		switch key {
		case "id":
			data.TGID, _ = strconv.ParseInt(value, 10, 64)
		case "first_name":
			data.FirstName = value
		case "last_name":
			data.LastName = value
		case "username":
			data.Username = value
		case "photo_url":
			data.PhotoURL = value
		case "auth_date":
			data.AuthDate, _ = strconv.ParseInt(value, 10, 64)
		case "hash":
			data.Hash = value
		}
	}
	return
}

// SetCookie convert user to key=value string with CookieSeparator as separator
// and set cookie with name CookieName
func SetCookie(w http.ResponseWriter, user TelegramUserData) {
	values := user.pairs()
	values = append(values, fmt.Sprintf("hash=%s", user.Hash))
	value := strings.Join(values, CookieSeparator)
	cookie := &http.Cookie{
		Name:  CookieName,
		Value: url.QueryEscape(value),
		Path:  "/",
	}
	http.SetCookie(w, cookie)
}

// DeleteCookie Set CookieName cookie to empty string.
func DeleteCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:  CookieName,
		Value: "",
		Path:  "/",
	}
	http.SetCookie(w, cookie)
}
