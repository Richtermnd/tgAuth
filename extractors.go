// extractors.go Provide a ways to extract data from different sources

package tgauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ContextKey used for avoid collision in context
type ContextKey string

const ContextUserKey ContextKey = "tgauth-user-data" // key for storing user in context

var (
	ErrNoData   = errors.New("no telegram data")
	ErrBadToken = errors.New("bad token")
)

// FromJSON TelegramUserData from body of request.
//
// It doesn't check is data valid, all invalid/empty fields will be ignored.
// If data is invalid, user will not pass authorisation check.
func FromJSON(r *http.Request) (TelegramUserData, error) {
	var data TelegramUserData
	err := json.NewDecoder(r.Body).Decode(&data)
	return data, err
}

// FromURL TelegramUserData from query of request
//
// It doesn't check is data valid, all invalid/empty fields will be ignored.
// If data is invalid, user will not pass authorisation check.
func FromURL(r *http.Request) (TelegramUserData, error) {
	var data TelegramUserData
	query := r.URL.Query()
	data.TGID, _ = strconv.ParseInt(query.Get("id"), 10, 64)
	data.FirstName = query.Get("first_name")
	data.LastName = query.Get("last_name")
	data.Username = query.Get("username")
	data.PhotoURL = query.Get("photo_url")
	data.AuthDate, _ = strconv.ParseInt(query.Get("auth_date"), 10, 64)
	data.Hash = query.Get("hash")
	return data, nil
}

// FromCookie extract TelegramUserData from cookie with name [CookieTokenName]
func FromCookie(r *http.Request) (TelegramUserData, error) {
	cookie, err := r.Cookie(CookieTokenName)
	if err != nil {
		return TelegramUserData{}, err
	}
	return FromTokenString(cookie.Value)
}

// FromCookie extract TelegramUserData from cookie with name [CookieTokenName]
func FromAuthorizationHeader(r *http.Request) (TelegramUserData, error) {
	return FromTokenString(r.Header.Get("Autorization"))
}

// FromTokenString parse a TelegramUserData struct from a token string.
//
// The token string is expected to be in the format:
//
//	{tg_id}{sep}{first_name}{sep}{last_name}{sep}{username}{sep}{photo_url}{sep}{auth_date}{sep}{hash}
//
// Where {sep} is the TokenSeparator constant.
func FromTokenString(token string) (TelegramUserData, error) {
	unescapedToken, err := url.QueryUnescape(token)
	if err != nil {
		return TelegramUserData{}, err
	}
	params := strings.Split(unescapedToken, TokenSeparator)
	if len(params) != 7 {
		return TelegramUserData{}, ErrBadToken
	}

	// Extract data from token
	var data TelegramUserData
	data.TGID, _ = strconv.ParseInt(params[0], 10, 64)     // Telegram user ID
	data.FirstName = params[1]                             // First name
	data.LastName = params[2]                              // Last name
	data.Username = params[3]                              // Username
	data.PhotoURL = params[4]                              // Photo URL
	data.AuthDate, _ = strconv.ParseInt(params[5], 10, 64) // Auth date
	data.Hash = params[6]                                  // Hash

	return data, nil
}

// FromContext Get TelegramUserData that middleware put in context.
func FromContext(r *http.Request) (TelegramUserData, error) {
	user, ok := r.Context().Value(ContextUserKey).(TelegramUserData)
	if !ok {
		return TelegramUserData{}, ErrNoData
	}
	return user, nil
}
