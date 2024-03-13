package tgauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ContextKey used for avoid collision in context
type ContextKey string

const (
	ContextUserKey ContextKey = "user-data" // key for storing user in context
	TokenSeparator string     = "$"         // Fields separator for token string
)

// TelegramUserData - https://core.telegram.org/widgets/login#receiving-authorization-data
type TelegramUserData struct {
	TGID      int64  `json:"id"`         // telegram id
	FirstName string `json:"first_name"` // first name
	LastName  string `json:"last_name"`  // last name
	Username  string `json:"username"`   // username
	PhotoURL  string `json:"photo_url"`  // photo url
	AuthDate  int64  `json:"auth_date"`  // auth date UNIX timestamp
	Hash      string `json:"hash"`       // hash
}

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

// IsTelegramAuthorization
//
// https://core.telegram.org/widgets/login#checking-authorization
func (u *TelegramUserData) IsTelegramAuthorization(token string) bool {
	// Generate hash
	generatedHash := u.GenerateHash(token)
	// Compare generated hash with hash
	return generatedHash == u.Hash
}

// IsExpiredDate Check ttl of telegram data. Return true if data is expired.
func (u *TelegramUserData) IsExpiredData(ttl time.Duration) bool {
	loginTime := time.Unix(u.AuthDate, 0).UTC()
	sinceFromLogin := time.Since(loginTime)
	return sinceFromLogin > ttl
}

// Generate hash from TelegramUserData.
//
// Use this for send TelegramUserData not from telegram widget. Telegram bots for example.
func (u *TelegramUserData) GenerateHash(token string) string {
	// Concate field to check string
	checkString := u.checkString()

	// Create encoder based on bot token
	encoder := hmac_sha256Encoder(token)

	// Encode check string by encoder.
	encoder.Write([]byte(checkString))
	encodedCheckString := encoder.Sum(nil)

	// Compare encodedCheckString with hash
	return hex.EncodeToString(encodedCheckString)
}

func (u *TelegramUserData) TokenString() string {
	params := []string{
		strconv.FormatInt(u.TGID, 10),
		u.FirstName,
		u.LastName,
		u.Username,
		u.PhotoURL,
		strconv.FormatInt(u.AuthDate, 10),
		u.Hash,
	}
	return url.QueryEscape(strings.Join(params, TokenSeparator))
}

// checkString - make []string{"key=value", "key=value"} from TelegramUserData with ignoring empty fields.
func (u *TelegramUserData) checkString() string {
	params := make([]string, 0, 6)
	params = append(params, fmt.Sprintf("auth_date=%d", u.AuthDate))
	params = append(params, fmt.Sprintf("first_name=%s", u.FirstName))
	params = append(params, fmt.Sprintf("id=%d", u.TGID))

	if u.LastName != "" {
		params = append(params, fmt.Sprintf("last_name=%s", u.LastName))
	}
	if u.PhotoURL != "" {
		params = append(params, fmt.Sprintf("photo_url=%s", u.PhotoURL))
	}
	if u.Username != "" {
		params = append(params, fmt.Sprintf("username=%s", u.Username))
	}
	return strings.Join(params, "\n")
}

// hmac_sha256Encoder generate new encoder based on token
func hmac_sha256Encoder(token string) hash.Hash {
	sha256Encoder := sha256.New()
	sha256Encoder.Write([]byte(token))
	secretKey := sha256Encoder.Sum(nil)
	return hmac.New(sha256.New, secretKey)
}
