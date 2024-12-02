package tgauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const TokenSeparator string = "$" // Fields separator for token string

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
