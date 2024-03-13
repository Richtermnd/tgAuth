package tgauth_test

import (
	"testing"

	"github.com/Richtermnd/tgauth"
)

func TestTokenString(t *testing.T) {
	testCases := []struct {
		name string
		data tgauth.TelegramUserData
		desc string
	}{
		{
			name: "all fields",
			data: tgauth.TelegramUserData{
				TGID:      1,
				FirstName: "test",
				LastName:  "test",
				Username:  "test",
				PhotoURL:  "test",
				AuthDate:  1,
				Hash:      "test",
			},
			desc: "all fields include",
		},
		{
			name: "only required fields",
			data: tgauth.TelegramUserData{
				TGID:      1,
				FirstName: "test",
				AuthDate:  1,
				Hash:      "test",
			},
			desc: "only required fields include",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			token := tc.data.TokenString()
			data, err := tgauth.FromTokenString(token)
			if err != nil {
				t.Fatal(err)
			}
			if data != tc.data {
				t.Fatalf("got %+v, want %+v", data, tc.data)
			}
		})
	}
}
