package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func NewToken(payload []byte, key []byte) string {
	h := header{
		"HS256",
		"JWT",
	}
	headerData, _ := json.Marshal(h) // TODO: return error
	headerString := base64.RawURLEncoding.EncodeToString(headerData)

	payloadString := base64.RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(headerString + "." + payloadString))

	return headerString + "." + payloadString + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func Validate(token string, key []byte) bool {
	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		return false // TODO: return error
	}

	headerData, _ := base64.RawURLEncoding.DecodeString(parts[0]) // TODO: return error

	var h header
	json.Unmarshal(headerData, &h)

	if h.Typ != "JWT" {
		return false
	}

	if h.Alg == "none" {
		return true
	} else if h.Alg == "HS256" {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(parts[0] + "." + parts[1]))

		decodedKey, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return false // TODO: return error
		}

		return hmac.Equal(mac.Sum(nil), decodedKey)
	} else {
		return false // TODO: return error
	}
}

func GetPayload(token string) string {
	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		return "" // TODO: return error
	}

	return parts[1]
}
