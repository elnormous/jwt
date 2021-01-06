package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var (
	ErrInvalidHeader    = errors.New("Invalid header")
	ErrInvalidToken     = errors.New("Invalid token")
	ErrInvalidAlgorithm = errors.New("Invalid algorithm")
)

const (
	AlgNone  = "none"
	AlgHS256 = "HS256"
	AlgHS384 = "HS384"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func NewToken(payload []byte, algorithm string, key []byte) (string, error) {
	h := header{
		algorithm,
		"JWT",
	}
	headerData, encodeError := json.Marshal(h)
	if encodeError != nil {
		return "", ErrInvalidHeader
	}

	headerString := base64.RawURLEncoding.EncodeToString(headerData)

	payloadString := base64.RawURLEncoding.EncodeToString(payload)

	if h.Alg == AlgNone {
		return headerString + "." + payloadString + ".", nil
	} else if h.Alg == AlgHS256 {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(headerString + "." + payloadString))
		return headerString + "." + payloadString + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	} else if h.Alg == AlgHS384 {
		mac := hmac.New(sha512.New384, key)
		mac.Write([]byte(headerString + "." + payloadString))
		return headerString + "." + payloadString + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	} else {
		return "", ErrInvalidAlgorithm
	}
}

func Validate(token string, key []byte) (bool, error) {
	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		return false, ErrInvalidToken
	}

	headerData, decodeError := base64.RawURLEncoding.DecodeString(parts[0]) // TODO: return error

	if decodeError != nil {
		return false, ErrInvalidToken
	}

	var h header
	json.Unmarshal(headerData, &h)

	if h.Typ != "JWT" {
		return false, nil
	}

	if h.Alg == AlgNone {
		return true, nil
	} else {
		decodedKey, keyDecodeError := base64.RawURLEncoding.DecodeString(parts[2])
		if keyDecodeError != nil {
			return false, ErrInvalidToken
		}

		if h.Alg == AlgHS256 {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(parts[0] + "." + parts[1]))
			return hmac.Equal(mac.Sum(nil), decodedKey), nil
		} else if h.Alg == AlgHS384 {
			mac := hmac.New(sha512.New384, key)
			mac.Write([]byte(parts[0] + "." + parts[1]))
			return hmac.Equal(mac.Sum(nil), decodedKey), nil
		} else {
			return false, ErrInvalidAlgorithm
		}
	}
}

func GetPayload(token string) (string, error) {
	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		return "", ErrInvalidToken
	}

	decodedPayload, payloadDecodeError := base64.RawURLEncoding.DecodeString(parts[1])
	if payloadDecodeError != nil {
		return "", ErrInvalidToken
	}

	return string(decodedPayload), nil
}
