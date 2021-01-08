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
	ErrInvalidSignature = errors.New("Invalid signature")
)

const (
	AlgNone  = "none"
	AlgHS256 = "HS256"
	AlgHS384 = "HS384"
	AlgHS512 = "HS512"
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
	} else if h.Alg == AlgHS512 {
		mac := hmac.New(sha512.New, key)
		mac.Write([]byte(headerString + "." + payloadString))
		return headerString + "." + payloadString + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	} else {
		return "", ErrInvalidAlgorithm
	}
}

func Validate(token string, key []byte) (bool, error) {
	_, err := GetPayload(token, key)

	if err == nil {
		return true, nil
	} else if err == ErrInvalidSignature {
		return false, nil
	} else {
		return false, err
	}
}

func GetPayload(token string, key []byte) (string, error) {
	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		return "", ErrInvalidToken
	}

	headerData, decodeError := base64.RawURLEncoding.DecodeString(parts[0])

	if decodeError != nil {
		return "", ErrInvalidToken
	}

	var h header
	json.Unmarshal(headerData, &h)

	if h.Typ != "JWT" {
		return "", ErrInvalidToken
	}

	if h.Alg != AlgNone {
		signature, signatureError := base64.RawURLEncoding.DecodeString(parts[2])
		if signatureError != nil {
			return "", ErrInvalidToken
		}

		if h.Alg == AlgHS256 {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(parts[0] + "." + parts[1]))
			if !hmac.Equal(mac.Sum(nil), signature) {
				return "", ErrInvalidSignature
			}
		} else if h.Alg == AlgHS384 {
			mac := hmac.New(sha512.New384, key)
			mac.Write([]byte(parts[0] + "." + parts[1]))
			if !hmac.Equal(mac.Sum(nil), signature) {
				return "", ErrInvalidSignature
			}
		} else if h.Alg == AlgHS512 {
			mac := hmac.New(sha512.New, key)
			mac.Write([]byte(parts[0] + "." + parts[1]))
			if !hmac.Equal(mac.Sum(nil), signature) {
				return "", ErrInvalidSignature
			}
		} else {
			return "", ErrInvalidAlgorithm
		}
	}

	decodedPayload, payloadDecodeError := base64.RawURLEncoding.DecodeString(parts[1])
	if payloadDecodeError != nil {
		return "", ErrInvalidToken
	}

	return string(decodedPayload), nil
}
