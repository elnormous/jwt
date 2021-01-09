package jwt_test

import (
	"errors"
	"testing"

	"github.com/elnormous/jwt"
)

func TestNewToken(t *testing.T) {
	testCases := []struct {
		name      string
		payload   string
		algorithm string
		key       string
		result    string
	}{
		{"Empty none token", "{}", jwt.AlgNone, "", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30."},
		{"None token with key value", "{\"a\":\"b\"}", jwt.AlgNone, "", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhIjoiYiJ9."},
		{"Empty HS256 token", "{}", jwt.AlgHS256, "test", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.P4Lqll22jQQJ1eMJikvNg5HKG-cKB0hUZA9BZFIG7Jk"},
		{"HS256 token with key value", "{\"a\":\"b\"}", jwt.AlgHS256, "test", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.fpozJzV-Il2PfKYRsp9XYnA0MD1iLr5V_Fib0QrugT8"},
		{"Empty HS384 token", "{}", jwt.AlgHS384, "test", "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.elH0w_ompO-w4utOhVejgCLg1mivQ98I6OqzMST_C_VZvQTljeDS97iTYInn0cGp"},
		{"HS384 token with key value", "{\"a\":\"b\"}", jwt.AlgHS384, "test", "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.swApKsaDxbxx1PyUprRXvQfdKInYNmclSXCIQbR9-R0b4O1Iax_dNzQWmCtXCAuR"},
		{"Empty HS512 token", "{}", jwt.AlgHS512, "test", "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.P7FSHtkG8Fi0MItmvmwO5f6ilgnzTHvJp2zr4iiynIyJSwH38a6bEJx7oizjPF5lsIvZd4kn4zoMwhcgqNhz2g"},
		{"HS512 token with key value", "{\"a\":\"b\"}", jwt.AlgHS512, "test", "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.AIjR460KZUZLePuJpgVkdKV2RNHSNbAeJjLFdOYsI2Ev7VMZgnWAUt4aYA9N5SQVmbqQiWtczmNNUmzkj4kecQ"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, newTokenError := jwt.NewToken([]byte(testCase.payload), testCase.algorithm, []byte(testCase.key))

			if newTokenError != nil {
				t.Errorf("Unexpected error: %s", newTokenError.Error())
			}

			if result != testCase.result {
				t.Errorf("Invalid result, got %s, exptected %s", result, testCase.result)
			}

			valid, validateError := jwt.Validate(result, []byte(testCase.key))

			if validateError != nil {
				t.Errorf("Unexpected error: %s", validateError.Error())
			}

			if !valid {
				t.Errorf("Validation failed")
			}

			payload, getPayloadError := jwt.GetPayload(result, []byte(testCase.key))
			if payload != testCase.payload {
				t.Errorf("Invalid payload, got %s, expected %s", payload, testCase.payload)
			}

			if getPayloadError != nil {
				t.Errorf("Unexpected error: %s", getPayloadError.Error())
			}
		})
	}
}

func TestGetPayloadErrors(t *testing.T) {
	testCases := []struct {
		name  string
		token string
		key   string
		err   error
	}{
		{"Missing payload", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.", "test", jwt.ErrInvalidToken},
		{"Invalid header", "xxx.e30.", "test", jwt.ErrInvalidToken},
		{"Missing signature", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.", "test", jwt.ErrInvalidSignature},
		{"Invalid signature", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.abc", "test", jwt.ErrInvalidSignature},
		{"Wrong signature", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.P4Lqll22jQQJ1eMJikvNg5HKG-cKB0hUZA9BZFIG7Jk", "1234", jwt.ErrInvalidSignature},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := jwt.GetPayload(testCase.token, []byte(testCase.key))

			if err == nil {
				t.Errorf("Expected an error for %s", testCase.token)
			} else if !errors.Is(err, testCase.err) {
				t.Errorf("Unexpected error \"%s\", expected \"%s\" for %s", err.Error(), testCase.err.Error(), testCase.token)
			}
		})
	}
}
