package jwt_test

import (
	"testing"

	"github.com/elnormous/jwt"
)

func TestNewTokenNone(t *testing.T) {
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
		{"Empty HS256 token", "{}", jwt.AlgHS384, "test", "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.elH0w_ompO-w4utOhVejgCLg1mivQ98I6OqzMST_C_VZvQTljeDS97iTYInn0cGp"},
		{"HS256 token with key value", "{\"a\":\"b\"}", jwt.AlgHS384, "test", "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.swApKsaDxbxx1PyUprRXvQfdKInYNmclSXCIQbR9-R0b4O1Iax_dNzQWmCtXCAuR"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, _ := jwt.NewToken([]byte(testCase.payload), testCase.algorithm, []byte(testCase.key))

			if result != testCase.result {
				t.Errorf("Invalid result, got %s, exptected %s", result, testCase.result)
			}

			valid, _ := jwt.Validate(result, []byte(testCase.key))

			if !valid {
				t.Errorf("Validation failed")
			}

			payload, _ := jwt.GetPayload(result)
			if payload != testCase.payload {
				t.Errorf("Invalid payload, got %s, expected %s", payload, testCase.payload)
			}
		})
	}
}
