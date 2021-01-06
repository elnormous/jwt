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
		{"Empty token", "{}", jwt.AlgNone, "", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30."},
		{"Key value", "{\"a\":\"b\"}", jwt.AlgNone, "", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhIjoiYiJ9."},
		{"Empty token", "{}", jwt.AlgHS256, "test", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.P4Lqll22jQQJ1eMJikvNg5HKG-cKB0hUZA9BZFIG7Jk"},
		{"Key value", "{\"a\":\"b\"}", jwt.AlgHS256, "test", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.fpozJzV-Il2PfKYRsp9XYnA0MD1iLr5V_Fib0QrugT8"},
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
