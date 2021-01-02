package jwt

import "testing"

func TestNewToken(t *testing.T) {
	testCases := []struct {
		name    string
		payload string
		key     string
		result  string
	}{
		{"Empty token", "{}", "test", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.P4Lqll22jQQJ1eMJikvNg5HKG-cKB0hUZA9BZFIG7Jk"},
		{"Key value", "{\"a\":\"b\"}", "test", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.fpozJzV-Il2PfKYRsp9XYnA0MD1iLr5V_Fib0QrugT8"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := NewToken([]byte(testCase.payload), []byte(testCase.key))

			if result != testCase.result {
				t.Errorf("Invalid result, got %s, exptected %s", result, testCase.result)
			}

			valid := Validate(result, []byte(testCase.key))

			if !valid {
				t.Errorf("Validation failed")
			}
		})
	}
}
