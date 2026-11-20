package secure

import "testing"

func TestHashAndVerify(t *testing.T) {
	hash, err := HashSecret("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySecret(hash, "correct horse battery staple") {
		t.Fatal("valid secret rejected")
	}
	if VerifySecret(hash, "wrong") {
		t.Fatal("wrong secret accepted")
	}
	if VerifySecret("garbage", "wrong") {
		t.Fatal("garbage hash accepted")
	}
	other, _ := HashSecret("correct horse battery staple")
	if hash == other {
		t.Fatal("hashes should use random salts")
	}
}
