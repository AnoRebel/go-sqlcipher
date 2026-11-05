package sqlite3

import "testing"

func TestCryptoSelfTest(t *testing.T) {
	t.Logf("AES implementation: %s", aesImplementation())
	if rc := cryptoSelfTest(); rc != 0 {
		t.Fatalf("libtomcrypt known-answer tests failed: error %d", rc)
	}
	// the hardware path must produce exactly what portable AES produces
	if bad := aesCrossCheck(30000); bad != 0 {
		t.Fatalf("dispatched AES differs from portable AES: %d mismatches", bad)
	}
}
