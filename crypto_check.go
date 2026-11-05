package sqlite3

/*
#include "tomcrypt_private.h"
#include "aes_armce.h"

static const char *_ltc_aes_impl(void) {
#if defined(LTC_AES_NI)
	if (aesni_is_supported()) return "aes-ni";
#endif
#if defined(LTC_AES_ARMCE)
	if (armce_is_supported()) return "armv8-ce";
#endif
	return "portable";
}

// Known-answer tests of the dispatched AES and SHA implementations.
static int _ltc_selftest(void) {
	int err;
	if ((err = aes_test()) != CRYPT_OK) return err;
	if ((err = sha1_test()) != CRYPT_OK) return err;
	if ((err = sha256_test()) != CRYPT_OK) return err;
	return sha512_test();
}

// Compare the dispatched aes_desc (AES-NI / ARMv8 CE when available) with the
// portable rijndael implementation on n pseudo-random keys and blocks.
// Returns the number of mismatches, or -1 on a setup error.
static int _ltc_aes_crosscheck(int n) {
	unsigned long x = 88172645463325252UL;
	int i, j, bad = 0;
	for (i = 0; i < n; i++) {
		unsigned char key[32], pt[16], c1[16], c2[16], d1[16], d2[16];
		symmetric_key hw, sw;
		int keylen = 16 + 8 * (i % 3);
		for (j = 0; j < 32; j++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; key[j] = (unsigned char)x; }
		for (j = 0; j < 16; j++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; pt[j] = (unsigned char)x; }
		if (aes_setup(key, keylen, 0, &hw) != CRYPT_OK) return -1;
		if (rijndael_setup(key, keylen, 0, &sw) != CRYPT_OK) return -1;
		aes_ecb_encrypt(pt, c1, &hw);
		rijndael_ecb_encrypt(pt, c2, &sw);
		aes_ecb_decrypt(c2, d1, &hw);
		rijndael_ecb_decrypt(c1, d2, &sw);
		if (XMEMCMP(c1, c2, 16) != 0 || XMEMCMP(d1, pt, 16) != 0 || XMEMCMP(d2, pt, 16) != 0) bad++;
	}
	return bad;
}
*/
import "C"

// aesImplementation reports which AES implementation libtomcrypt dispatches to
// on this CPU: "aes-ni", "armv8-ce" or "portable".
func aesImplementation() string {
	return C.GoString(C._ltc_aes_impl())
}

// cryptoSelfTest runs the libtomcrypt known-answer tests for AES, SHA-1,
// SHA-256 and SHA-512 and returns the libtomcrypt error code (0 = OK).
func cryptoSelfTest() int {
	return int(C._ltc_selftest())
}

// aesCrossCheck compares the dispatched AES with the portable implementation
// on n random keys/blocks and returns the number of mismatches (-1 = error).
func aesCrossCheck(n int) int {
	return int(C._ltc_aes_crosscheck(C.int(n)))
}
