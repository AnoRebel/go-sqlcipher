/* go-sqlcipher addition (not part of LibTomCrypt).
 *
 * AES using the ARMv8 Cryptography Extensions on aarch64, dispatched from
 * LibTomCrypt's aes_desc (see patches/aes_desc_armce.patch) the same way
 * LibTomCrypt dispatches to AES-NI on x86. Include after tomcrypt_private.h.
 */
#ifndef AES_ARMCE_H
#define AES_ARMCE_H

#if defined(LTC_ARCH_AARCH64) && defined(__aarch64__) && !defined(__AARCH64EB__) && !defined(LTC_NO_ACCEL) && !defined(LTC_NO_AES_ARMCE)
#define LTC_AES_ARMCE

int armce_is_supported(void);
int armce_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
int armce_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey);
int armce_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey);
#endif

#endif /* AES_ARMCE_H */
