/* go-sqlcipher addition (not part of LibTomCrypt).
 *
 * AES block functions using the ARMv8 Cryptography Extensions, operating on
 * LibTomCrypt's symmetric_key so aes_desc can dispatch to them.
 *
 * Round function, key expansion and inverse key schedule are derived from
 * Mbed TLS 3.6.7 library/aesce.c:
 *   Copyright The Mbed TLS Contributors
 *   SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/* clang only declares the AES intrinsics when the feature macro is set; the
 * functions below are compiled for the crypto extension via the target
 * pragma, and only called after the runtime check. (Same as Mbed TLS.) */
#if defined(__aarch64__) && defined(__clang__) && !defined(__ARM_FEATURE_CRYPTO) && !defined(__ARM_FEATURE_AES)
#define __ARM_FEATURE_CRYPTO 1
#define __ARM_FEATURE_AES    1
#define ARMCE_NEED_TARGET_PRAGMA
#elif defined(__aarch64__) && defined(__GNUC__) && !defined(__clang__) && !defined(__ARM_FEATURE_AES)
#define ARMCE_NEED_TARGET_PRAGMA
#endif

#include "tomcrypt_private.h"
#include "aes_armce.h"

#if defined(LTC_AES_ARMCE)

#if defined(ARMCE_NEED_TARGET_PRAGMA)
#  if defined(__clang__)
#    pragma clang attribute push (__attribute__((target("aes"))), apply_to=function)
#  else
#    pragma GCC push_options
#    pragma GCC target ("+crypto")
#  endif
#endif

#include <arm_neon.h>

#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_ASIMD
#define HWCAP_ASIMD (1 << 1)
#endif
#ifndef HWCAP_AES
#define HWCAP_AES   (1 << 3)
#endif
#endif

int armce_is_supported(void)
{
#if defined(__APPLE__)
   /* every Apple arm64 CPU implements the crypto extensions */
   return 1;
#elif defined(__linux__)
   /* benign race like LibTomCrypt's AES-NI check: all writers store the
    * same value */
   static int initialized = 0, is_supported = 0;
   if (initialized == 0) {
      unsigned long hwcap = getauxval(AT_HWCAP);
      is_supported = (hwcap & (HWCAP_ASIMD | HWCAP_AES)) == (HWCAP_ASIMD | HWCAP_AES);
      initialized = 1;
   }
   return is_supported;
#else
   /* ponytail: no detection on other OSes (Windows, BSDs), they use the
    * portable C AES; add IsProcessorFeaturePresent/elf_aux_info if needed */
   return 0;
#endif
}

static uint32_t s_rot_word(uint32_t word)
{
   return (word << (32 - 8)) | (word >> 8);
}

static uint32_t s_sub_word(uint32_t in)
{
   uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(in));
   uint8x16_t zero = vdupq_n_u8(0);
   /* vaeseq_u8 does SubBytes and ShiftRows; the first row is unaffected by
    * ShiftRows, so lane 0 is SubWord(in). */
   v = vaeseq_u8(zero, v);
   return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}

/* FIPS-197 key expansion into raw round-key bytes, Nk = keylen / 4 */
static void s_setkey_enc(unsigned char *rk, const unsigned char *key, int keylen)
{
   static const uint8_t rcon[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
   const int nk = keylen / 4;
   uint32_t *w = (uint32_t *)rk;
   const uint32_t *end = w + 4 * (nk + 6 + 1);
   uint32_t *rki;

   XMEMCPY(rk, key, (size_t)keylen);
   for (rki = w; rki + nk < end; rki += nk) {
      uint32_t *rko = rki + nk;
      rko[0] = s_rot_word(s_sub_word(rki[nk - 1])) ^ rcon[(rki - w) / nk] ^ rki[0];
      rko[1] = rko[0] ^ rki[1];
      rko[2] = rko[1] ^ rki[2];
      rko[3] = rko[2] ^ rki[3];
      if (rko + nk > end) {
         continue; /* do not write past the last round key */
      }
      if (nk == 6) {
         rko[4] = rko[3] ^ rki[4];
         rko[5] = rko[4] ^ rki[5];
      } else if (nk == 8) {
         rko[4] = s_sub_word(rko[3]) ^ rki[4];
         rko[5] = rko[4] ^ rki[5];
         rko[6] = rko[5] ^ rki[6];
         rko[7] = rko[6] ^ rki[7];
      }
   }
}

int armce_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   unsigned char *ek, *dk;
   int i, j;

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(skey != NULL);

   if (keylen != 16 && keylen != 24 && keylen != 32) {
      return CRYPT_INVALID_KEYSIZE;
   }
   if (num_rounds != 0 && num_rounds != (keylen / 4 + 6)) {
      return CRYPT_INVALID_ROUNDS;
   }

   /* same layout as rijndael_setup/aesni_setup: 60 words each for eK, dK */
   skey->rijndael.Nr = keylen / 4 + 6;
   skey->rijndael.eK = LTC_ALIGN_BUF(skey->rijndael.K, 16);
   skey->rijndael.dK = skey->rijndael.eK + 60;
   ek = (unsigned char *)skey->rijndael.eK;
   dk = (unsigned char *)skey->rijndael.dK;

   s_setkey_enc(ek, key, keylen);

   /* equivalent inverse cipher: reversed order, InvMixColumns on the
    * middle round keys */
   j = skey->rijndael.Nr;
   vst1q_u8(dk, vld1q_u8(ek + j * 16));
   for (i = 1, j--; j > 0; i++, j--) {
      vst1q_u8(dk + i * 16, vaesimcq_u8(vld1q_u8(ek + j * 16)));
   }
   vst1q_u8(dk + i * 16, vld1q_u8(ek + j * 16));

   return CRYPT_OK;
}

int armce_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
{
   const unsigned char *k;
   uint8x16_t b;
   int r;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(skey != NULL);

   k = (const unsigned char *)skey->rijndael.eK;
   b = vld1q_u8(pt);
   for (r = 0; r < skey->rijndael.Nr - 1; r++, k += 16) {
      b = vaesmcq_u8(vaeseq_u8(b, vld1q_u8(k)));
   }
   b = vaeseq_u8(b, vld1q_u8(k));      /* final round: no MixColumns */
   b = veorq_u8(b, vld1q_u8(k + 16));  /* final AddRoundKey */
   vst1q_u8(ct, b);
   return CRYPT_OK;
}

int armce_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
{
   const unsigned char *k;
   uint8x16_t b;
   int r;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(skey != NULL);

   k = (const unsigned char *)skey->rijndael.dK;
   b = vld1q_u8(ct);
   for (r = 0; r < skey->rijndael.Nr - 1; r++, k += 16) {
      b = vaesimcq_u8(vaesdq_u8(b, vld1q_u8(k)));
   }
   b = vaesdq_u8(b, vld1q_u8(k));
   b = veorq_u8(b, vld1q_u8(k + 16));
   vst1q_u8(pt, b);
   return CRYPT_OK;
}

#if defined(ARMCE_NEED_TARGET_PRAGMA)
#  if defined(__clang__)
#    pragma clang attribute pop
#  else
#    pragma GCC pop_options
#  endif
#endif

#endif /* LTC_AES_ARMCE */
