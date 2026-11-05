#!/bin/sh -e

if [ $# -ne 1 ]
then
  echo "Usage: $0 libtomcrypt_dir" >&2
  echo "Copy tracked source files from libtomcrypt_dir to current directory." >&2
  exit 1
fi

ltd=$1
src=$ltd/src

# copy header files
for h in argchk cfg cipher custom hash mac macros math misc pkcs pk private prng
do
  cp -f "$src/headers/tomcrypt_$h.h" .
done
cp -f "$src/headers/tomcrypt.h" .

# AES (aesni.c is LibTomCrypt's runtime-detected AES-NI implementation)
cp -f "$src/ciphers/aes/aes.c" .
cp -f "$src/ciphers/aes/aes_desc.c" .
cp -f "$src/ciphers/aes/aesni.c" .
cp -f "$src/ciphers/aes/aes_tab.c" aes_tab.h
sed 's#include "aes_tab.c"#include "aes_tab.h"#' aes.c > aes.c.tmp && mv aes.c.tmp aes.c

# misc
cp -f "$src/misc/burn_stack.c" .
cp -f "$src/misc/compare_testvector.c" .
cp -f "$src/misc/zeromem.c" .

# CBC and ECB modes
for f in decrypt done encrypt start
do
  cp -f "$src/modes/cbc/cbc_$f.c" .
  cp -f "$src/modes/ecb/ecb_$f.c" .
done

# crypt registry
for f in argchk cipher_descriptor cipher_is_valid find_cipher find_hash \
         hash_descriptor hash_is_valid prng_descriptor register_cipher \
         register_hash register_prng
do
  cp -f "$src/misc/crypt/crypt_$f.c" .
done

# PRNG
cp -f "$src/prngs/fortuna.c" .
cp -f "$src/prngs/rng_get_bytes.c" .

# hashes (*_desc.c dispatches at runtime to the *_x86.c SHA extensions)
cp -f "$src/hashes/helper/hash_memory.c" .
cp -f "$src/hashes/sha1.c" "$src/hashes/sha1_desc.c" "$src/hashes/sha1_x86.c" .
for h in sha256 sha512
do
  cp -f "$src/hashes/sha2/$h.c" "$src/hashes/sha2/${h}_desc.c" "$src/hashes/sha2/${h}_x86.c" .
done

# HMAC
for f in done init memory process
do
  cp -f "$src/mac/hmac/hmac_$f.c" .
done

# PKCS #5
cp -f "$src/misc/pkcs5/pkcs_5_2.c" .

# go-sqlcipher: dispatch aes_desc to ARMv8 Crypto Extensions (aes_armce.c)
patch -p1 --no-backup-if-mismatch < "$(dirname "$0")/patches/aes_desc_armce.patch"

echo "libtomcrypt commit: $(git -C "$ltd" rev-parse HEAD 2>/dev/null || echo unknown) - update MAINTENANCE"
