#!/bin/sh
# Report whether the vendored upstreams have newer versions.
# Exit status: 0 = everything up to date, 1 = updates available, 2 = error.

cd "$(dirname "$0")" || exit 2

latest_tag() { # repo, grep -E filter for tags
  git ls-remote --tags --refs "https://github.com/$1" |
    sed 's#.*refs/tags/##' | grep -E "$2" | sort -V | tail -n 1
}

status=0
report() { # name, current, latest
  if [ -z "$3" ]; then
    echo "$1: could not query upstream" >&2
    exit 2
  elif [ "$2" = "$3" ]; then
    echo "$1: $2 (up to date)"
  else
    echo "$1: $2 -> $3 available"
    status=1
  fi
}

# go-sqlite3: version recorded in MAINTENANCE
cur=$(sed -n 's/^Current release: \(v1\.[0-9.]*\)$/\1/p' MAINTENANCE | head -n 1)
report "mattn/go-sqlite3" "$cur" "$(latest_tag mattn/go-sqlite3 '^v1\.[0-9]+\.[0-9]+$')"

# SQLCipher: version compiled into the amalgamation; stable 4.x only, but
# mention a newer major (5.x is not compatible with 4.x databases by default)
cur=v$(sed -n 's/^#define CIPHER_VERSION_NUMBER \([0-9.]*\)$/\1/p' sqlite3.c | head -n 1)
report "sqlcipher/sqlcipher" "$cur" "$(latest_tag sqlcipher/sqlcipher '^v4\.[0-9]+\.[0-9]+$')"
major=$(latest_tag sqlcipher/sqlcipher '^v[5-9]\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$')
[ -n "$major" ] && echo "  note: SQLCipher $major exists (new major version, review before adopting)"

# libtomcrypt: tracked from the develop branch
cur=$(sed -n 's/^Current HEAD: \([0-9a-f]*\)$/\1/p' MAINTENANCE | head -n 1)
head=$(git ls-remote https://github.com/libtom/libtomcrypt refs/heads/develop | cut -f 1)
report "libtom/libtomcrypt (develop)" "$cur" "$head"

# Mbed TLS: aes_armce.c is derived from the 3.6 LTS branch's aesce.c
cur=$(sed -n 's/^ \* Mbed TLS \([0-9.]*\) library\/aesce.c.*/\1/p' aes_armce.c | head -n 1)
latest=$(latest_tag Mbed-TLS/mbedtls '^mbedtls-3\.6\.[0-9]+$' | sed 's/^mbedtls-//')
report "Mbed-TLS/mbedtls 3.6 (aes_armce.c)" "$cur" "$latest"
[ "$cur" != "$latest" ] && echo "  note: only aesce.c changes matter, see MAINTENANCE"

exit $status
