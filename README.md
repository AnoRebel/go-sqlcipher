## go-sqlcipher

[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/AnoRebel/go-sqlcipher) [![CI](https://github.com/AnoRebel/go-sqlcipher/workflows/CI/badge.svg)](https://github.com/AnoRebel/go-sqlcipher/actions)

### Description

Self-contained Go sqlite3 driver with an AES-256 encrypted sqlite3 database
conforming to the built-in database/sql interface. It is based on:

- Go sqlite3 driver: https://github.com/mattn/go-sqlite3 (v1.14.53)
- SQLite extension with AES-256 codec: https://github.com/sqlcipher/sqlcipher (v4.20.0, SQLite 3.54.1)
- AES-256 implementation from: https://github.com/libtom/libtomcrypt
- ARMv8 AES derived from https://github.com/Mbed-TLS/mbedtls (3.6.7)

SQLite itself is part of SQLCipher.

### Requirements

- Go 1.26+
- C compiler (gcc or clang) for CGo

### Hardware acceleration

The crypto implementation is chosen at runtime, with a portable C fallback:

| CPU | AES | SHA |
|---|---|---|
| x86 / x86_64 | AES-NI | SHA-1/SHA-256 extensions; SHA-512 extension with GCC 14+ / clang 17+ on CPUs that have it |
| arm64 (Linux, Android, macOS) | ARMv8 Crypto Extensions | portable C |
| other | portable C | portable C |

Build with `CGO_CFLAGS="-O2 -g -DLTC_NO_ACCEL"` to force the portable C
implementations. SQLCipher 4 uses HMAC-SHA512 per page and
PBKDF2-HMAC-SHA512 for passphrases, so the gain from AES acceleration alone
is moderate for page I/O and none for key derivation unless the CPU also has
the SHA-512 extension.

### Incompatibilities of SQLCipher

**SQLCipher 4.x is incompatible with SQLCipher 3.x!**

go-sqlcipher supports a compatibility mode to open SQLCipher 3.x databases
(see `_pragma_cipher_compatibility` below).

See [migrating databases](https://www.zetetic.net/sqlcipher/sqlcipher-api/#Migrating_Databases) for details.

### Installation

This package can be installed with the go get command:

    go get github.com/AnoRebel/go-sqlcipher


### Documentation

To create and open encrypted database files use the following DSN parameters:

**Hex key (256-bit):**

```go
key := "2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99"
dbname := fmt.Sprintf("db?_pragma_key=x'%s'&_pragma_cipher_page_size=4096", key)
db, _ := sql.Open("sqlite3", dbname)
```

`_pragma_key` is the hex encoded 32 byte key (must be 64 characters long).
`_pragma_cipher_page_size` is the page size of the encrypted database (set if
you want a different value than the default size).

**Passphrase:**

```go
key := url.QueryEscape("secret")
dbname := fmt.Sprintf("db?_pragma_key=%s&_pragma_cipher_page_size=4096", key)
db, _ := sql.Open("sqlite3", dbname)
```

This uses a passphrase directly as `_pragma_key` with the key derivation function in
SQLCipher. Do not forget the `url.QueryEscape()` call in your code!

**SQLCipher 3 compatibility mode:**

```go
dbname := "db?_pragma_key=secret&_pragma_cipher_compatibility=3"
db, _ := sql.Open("sqlite3", dbname)
```

This opens a database created with SQLCipher 3.x using the v4 library.

See also [PRAGMA key](https://www.zetetic.net/sqlcipher/sqlcipher-api/#PRAGMA_key).

### DSN Parameters

| Parameter | Description |
|---|---|
| `_pragma_key` | Encryption key (hex with `x'...'` prefix, or passphrase via `url.QueryEscape()`) |
| `_pragma_cipher_page_size` | Page size for the encrypted database (default: SQLCipher default) |
| `_pragma_cipher_compatibility` | Set to `3` to open SQLCipher 3.x databases (applied before the settings below, which override it) |
| `_pragma_kdf_iter` | PBKDF2 iterations for passphrase keys |
| `_pragma_cipher_hmac_algorithm` | `HMAC_SHA1`, `HMAC_SHA256` or `HMAC_SHA512` |
| `_pragma_cipher_kdf_algorithm` | `PBKDF2_HMAC_SHA1`, `PBKDF2_HMAC_SHA256` or `PBKDF2_HMAC_SHA512` |
| `_pragma_cipher_plaintext_header_size` | Bytes of the header left unencrypted (e.g. `32` for iOS shared containers). The salt can then not be stored in the file: use a raw key with salt, `x'<64 hex key><32 hex salt>'` |

All other go-sqlite3 DSN parameters work as well, e.g. `_stmt_cache_size` to
cache prepared statements per connection.

Settings must match the ones the database was created with. See
[SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/).

### Utility Functions

Use the function
[sqlite3.IsEncrypted()](https://godoc.org/github.com/AnoRebel/go-sqlcipher#IsEncrypted)
to check whether a database file is encrypted or not.

### Maintenance

See [MAINTENANCE](MAINTENANCE). `./check_upstream.sh` reports whether
go-sqlite3, SQLCipher, libtomcrypt or Mbed TLS have newer versions.

### Examples

Examples can be found under the `./_example` directory.

### License

The code of the originating packages is covered by their respective licenses.
See [LICENSE](LICENSE) file for details.
