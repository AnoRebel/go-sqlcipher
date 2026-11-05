package sqlite3

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
)

// sqlite3Header defines the header string used by SQLite 3.
var sqlite3Header = []byte("SQLite format 3\000")

// IsEncrypted returns true, if the database with the given filename is
// encrypted, and false otherwise.
// If the database header cannot be read properly an error is returned.
func IsEncrypted(filename string) (bool, error) {
	// open file
	db, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer db.Close()
	// read header
	var header [16]byte
	n, err := db.Read(header[:])
	if err != nil {
		return false, err
	}
	if n != len(header) {
		return false, errors.New("go-sqlcipher: could not read full header")
	}
	// SQLCipher encrypts also the header, the file is encrypted if the read
	// header does not equal the header string used by SQLite 3.
	encrypted := !bytes.Equal(header[:], sqlite3Header)
	return encrypted, nil
}

// parseCipherPragmas turns the SQLCipher DSN parameters into the PRAGMA
// statements to run right after opening the database, in the required order:
// key first, then cipher_compatibility (which resets all cipher settings to
// the defaults of that major version), then the individual settings.
func parseCipherPragmas(params url.Values) ([]string, error) {
	var pragmas []string

	if key := params.Get("_pragma_key"); key != "" {
		// single-quoted SQL string literal; SQLCipher sees the same value for
		// passphrases and raw x'...' keys
		pragmas = append(pragmas, "PRAGMA key = '"+strings.ReplaceAll(key, "'", "''")+"';")
	}

	ints := []struct{ param, pragma string }{
		{"_pragma_cipher_compatibility", "cipher_compatibility"},
		{"_pragma_cipher_page_size", "cipher_page_size"},
		{"_pragma_kdf_iter", "kdf_iter"},
		{"_pragma_cipher_plaintext_header_size", "cipher_plaintext_header_size"},
	}
	for _, p := range ints {
		val := params.Get(p.param)
		if val == "" {
			continue
		}
		n, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("sqlite3: %s cannot be parsed: %s", p.param, err)
		}
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA %s = %d;", p.pragma, n))
	}

	algos := []struct {
		param, pragma string
		allowed       []string
	}{
		{"_pragma_cipher_hmac_algorithm", "cipher_hmac_algorithm",
			[]string{"HMAC_SHA1", "HMAC_SHA256", "HMAC_SHA512"}},
		{"_pragma_cipher_kdf_algorithm", "cipher_kdf_algorithm",
			[]string{"PBKDF2_HMAC_SHA1", "PBKDF2_HMAC_SHA256", "PBKDF2_HMAC_SHA512"}},
	}
	for _, a := range algos {
		val := strings.ToUpper(params.Get(a.param))
		if val == "" {
			continue
		}
		if !slices.Contains(a.allowed, val) {
			return nil, fmt.Errorf("sqlite3: %s must be one of %s", a.param, strings.Join(a.allowed, ", "))
		}
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA %s = %s;", a.pragma, val))
	}

	return pragmas, nil
}
