package sqlite3_test

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	sqlite3 "github.com/AnoRebel/go-sqlcipher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	db      *sql.DB
	testDir = "go-sqlcipher_test"
	tables  = `
CREATE TABLE KeyValueStore (
  KeyEntry   TEXT NOT NULL UNIQUE,
  ValueEntry TEXT NOT NULL
);`
)

func init() {
	// create DB
	key := url.QueryEscape("passphrase")
	tmpdir, err := os.MkdirTemp("", testDir)
	if err != nil {
		panic(err)
	}
	dbname := filepath.Join(tmpdir, "sqlcipher_test")
	dbnameWithDSN := dbname + fmt.Sprintf("?_pragma_key=%s&_pragma_cipher_page_size=4096", key)
	db, err = sql.Open("sqlite3", dbnameWithDSN)
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(tables)
	if err != nil {
		panic(err)
	}
	db.Close()
	// make sure DB is encrypted
	encrypted, err := sqlite3.IsEncrypted(dbname)
	if err != nil {
		panic(err)
	}
	if !encrypted {
		panic(errors.New("go-sqlcipher: DB not encrypted"))
	}
	// open DB for testing
	db, err = sql.Open("sqlite3", dbnameWithDSN)
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("SELECT count(*) FROM sqlite_master;")
	if err != nil {
		panic(err)
	}
}

var mapping = map[string]string{
	"foo": "one",
	"bar": "two",
	"baz": "three",
}

func TestSQLCipherParallelInsert(t *testing.T) {
	t.Parallel()
	insertValueQuery, err := db.Prepare("INSERT INTO KeyValueStore (KeyEntry, ValueEntry) VALUES (?, ?);")
	require.NoError(t, err)
	for key, value := range mapping {
		_, err := insertValueQuery.Exec(key, value)
		assert.NoError(t, err)
	}
}

func TestSQLCipherParallelSelect(t *testing.T) {
	t.Parallel()
	getValueQuery, err := db.Prepare("SELECT ValueEntry FROM KeyValueStore WHERE KeyEntry=?;")
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range mapping {
		var val string
		err := getValueQuery.QueryRow(key).Scan(&val)
		if err != sql.ErrNoRows {
			if assert.NoError(t, err) {
				assert.Equal(t, value, val)
			}
		}
	}
}

func TestSQLCipherIsEncryptedFalse(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "unencrypted.sqlite")
	db, err := sql.Open("sqlite3", dbname)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.Exec(tables)
	require.NoError(t, err)
	encrypted, err := sqlite3.IsEncrypted(dbname)
	if assert.NoError(t, err) {
		assert.False(t, encrypted)
	}
}

func TestSQLCipherIsEncryptedTrue(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "encrypted.sqlite")
	var key [32]byte
	_, err := io.ReadFull(rand.Reader, key[:])
	require.NoError(t, err)
	dbnameWithDSN := dbname + fmt.Sprintf("?_pragma_key=x'%s'",
		hex.EncodeToString(key[:]))
	db, err := sql.Open("sqlite3", dbnameWithDSN)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.Exec(tables)
	require.NoError(t, err)
	encrypted, err := sqlite3.IsEncrypted(dbname)
	if assert.NoError(t, err) {
		assert.True(t, encrypted)
	}
}

func TestSQLCipher3DB(t *testing.T) {
	dbname := filepath.Join("testdata", "sqlcipher3.sqlite3")
	dbnameWithDSN := dbname + "?_pragma_key=passphrase&_pragma_cipher_page_size=4096"
	// make sure DB is encrypted
	encrypted, err := sqlite3.IsEncrypted(dbname)
	if err != nil {
		t.Fatal(err)
	}
	if !encrypted {
		t.Fatal("go-sqlcipher: DB not encrypted")
	}
	// open DB for testing
	db, err := sql.Open("sqlite3", dbnameWithDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// should fail — SQLCipher 4 cannot open v3 databases without compatibility mode
	_, err = db.Exec("SELECT count(*) FROM sqlite_master;")
	if err == nil {
		t.Fatal(errors.New("opening a SQLCipher 3 database with SQLCipher 4 should fail"))
	}
}

func TestSQLCipherCompatibilityMode(t *testing.T) {
	// Create a DB using cipher_compatibility=3, then reopen with the same mode
	dbname := filepath.Join(t.TempDir(), "compat.sqlite")
	dsnCompat3 := dbname + "?_pragma_key=testkey&_pragma_cipher_compatibility=3"

	// create DB with v3 compatibility settings
	db, err := sql.Open("sqlite3", dsnCompat3)
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, data TEXT);")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO t(data) VALUES('compat3');")
	require.NoError(t, err)
	db.Close()

	// verify encrypted
	encrypted, err := sqlite3.IsEncrypted(dbname)
	require.NoError(t, err)
	assert.True(t, encrypted)

	// reopen with v3 compatibility — should succeed
	db, err = sql.Open("sqlite3", dsnCompat3)
	require.NoError(t, err)
	defer db.Close()
	var data string
	err = db.QueryRow("SELECT data FROM t WHERE id=1;").Scan(&data)
	require.NoError(t, err)
	assert.Equal(t, "compat3", data)
}

func TestSQLCipher4DB(t *testing.T) {
	dbname := filepath.Join("testdata", "sqlcipher4.sqlite3")
	dbnameWithDSN := dbname + "?_pragma_key=passphrase&_pragma_cipher_page_size=4096"
	// make sure DB is encrypted
	encrypted, err := sqlite3.IsEncrypted(dbname)
	if err != nil {
		t.Fatal(err)
	}
	if !encrypted {
		t.Fatal("go-sqlcipher: DB not encrypted")
	}
	// open DB for testing
	db, err := sql.Open("sqlite3", dbnameWithDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// should succeed
	_, err = db.Exec("SELECT count(*) FROM sqlite_master;")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSQLCipherHexKey(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "hexkey.sqlite")
	var key [32]byte
	_, err := io.ReadFull(rand.Reader, key[:])
	require.NoError(t, err)
	hexKey := hex.EncodeToString(key[:])
	dbnameWithDSN := dbname + fmt.Sprintf("?_pragma_key=x'%s'&_pragma_cipher_page_size=4096", hexKey)

	// create and write data
	db, err := sql.Open("sqlite3", dbnameWithDSN)
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT);")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO t(name) VALUES(?);", "hello")
	require.NoError(t, err)
	db.Close()

	// verify encrypted
	encrypted, err := sqlite3.IsEncrypted(dbname)
	require.NoError(t, err)
	assert.True(t, encrypted)

	// reopen and read
	db, err = sql.Open("sqlite3", dbnameWithDSN)
	require.NoError(t, err)
	defer db.Close()
	var name string
	err = db.QueryRow("SELECT name FROM t WHERE id=1;").Scan(&name)
	require.NoError(t, err)
	assert.Equal(t, "hello", name)
}

func TestSQLCipherPassphrase(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "passphrase.sqlite")
	passphrase := url.QueryEscape("my secret passphrase!@#$%")
	dbnameWithDSN := dbname + fmt.Sprintf("?_pragma_key=%s&_pragma_cipher_page_size=4096", passphrase)

	// create and write data
	db, err := sql.Open("sqlite3", dbnameWithDSN)
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT);")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO t(value) VALUES(?);", "secret data")
	require.NoError(t, err)
	db.Close()

	// verify encrypted
	encrypted, err := sqlite3.IsEncrypted(dbname)
	require.NoError(t, err)
	assert.True(t, encrypted)

	// reopen and read
	db, err = sql.Open("sqlite3", dbnameWithDSN)
	require.NoError(t, err)
	defer db.Close()
	var value string
	err = db.QueryRow("SELECT value FROM t WHERE id=1;").Scan(&value)
	require.NoError(t, err)
	assert.Equal(t, "secret data", value)
}

func TestSQLCipherRekey(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "rekey.sqlite")
	oldKey := url.QueryEscape("oldpassword")
	newKey := url.QueryEscape("newpassword")
	dsnOld := dbname + fmt.Sprintf("?_pragma_key=%s", oldKey)
	dsnNew := dbname + fmt.Sprintf("?_pragma_key=%s", newKey)

	// create DB with old key
	db, err := sql.Open("sqlite3", dsnOld)
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, data TEXT);")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO t(data) VALUES('before rekey');")
	require.NoError(t, err)

	// rekey
	_, err = db.Exec(fmt.Sprintf("PRAGMA rekey = \"%s\";", newKey))
	require.NoError(t, err)
	db.Close()

	// verify old key no longer works
	db, err = sql.Open("sqlite3", dsnOld)
	require.NoError(t, err)
	_, err = db.Exec("SELECT count(*) FROM sqlite_master;")
	assert.Error(t, err)
	db.Close()

	// verify new key works
	db, err = sql.Open("sqlite3", dsnNew)
	require.NoError(t, err)
	defer db.Close()
	var data string
	err = db.QueryRow("SELECT data FROM t WHERE id=1;").Scan(&data)
	require.NoError(t, err)
	assert.Equal(t, "before rekey", data)
}

func TestSQLCipherPageSize(t *testing.T) {
	pageSizes := []int{1024, 4096, 8192, 16384}
	for _, pageSize := range pageSizes {
		t.Run(fmt.Sprintf("page_size_%d", pageSize), func(t *testing.T) {
			dbname := filepath.Join(t.TempDir(), "pagesize.sqlite")
			dsn := dbname + fmt.Sprintf("?_pragma_key=test&_pragma_cipher_page_size=%d", pageSize)

			db, err := sql.Open("sqlite3", dsn)
			require.NoError(t, err)
			defer db.Close()

			_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, data TEXT);")
			require.NoError(t, err)
			_, err = db.Exec("INSERT INTO t(data) VALUES('test');")
			require.NoError(t, err)

			var data string
			err = db.QueryRow("SELECT data FROM t WHERE id=1;").Scan(&data)
			require.NoError(t, err)
			assert.Equal(t, "test", data)
		})
	}
}

func TestSQLCipherWAL(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "wal.sqlite")
	dsn := dbname + "?_pragma_key=waltest&_pragma_cipher_page_size=4096"

	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	defer db.Close()

	// enable WAL mode
	var mode string
	err = db.QueryRow("PRAGMA journal_mode=WAL;").Scan(&mode)
	require.NoError(t, err)
	assert.Equal(t, "wal", mode)

	// create table and write data
	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, data TEXT);")
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		_, err = db.Exec("INSERT INTO t(data) VALUES(?);", fmt.Sprintf("row-%d", i))
		require.NoError(t, err)
	}

	var count int
	err = db.QueryRow("SELECT count(*) FROM t;").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 100, count)
}

func TestSQLCipherLargeData(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "large.sqlite")
	dsn := dbname + "?_pragma_key=largetest&_pragma_cipher_page_size=4096"

	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, data TEXT);")
	require.NoError(t, err)

	// insert 10000 rows in a transaction
	tx, err := db.Begin()
	require.NoError(t, err)
	stmt, err := tx.Prepare("INSERT INTO t(data) VALUES(?);")
	require.NoError(t, err)
	for i := 0; i < 10000; i++ {
		_, err = stmt.Exec(fmt.Sprintf("data-%d", i))
		require.NoError(t, err)
	}
	err = tx.Commit()
	require.NoError(t, err)

	// verify count
	var count int
	err = db.QueryRow("SELECT count(*) FROM t;").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 10000, count)

	// verify a specific row
	var data string
	err = db.QueryRow("SELECT data FROM t WHERE id=5000;").Scan(&data)
	require.NoError(t, err)
	assert.Equal(t, "data-4999", data)
}

func TestSQLCipherConcurrent(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "concurrent.sqlite")
	dsn := dbname + "?_pragma_key=concurrent&_pragma_cipher_page_size=4096"

	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1) // SQLite only supports one writer at a time

	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, data TEXT);")
	require.NoError(t, err)

	// concurrent writes
	var wg sync.WaitGroup
	errCh := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := db.Exec("INSERT INTO t(data) VALUES(?);", fmt.Sprintf("goroutine-%d", n))
			if err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent write error: %v", err)
	}

	// verify all rows written
	var count int
	err = db.QueryRow("SELECT count(*) FROM t;").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 50, count)
}

func TestSQLCipherPragmaVersion(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "version.sqlite")
	dsn := dbname + "?_pragma_key=versiontest"

	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	defer db.Close()

	// must create something to force the connection open
	_, err = db.Exec("CREATE TABLE t(x INTEGER);")
	require.NoError(t, err)

	var cipherVersion string
	err = db.QueryRow("PRAGMA cipher_version;").Scan(&cipherVersion)
	require.NoError(t, err)
	assert.NotEmpty(t, cipherVersion)
	t.Logf("cipher_version: %s", cipherVersion)

	var cipherProvider string
	err = db.QueryRow("PRAGMA cipher_provider;").Scan(&cipherProvider)
	require.NoError(t, err)
	assert.NotEmpty(t, cipherProvider)
	t.Logf("cipher_provider: %s", cipherProvider)
}

func TestSQLCipherNullBlob(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "nullblob.sqlite")
	dsn := dbname + "?_pragma_key=nulltest"

	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, data BLOB);")
	require.NoError(t, err)

	// insert NULL blob
	_, err = db.Exec("INSERT INTO t(id, data) VALUES(1, NULL);")
	require.NoError(t, err)

	// insert non-NULL blob
	_, err = db.Exec("INSERT INTO t(id, data) VALUES(2, ?);", []byte("hello"))
	require.NoError(t, err)

	// insert zero-length blob
	_, err = db.Exec("INSERT INTO t(id, data) VALUES(3, ?);", []byte{})
	require.NoError(t, err)

	// scan NULL blob — column type is SQLITE_NULL, returns nil
	var nullData []byte
	err = db.QueryRow("SELECT data FROM t WHERE id=1;").Scan(&nullData)
	require.NoError(t, err)
	assert.Nil(t, nullData, "NULL BLOB should scan as nil")

	// scan non-NULL blob
	var blobData []byte
	err = db.QueryRow("SELECT data FROM t WHERE id=2;").Scan(&blobData)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), blobData)

	// scan zero-length blob — returns empty slice, not nil
	var emptyData []byte
	err = db.QueryRow("SELECT data FROM t WHERE id=3;").Scan(&emptyData)
	require.NoError(t, err)
	assert.NotNil(t, emptyData, "zero-length BLOB should scan as empty slice, not nil")
	assert.Empty(t, emptyData)
}

func TestSQLCipherWrongKey(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "wrongkey.sqlite")
	dsn := dbname + "?_pragma_key=correctkey&_pragma_cipher_page_size=4096"

	// create encrypted DB
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY);")
	require.NoError(t, err)
	db.Close()

	// try to open with wrong key
	wrongDSN := dbname + "?_pragma_key=wrongkey&_pragma_cipher_page_size=4096"
	db, err = sql.Open("sqlite3", wrongDSN)
	require.NoError(t, err)
	defer db.Close()

	// any query should fail
	_, err = db.Exec("SELECT count(*) FROM sqlite_master;")
	assert.Error(t, err, "wrong key should cause an error")
}

func TestSQLCipherEmptyDB(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "empty.sqlite")
	dsn := dbname + "?_pragma_key=emptytest"

	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	defer db.Close()

	// create a table on an empty encrypted DB
	_, err = db.Exec("CREATE TABLE t(x INTEGER);")
	require.NoError(t, err)

	// verify it's encrypted
	encrypted, err := sqlite3.IsEncrypted(dbname)
	require.NoError(t, err)
	assert.True(t, encrypted)
}

func TestSQLCipherBlobReadWrite(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "blob.sqlite")
	dsn := dbname + "?_pragma_key=blobtest"

	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, data BLOB);")
	require.NoError(t, err)

	// write random binary data
	binaryData := make([]byte, 4096)
	_, err = io.ReadFull(rand.Reader, binaryData)
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO t(data) VALUES(?);", binaryData)
	require.NoError(t, err)

	// read it back
	var result []byte
	err = db.QueryRow("SELECT data FROM t WHERE id=1;").Scan(&result)
	require.NoError(t, err)
	assert.Equal(t, binaryData, result)
}

func TestSQLCipherTransactions(t *testing.T) {
	dbname := filepath.Join(t.TempDir(), "tx.sqlite")
	dsn := dbname + "?_pragma_key=txtest"

	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, data TEXT);")
	require.NoError(t, err)

	// test commit
	tx, err := db.Begin()
	require.NoError(t, err)
	_, err = tx.Exec("INSERT INTO t(data) VALUES('committed');")
	require.NoError(t, err)
	err = tx.Commit()
	require.NoError(t, err)

	var count int
	err = db.QueryRow("SELECT count(*) FROM t;").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// test rollback
	tx, err = db.Begin()
	require.NoError(t, err)
	_, err = tx.Exec("INSERT INTO t(data) VALUES('rolled back');")
	require.NoError(t, err)
	err = tx.Rollback()
	require.NoError(t, err)

	err = db.QueryRow("SELECT count(*) FROM t;").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "rollback should not have added a row")
}

func ExampleIsEncrypted() {
	// create random key
	var key [32]byte
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		log.Fatal(err)
	}
	// set DB name
	dbname := "go-sqlcipher.sqlite"
	dbnameWithDSN := dbname + fmt.Sprintf("?_pragma_key=x'%s'",
		hex.EncodeToString(key[:]))
	// create encrypted DB file
	db, err := sql.Open("sqlite3", dbnameWithDSN)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(dbname)
	defer db.Close()
	// create table
	_, err = db.Exec("CREATE TABLE t(x INTEGER);")
	if err != nil {
		log.Fatal(err)
	}
	// make sure database is encrypted
	encrypted, err := sqlite3.IsEncrypted(dbname)
	if err != nil {
		log.Fatal(err)
	}
	if encrypted {
		fmt.Println("DB is encrypted")
	} else {
		fmt.Println("DB is unencrypted")
	}
	// Output:
	// DB is encrypted
}
