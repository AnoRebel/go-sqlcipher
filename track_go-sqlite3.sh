#!/bin/sh -e

if [ $# -ne 1 ]
then
  echo "Usage: $0 go-sqlite3_dir" >&2
  echo "Copy tracked source files from go-sqlite3 to current directory." >&2
  exit 1
fi

ltd=$1

# report Go files that upstream does not have: either local additions (keep)
# or files upstream removed/renamed (delete)
for f in *.go
do
  [ -e "$ltd/$f" ] || echo "not in upstream (keep if local, delete if removed upstream): $f"
done

# copy C files
cp -f "$ltd"/sqlite3_opt_unlock_notify.c .

# copy Go files
cp -f "$ltd"/*.go .
rm -rf _example
cp -r "$ltd"/_example .

# rewrite import paths
for f in *.go $(find _example -name '*.go' -o -name Makefile -o -name Dockerfile)
do
  sed 's#github.com/mattn/go-sqlite3#github.com/AnoRebel/go-sqlcipher#g' "$f" > "$f.tmp"
  mv "$f.tmp" "$f"
done

echo "make sure to adjust sqlite3.go with sqlcipher pragmas and #include <stdint.h>!"
