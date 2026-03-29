package main

import (
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func TestOpenDatabaseUpgradesLegacyBuckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	legacyDB, err := bbolt.Open(path, DB_PERM, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = legacyDB.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(DB_BUCKET_SYM); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(DB_BUCKET_SEC); err != nil {
			return err
		}
		return nil
	})
	legacyDB.Close()
	if err != nil {
		t.Fatal(err)
	}

	db, err := OpenDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	err = db.View(func(tx *bbolt.Tx) error {
		if tx.Bucket(DB_BUCKET_SYM) == nil {
			t.Fatal("Symbols bucket missing")
		}
		if tx.Bucket(DB_BUCKET_SEC) == nil {
			t.Fatal("Sections bucket missing")
		}
		if tx.Bucket(DB_BUCKET_LOC) == nil {
			t.Fatal("Locations bucket missing")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
