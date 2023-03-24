// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

const (
	DB_PERM = 0600
	U32_FF  = uint32(0xff)
)

var (
	DB_BUCKET_SYM = []byte("Symbols")
	DB_BUCKET_SEC = []byte("Sections")
)

type MetaHints struct {
	Author string
	Name   string
	Hints  []*Hint
}

type MetaSymbol struct {
	Author string
	Symbol *Symbol
}

func SignatureToKey(s *Signature) []byte {
	symlen := U32_FF
	if s.Length < U32_FF {
		symlen = s.Length
	}
	arch := sanitizeWord(s.Arch, "x86")
	prefix := fmt.Sprintf("%s|%d|%02x|", arch, s.Bits, symlen)
	return append([]byte(prefix), s.Digest...)
}

func SectionHashToKey(sh *SectionHash, binType, binOs string) []byte {
	btype := sanitizeWord(binType, "any")
	bos := sanitizeWord(binOs, "any")
	prefix := fmt.Sprintf("%s|%s|%08x|", btype, bos, sh.Size)
	return append([]byte(prefix), sh.Digest...)
}

func setValue(db *bbolt.DB, name, key, value []byte) error {
	return db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(name)
		if bucket == nil {
			return BUCKET_SEC_FAIL
		}
		return bucket.Put(key, value)
	})
}

func getValue(db *bbolt.DB, name, key []byte) ([]byte, error) {
	var value []byte = nil
	err := db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(name)
		if bucket == nil {
			return BUCKET_SEC_FAIL
		}
		value = bucket.Get(key)
		return nil
	})
	return value, err
}

func DbGetHints(db *bbolt.DB, key []byte) ([]*Hint, error) {
	value, err := getValue(db, DB_BUCKET_SEC, key)
	if value == nil {
		return nil, err
	}

	ms := MetaHints{}
	err = json.Unmarshal(value, &ms)
	return ms.Hints, err
}

func DbHasHints(db *bbolt.DB, key []byte) (bool, error) {
	value, err := getValue(db, DB_BUCKET_SEC, key)
	return value != nil, err
}

func DbSetHints(db *bbolt.DB, key []byte, author, name string, hints []*Hint) error {
	ms := MetaHints{
		Author: author,
		Name:   name,
		Hints:  hints,
	}

	value, err := json.Marshal(&ms)
	if err != nil {
		return err
	}

	return setValue(db, DB_BUCKET_SEC, key, value)
}

func DbGetSymbol(db *bbolt.DB, key []byte) (*Symbol, error) {
	value, err := getValue(db, DB_BUCKET_SYM, key)
	if value == nil {
		return nil, err
	}

	ms := MetaSymbol{}
	err = json.Unmarshal(value, &ms)
	return ms.Symbol, err
}

func DbHasSymbol(db *bbolt.DB, key []byte) (bool, error) {
	value, err := getValue(db, DB_BUCKET_SYM, key)
	return value != nil, err
}

func DbSetSymbol(db *bbolt.DB, key []byte, author string, sym *Symbol) error {
	if sym == nil {
		return nil
	}

	ms := MetaSymbol{
		Author: author,
		Symbol: sym,
	}

	value, err := json.Marshal(&ms)
	if err != nil {
		return err
	}

	return setValue(db, DB_BUCKET_SYM, key, value)
}

func initDatabase(tx *bbolt.Tx) error {
	_, err := tx.CreateBucketIfNotExists(DB_BUCKET_SYM)
	if err != nil {
		return err
	}
	_, err = tx.CreateBucketIfNotExists(DB_BUCKET_SEC)
	if err != nil {
		return err
	}
	return nil
}

func OpenDatabase(filepath string) (*bbolt.DB, error) {
	db, err := bbolt.Open(filepath, DB_PERM, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}

	err = db.Update(initDatabase)
	if err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}
