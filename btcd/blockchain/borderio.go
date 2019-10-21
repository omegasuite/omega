// Copyright (c) 2015-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
)

// dbPutVtxView uses an existing database transaction to update the vertex set
// in the database based on the provided utxo view contents and state. In
// particular, only the entries that have been marked as modified (meaning new)
// and not spent (meaning not to be deleted) are written to the database.
func dbPutBorderView(dbTx database.Tx, view *BorderViewpoint) error {
	bucket := dbTx.Metadata().Bucket(borderSetBucketName)

	for hash, entry := range view.Entries() {
		// No need to update the database if the entry was not modified.
		if entry == nil || !entry.isModified() {
			continue
		}

		// Remove the utxo entry if it is spent.
		if entry.toDelete() {
			if err := bucket.Delete(hash[:]); err != nil {
				return err
			}
		}

		// Serialize and store the utxo entry.
		serialized, err := serializeBorderEntry(entry)
		if err != nil {
			return err
		}

		if err = bucket.Put(hash[:], serialized); err != nil {
			return err
		}
	}

	return nil
}

// serializeVtxEntry returns the entry serialized to a format that is suitable
// for long-term storage.  The format is described in detail above.
func serializeBorderEntry(entry *BorderEntry) ([]byte, error) {
	// Spent outputs have no serialization.
	if entry.toDelete() {
		return nil, nil
	}

	var serialized = make([]byte, chainhash.HashSize * (3 + len(entry.children)))

	copy(serialized[:], entry.father[:])
	copy(serialized[chainhash.HashSize:], entry.begin[:])
	copy(serialized[chainhash.HashSize * 2:], entry.end[:])

	pos := chainhash.HashSize * 3
	for _,v := range entry.children {
		copy(serialized[pos:], v[:])
		pos += chainhash.HashSize
	}

	return serialized, nil
}

func dbFetchBorderEntry(dbTx database.Tx, hash *chainhash.Hash) (*BorderEntry, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(borderSetBucketName)
	serialized := hashIndex.Get(hash[:])

	if serialized == nil {
		str := fmt.Sprintf("border %s does not exist in the main chain", hash)
		return nil, errNotInMainChain(str)
	}

	b := BorderEntry{}

	copy(b.father[:], serialized[:chainhash.HashSize])
	copy(b.begin[:], serialized[chainhash.HashSize:chainhash.HashSize * 2])
	copy(b.end[:], serialized[chainhash.HashSize * 2:chainhash.HashSize * 3])
	b.children = make([]chainhash.Hash, (len(serialized) - 3 * chainhash.HashSize) / chainhash.HashSize)

	for i := 0; i < len(b.children); i ++ {
		copy(b.children[i][:], serialized[(i + 3) * chainhash.HashSize:])
	}

	return &b, nil
}

func dbRemoveBorder(dbTx database.Tx, hash *chainhash.Hash) error {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(borderSetBucketName)

	// remove border itself
	return hashIndex.Delete(hash[:])
}
