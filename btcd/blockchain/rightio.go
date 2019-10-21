// Copyright (c) 2015-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
)

// dbPutRightView uses an existing database transaction to update the right set
// in the database based on the provided right view contents and state. In
// particular, only the entries that have been marked as modified (meaning new)
// and not spent (meaning not to be deleted) are written to the database.

func dbPutRightView(dbTx database.Tx, view *RightViewpoint) error {
	bucket := dbTx.Metadata().Bucket(rightSetBucketName)
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
			continue
		}

		// Serialize and store the utxo entry.
		serialized, err := serializeRightEntry(entry)
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
func serializeRightEntry(entry *RightEntry) ([]byte, error) {
	// Spent outputs have no serialization.
	if entry.toDelete() {
		return nil, nil
	}

	var serialized = make([]byte, chainhash.HashSize + len(entry.desc) + 1)
	copy(serialized[:], entry.father[:])
	serialized[chainhash.HashSize] = entry.attrib
	copy(serialized[chainhash.HashSize + 1:], entry.desc[:])

	return serialized, nil
}

func dbPutRight(dbTx database.Tx, d *wire.RightDef) error {
	meta := dbTx.Metadata()
	bkt := meta.Bucket(rightSetBucketName)

	serialized := make([]byte, chainhash.HashSize + 1 + len(d.Desc))
	copy(serialized[:], d.Father[:])
	serialized[chainhash.HashSize] = d.Attrib
	copy(serialized[chainhash.HashSize+1:], d.Desc)

	h := d.Hash()

	return bkt.Put(h[:], serialized[:])
}

func dbFetchRight(dbTx database.Tx, hash *chainhash.Hash) (*wire.RightDef, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(rightSetBucketName)
	serialized := hashIndex.Get(hash[:])

	var d wire.RightDef

	copy(d.Father[:], serialized[:])
	d.Attrib = serialized[chainhash.HashSize]
	d.Desc = make([]byte, len(serialized) - chainhash.HashSize - 1)
	copy(d.Desc, serialized[chainhash.HashSize+1:])

	return &d, nil
}

func dbRemoveRight(dbTx database.Tx, hash *chainhash.Hash) error {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(rightSetBucketName)

	return hashIndex.Delete(hash[:])
}
