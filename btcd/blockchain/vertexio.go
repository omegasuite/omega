// Copyright (c) 2015-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
)

// dbPutVtxView uses an existing database transaction to update the vertex set
// in the database based on the provided vertex view contents and state. In
// particular, only the entries that have been marked as modified (meaning new)
// and not spent (meaning not to be deleted) are written to the database.

func dbPutVtxView(dbTx database.Tx, view *VtxViewpoint) error {
	bucket := dbTx.Metadata().Bucket(vertexSetBucketName)
	for hash, entry := range view.Entries() {
		// No need to update the database if the entry was not modified.
		if entry == nil || !entry.isModified() {
			continue
		}

		// Remove the vertex entry if it is marked for deletion.
		if entry.toDelete() {
			if err := bucket.Delete(hash[:]); err != nil {
				return err
			}
			continue
		}

		// Serialize and store the utxo entry.
		serialized, err := serializeVtxEntry(entry)
		if err = bucket.Put(hash[:], serialized); err != nil {
			return err
		}
	}

	return nil
}

// serializeVtxEntry returns the entry serialized to a format that is suitable
// for long-term storage.  The format is described in detail above.
func serializeVtxEntry(entry *VtxEntry) ([]byte, error) {
	// Spent outputs have no serialization.
	if entry.toDelete() {
		return nil, nil
	}

	var serialized = make([]byte, 8 + len(entry.desc))

	byteOrder.PutUint32(serialized[:], entry.lat)
	byteOrder.PutUint32(serialized[4:], entry.lng)
	copy(serialized[8:], entry.desc[:])

	return serialized, nil
}

func (b *BlockChain) dbFetchVertex(blockHeight int32, tx int32, ind uint32) (*wire.VertexDef, error) {
	blk,err := b.BlockByHeight(blockHeight)
	if err != nil {
		return nil, err
	}

	return blk.Transactions()[tx].MsgTx().TxDef[ind].(*wire.VertexDef), nil
}

func dbFetchVertexEntry(dbTx database.Tx, hash *chainhash.Hash) (*VtxEntry, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(vertexSetBucketName)
	serialized := hashIndex.Get(hash[:])
	if serialized == nil {
		str := fmt.Sprintf("vertex %s does not exist in the main chain", hash)
		return nil, errNotInMainChain(str)
	}

	vtx := VtxEntry { }
	vtx.lat = byteOrder.Uint32(serialized[:])
	vtx.lng = byteOrder.Uint32(serialized[4:])
	vtx.desc = make([]byte, len(serialized) - 8)
	copy(vtx.desc[:], serialized[8:])

	return &vtx, nil
}

func dbRemoveVertex(dbTx database.Tx, hash *chainhash.Hash) error {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(vertexSetBucketName)
	return hashIndex.Delete(hash[:])
}
