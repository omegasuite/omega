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
// in the database based on the provided utxo view contents and state. In
// particular, only the entries that have been marked as modified (meaning new)
// and not spent (meaning not to be deleted) are written to the database.
func dbPutPolygonView(dbTx database.Tx, view *PolygonViewpoint) error {
	bucket := dbTx.Metadata().Bucket(polygonSetBucketName)
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
		serialized, err := serializePolygonEntry(entry)
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
func serializePolygonEntry(entry *PolygonEntry) ([]byte, error) {
	// Spent outputs have no serialization.
	if entry.toDelete() {
		return nil, nil
	}

	size := serializeSizeVLQ(uint64(len(entry.loops)))
	for _, l := range entry.loops {
		size += serializeSizeVLQ(uint64(len(l))) + len(l) * chainhash.HashSize
	}

	var serialized = make([]byte, size)

	putVLQ(serialized[:], uint64(len(entry.loops)))
	p := serializeSizeVLQ(uint64(len(entry.loops)))
	for _, l := range entry.loops {
		putVLQ(serialized[p:], uint64(len(l)))
		p += serializeSizeVLQ(uint64(len(l)))
		for _,t := range l {
			copy(serialized[p:], t[:])
			p +=  chainhash.HashSize
		}
	}

	return serialized, nil
}

func dbPutPolygon(dbTx database.Tx, p *wire.PolygonDef) error {
	meta := dbTx.Metadata()
	bkt := meta.Bucket(polygonSetBucketName)

	count := serializeSizeVLQ(uint64(len(p.Loops)))
	for _, l := range p.Loops {
		count += serializeSizeVLQ(uint64(len(l))) + len(l) * chainhash.HashSize
	}

	serialized := make([]byte, count)
	offset := putVLQ(serialized, uint64(len(p.Loops)))
	for _, l := range p.Loops {
		offset += putVLQ(serialized[offset:], uint64(len(l)))
		for _, b := range l {
			copy(serialized[offset:], b[:])
			offset += chainhash.HashSize
		}
	}

	h := p.Hash()

	return bkt.Put(h[:], serialized)
}

func dbFetchPolygon(dbTx database.Tx, hash *chainhash.Hash) (*wire.PolygonDef, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(polygonSetBucketName)
	serialized := hashIndex.Get(hash[:])

	if serialized == nil {
		str := fmt.Sprintf("polygon %s does not exist in the main chain", hash)
		return nil, errNotInMainChain(str)
	}

	b := wire.PolygonDef {}

	loops, pos := deserializeVLQ(serialized)

	b.Loops = make([]wire.LoopDef, loops)

	for i := uint64(0);  i < loops; i++ {
		bds, offset := deserializeVLQ(serialized[pos:])
		pos += offset
		loop := make([]chainhash.Hash, bds)
		for j := uint64(0);  j < bds; j++ {
			copy(loop[j][:], serialized[pos:pos + chainhash.HashSize])
			pos += chainhash.HashSize
		}
		b.Loops[i] = loop
	}

	return &b, nil
}

func dbRemovePolygon(dbTx database.Tx, hash *chainhash.Hash) error {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(polygonSetBucketName)

	return hashIndex.Delete(hash[:])
}
