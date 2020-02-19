/* Copyright (C) 2019-2020 omega-chain.com - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
* You should have received a copy of the license with this file.
* If not, please visit: <https://omega-chain.com/license.html>
 */

package viewpoint

import (
//	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
//	"github.com/btcsuite/btcd/txscript"
//	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
	"fmt"
	"github.com/btcsuite/btcd/blockchain/bccompress"
)

// VtxEntry houses details about an individual vertex definition in a definition
// view.
type PolygonEntry struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.

	Loops []token.LoopDef

	// packedFlags contains additional info about vertex. Currently unused.
	PackedFlags txoFlags
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry * PolygonEntry) isModified() bool {
	return entry.PackedFlags & TfModified == TfModified
}

func (entry * PolygonEntry) toDelete() bool {
	return entry.PackedFlags & TfSpent == TfSpent
}

// Clone returns a shallow copy of the vertex entry.
func (entry * PolygonEntry) Clone() *PolygonEntry {
	if entry == nil {
		return nil
	}

	return &PolygonEntry{
		Loops:   entry.Loops,
		PackedFlags: entry.PackedFlags,
	}
}

func (entry * PolygonEntry) deReference(view * ViewPointSet) {
	for _, loop := range entry.Loops {
		for _, b := range loop {
			fb, _ := view.Border.FetchEntry(view.Db, &b)
			fb.deReference()
		}
	}
}

func (entry * PolygonEntry) reference(view * ViewPointSet) {
	for _, loop := range entry.Loops {
		for _, b := range loop {
			fb, _ := view.Border.FetchEntry(view.Db, &b)
			fb.reference()
		}
	}
}

func (entry * PolygonEntry) ToToken() *token.PolygonDef {
	return &token.PolygonDef{
		Loops: entry.Loops,
	}
}
// VtxViewpoint represents a view into the set of vertex definition
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.

type PolygonViewpoint struct {
	entries  map[chainhash.Hash]*PolygonEntry
	bestHash chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view * PolygonViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view * PolygonViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// LookupEntry returns information about a given vertex according to
// the current state of the view.  It will return nil if the passed vertex does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
func (view * PolygonViewpoint) LookupEntry(p chainhash.Hash) * PolygonEntry {
	return view.entries[p]
}

// addVertex adds the specified vertex to the view.
func (view * ViewPointSet) addPolygon(b *token.PolygonDef) bool {
	h := b.Hash()
	entry := view.Polygon.LookupEntry(h)
	if entry == nil {
		entry = new(PolygonEntry)
		entry.Loops = b.Loops
		for _, loop := range b.Loops {
			for _, b := range loop {
				d, _ := view.Border.FetchEntry(view.Db, &b)
				if d == nil {
					return false
				}
			}
		}
		entry.PackedFlags = TfModified
		view.Polygon.entries[h] = entry
	}
	return true
}
// addVertex adds the specified vertex to the view.
func (view * ViewPointSet) AddOnePolygon(b *token.PolygonDef) bool {
	return view.addPolygon(b)
}

// AddVertices adds all vertex definitions in the passed transaction to the view.
func (view * ViewPointSet) AddPolygon(tx *btcutil.Tx) bool {
	// Loop all of the vertex definitions

	for _, txVtx := range tx.MsgTx().TxDef {
		switch txVtx.(type) {
			case *token.PolygonDef:
				if !view.addPolygon(txVtx.(*token.PolygonDef)) {
					return false
				}
			break
		}
	}
	return true
}

// FetchEntry attempts to find any vertex for the given hash by
// searching the entire view.  It checks the view first and then falls
// back to the database if needed.
func (view * PolygonViewpoint) FetchEntry(db database.DB, hash *chainhash.Hash) (*PolygonEntry, error) {
	// First attempt to find a utxo with the provided hash in the view.
	entry := view.LookupEntry(*hash)
	if entry != nil {
		return entry, nil
	}

	// Check the database since it doesn't exist in the view.  This will
	// often by the case since only specifically referenced vertex are loaded
	// into the view.
	err := db.View(func(dbTx database.Tx) error {
		e, err := DbFetchPolygon(dbTx, hash)
		if err != nil {
			return err
		}
		entry = &PolygonEntry{
			Loops: e.Loops,
			PackedFlags: 0,
		}
		view.entries[*hash] = entry
		return  err
	})
	return entry, err
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (entry *PolygonEntry) RollBack() {
	// Nothing to do if the output is already spent.
	if entry.toDelete() {
		return
	}

	// Mark the output as spent and modified.
	entry.PackedFlags |= TfSpent | TfModified
}

// disconnectTransactions updates the view by removing all of the transactions
// created by the passed block, removing all vertices defined in the transactions,
// and setting the best hash for the view to the block before the passed block.
func (view * PolygonViewpoint) disconnectTransactions(db database.DB, block *btcutil.Block) error {
	for _,tx := range block.Transactions() {
		for _, txDef := range tx.MsgTx().TxDef {
			switch txDef.(type) {
			case *token.PolygonDef:
				view.LookupEntry(txDef.Hash()).RollBack()
				break
			}
		}
	}

	// Update the best hash for view to the previous block since all of the
	// transactions for the current block have been disconnected.
	view.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return nil
}

// RemoveEntry removes the given transaction output from the current state of
// the view.  It will have no effect if the passed output does not exist in the
// view.
func (view * PolygonViewpoint) RemoveEntry(hash chainhash.Hash) {
	delete(view.entries, hash)
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view * PolygonViewpoint) Entries() map[chainhash.Hash]*PolygonEntry {
	return view.entries
}

// commit. this is to be called after data has been committed to db
func (view * PolygonViewpoint) commit() {
	for outpoint, entry := range view.entries {
		if entry == nil || ((entry.PackedFlags & TfSpent) == TfSpent) {
			delete(view.entries, outpoint)
			continue
		}

		entry.PackedFlags ^= TfModified
	}
}

// fetchVertexMain fetches vertex data about the provided
// set of vertices from the point of view of the end of the main chain at the
// time of the call.
//
// Upon completion of this function, the view will contain an entry for each
// requested vertices.
func (view * PolygonViewpoint) fetchPolygonMain(db database.DB, b map[chainhash.Hash]struct{}) error {
	// Nothing to do if there are no requested outputs.
	if len(b) == 0 {
		return nil
	}

	// Load the requested set of vertices from the point
	// of view of the end of the main chain.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the store as a way
	// to unnecessarily avoid attempting to reload it from the database.
	return db.View(func(dbTx database.Tx) error {
		for vtx,_ := range b {
			e, err := DbFetchPolygon(dbTx, &vtx)
			if err != nil {
				return err
			}

			view.entries[vtx] = &PolygonEntry{
				Loops: e.Loops,
				PackedFlags: 0,
			}
		}

		return nil
	})
}

// fetchVertex loads the vertices for the provided set into the view
// from the database as needed unless they already exist
// in the view in which case they are ignored.
func (view * PolygonViewpoint) FetchPolygon(db database.DB, b map[chainhash.Hash]struct{}) error {
	// Nothing to do if there are no requested vertices.
	if len(b) == 0 {
		return nil
	}

	// Filter entries that are already in the view.
	neededSet := make(map[chainhash.Hash]struct{})
	for vtx := range b {
		// Already loaded into the current view.
		if _, ok := view.entries[vtx]; ok {
			continue
		}

		neededSet[vtx] = struct{}{}
	}

	// Request the input utxos from the database.
	return view.fetchPolygonMain(db, neededSet)
}

// NewVtxViewpoint returns a new empty vertex view.
func NewPolygonViewpoint() * PolygonViewpoint {
	return &PolygonViewpoint{
		entries: make(map[chainhash.Hash]*PolygonEntry),
	}
}


// dbPutVtxView uses an existing database transaction to update the vertex set
// in the database based on the provided utxo view contents and state. In
// particular, only the entries that have been marked as modified (meaning new)
// and not spent (meaning not to be deleted) are written to the database.
func DbPutPolygonView(dbTx database.Tx, view *PolygonViewpoint) error {
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

	size := bccompress.SerializeSizeVLQ(uint64(len(entry.Loops)))
	for _, l := range entry.Loops {
		size += bccompress.SerializeSizeVLQ(uint64(len(l))) + len(l) * chainhash.HashSize
	}

	var serialized = make([]byte, size)

	bccompress.PutVLQ(serialized[:], uint64(len(entry.Loops)))
	p := bccompress.SerializeSizeVLQ(uint64(len(entry.Loops)))
	for _, l := range entry.Loops {
		bccompress.PutVLQ(serialized[p:], uint64(len(l)))
		p += bccompress.SerializeSizeVLQ(uint64(len(l)))
		for _,t := range l {
			copy(serialized[p:], t[:])
			p +=  chainhash.HashSize
		}
	}

	return serialized, nil
}

func DbFetchPolygon(dbTx database.Tx, hash *chainhash.Hash) (*PolygonEntry, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(polygonSetBucketName)
	serialized := hashIndex.Get(hash[:])

	if serialized == nil {
		str := fmt.Sprintf("polygon %s does not exist in the main chain", hash)
		return nil, bccompress.ErrNotInMainChain(str)
	}

	b := PolygonEntry {}

	loops, pos := bccompress.DeserializeVLQ(serialized)

	b.Loops = make([]token.LoopDef, loops)

	for i := uint64(0);  i < loops; i++ {
		bds, offset := bccompress.DeserializeVLQ(serialized[pos:])
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