// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

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
type VtxEntry struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.

	Lat uint32
	Lng uint32
	desc []byte

	// packedFlags contains additional info about vertex. Currently unused.
	packedFlags txoFlags
}

func (entry *VtxEntry)  Desc() []byte {
	return entry.desc;
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry *VtxEntry) isModified() bool {
	return entry.packedFlags & TfModified == TfModified
}

func (entry *VtxEntry) toDelete() bool {
	return entry.packedFlags & TfSpent == TfSpent
}

// Clone returns a shallow copy of the vertex entry.
func (entry *VtxEntry) Clone() *VtxEntry {
	if entry == nil {
		return nil
	}

	return &VtxEntry{
		Lat:      entry.Lat,
		Lng:	  entry.Lng,
		desc:	  entry.desc,
		packedFlags: entry.packedFlags,
	}
}

// VtxViewpoint represents a view into the set of vertex definition
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.

type VtxViewpoint struct {
	entries  map[chainhash.Hash]*VtxEntry
	bestHash chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view *VtxViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view *VtxViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// LookupEntry returns information about a given vertex according to
// the current state of the view.  It will return nil if the passed vertex does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
func (view *VtxViewpoint) LookupEntry(p chainhash.Hash) *VtxEntry {
	return view.entries[p]
}

// addVertex adds the specified vertex to the view.
func (view *VtxViewpoint) addVertex(vertex *token.VertexDef) {
	h := vertex.Hash()
	entry := view.LookupEntry(h)
	if entry == nil {
		entry = new(VtxEntry)
		view.entries[h] = entry
		entry.Lat = vertex.Lat
		entry.Lng = vertex.Lng
		entry.desc = make([]byte, len(vertex.Desc))
		copy(entry.desc[:], vertex.Desc[:])
		entry.packedFlags = TfModified
	}
}

// addVertex adds the specified vertex to the view.
func (view *VtxViewpoint) AddOneVertex(vertex *token.VertexDef) {
	view.addVertex(vertex)
}
// AddVertices adds all vertex definitions in the passed transaction to the view.
func (view *VtxViewpoint) AddVertices(tx *btcutil.Tx) {
	// Loop all of the vertex definitions

	for _, txVtx := range tx.MsgTx().TxDef {
		switch txVtx.(type) {
			case *token.VertexDef:
				view.addVertex(txVtx.(*token.VertexDef))
			break
		}
	}
}

// fetchEntry attempts to find any vertex for the given hash by
// searching the entire view.  It checks the view first and then falls
// back to the database if needed.
func (view *VtxViewpoint) FetchEntry(db database.DB, hash *chainhash.Hash) (*VtxEntry, error) {
	// First attempt to find a utxo with the provided hash in the view.
	entry := view.LookupEntry(*hash)
	if entry != nil {
		return entry, nil
	}

	// Check the database since it doesn't exist in the view.  This will
	// often by the case since only specifically referenced vertex are loaded
	// into the view.
	err := db.View(func(dbTx database.Tx) error {
		e, err := DbFetchVertexEntry(dbTx, hash)
		view.entries[*hash] = e
		entry = e
		return  err
	})
	return entry, err
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (entry *VtxEntry) RollBack() {
	// Nothing to do if the output is already spent.
	if entry.toDelete() {
		return
	}

	// Mark the output as spent and modified.
	entry.packedFlags |= TfSpent | TfModified
}

// disconnectTransactions updates the view by removing all of the transactions
// created by the passed block, removing all vertices defined in the transactions,
// and setting the best hash for the view to the block before the passed block.
func (view *VtxViewpoint) disconnectTransactions(db database.DB, block *btcutil.Block) error {
	for _,tx := range block.Transactions() {
		for _, txDef := range tx.MsgTx().TxDef {
			switch txDef.(type) {
			case *token.VertexDef:
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
func (view *VtxViewpoint) RemoveEntry(hash chainhash.Hash) {
	delete(view.entries, hash)
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view *VtxViewpoint) Entries() map[chainhash.Hash]*VtxEntry {
	return view.entries
}

// commit. this is to be called after data has been committed to db
func (view *VtxViewpoint) commit() {
	for outpoint, entry := range view.entries {
		if entry == nil || ((entry.packedFlags & TfSpent) == TfSpent) {
			delete(view.entries, outpoint)
			continue
		}

		entry.packedFlags ^= TfModified
	}
}

// fetchVertexMain fetches vertex data about the provided
// set of vertices from the point of view of the end of the main chain at the
// time of the call.
//
// Upon completion of this function, the view will contain an entry for each
// requested vertices.
func (view *VtxViewpoint) fetchVertexMain(db database.DB, vertices map[chainhash.Hash]struct{}) error {
	// Nothing to do if there are no requested outputs.
	if len(vertices) == 0 {
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
		for vtx,_ := range vertices {
			e, err := DbFetchVertexEntry(dbTx, &vtx)
			if err != nil {
				return err
			}

			view.entries[vtx] = e
		}

		return nil
	})
}

// fetchVertex loads the vertices for the provided set into the view
// from the database as needed unless they already exist
// in the view in which case they are ignored.
func (view *VtxViewpoint) FetchVertex(db database.DB, vertices map[chainhash.Hash]struct{}) error {
	// Nothing to do if there are no requested vertices.
	if len(vertices) == 0 {
		return nil
	}

	// Filter entries that are already in the view.
	neededSet := make(map[chainhash.Hash]struct{})
	for vtx := range vertices {
		// Already loaded into the current view.
		if _, ok := view.entries[vtx]; ok {
			continue
		}

		neededSet[vtx] = struct{}{}
	}

	// Request the input utxos from the database.
	return view.fetchVertexMain(db, neededSet)
}

// NewVtxViewpoint returns a new empty vertex view.
func NewVtxViewpoint() *VtxViewpoint {
	return &VtxViewpoint{
		entries: make(map[chainhash.Hash]*VtxEntry),
	}
}


// dbPutVtxView uses an existing database transaction to update the vertex set
// in the database based on the provided vertex view contents and state. In
// particular, only the entries that have been marked as modified (meaning new)
// and not spent (meaning not to be deleted) are written to the database.

func DbPutVtxView(dbTx database.Tx, view *VtxViewpoint) error {
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

	byteOrder.PutUint32(serialized[:], entry.Lat)
	byteOrder.PutUint32(serialized[4:], entry.Lng)
	copy(serialized[8:], entry.desc[:])

	return serialized, nil
}

func DbFetchVertexEntry(dbTx database.Tx, hash *chainhash.Hash) (*VtxEntry, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(vertexSetBucketName)
	serialized := hashIndex.Get(hash[:])
	if serialized == nil {
		str := fmt.Sprintf("vertex %s does not exist in the main chain", hash)
		return nil, bccompress.ErrNotInMainChain(str)
	}

	vtx := VtxEntry { }
	vtx.Lat = byteOrder.Uint32(serialized[:])
	vtx.Lng = byteOrder.Uint32(serialized[4:])
	vtx.desc = make([]byte, len(serialized) - 8)
	copy(vtx.desc[:], serialized[8:])

	return &vtx, nil
}

func dbRemoveVertex(dbTx database.Tx, hash *chainhash.Hash) error {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(vertexSetBucketName)
	return hashIndex.Delete(hash[:])
}
