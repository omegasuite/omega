// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
//	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
//	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// BorderEntry houses details about an individual Border definition in a definition
// view.
type BorderEntry struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.

	father chainhash.Hash
	begin chainhash.Hash
	end chainhash.Hash
	children []chainhash.Hash

	// packedFlags contains additional info about vertex. Currently unused.
	packedFlags txoFlags
}

func (entry * BorderEntry) Father() chainhash.Hash {
	return entry.father
}

func (entry * BorderEntry) Begin() chainhash.Hash {
	return entry.begin
}

func (entry * BorderEntry) End() chainhash.Hash {
	return entry.end
}

func (entry * BorderEntry) Children() [] chainhash.Hash {
	return entry.children
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry * BorderEntry) isModified() bool {
	return entry.packedFlags & tfModified == tfModified
}

func (entry * BorderEntry) toDelete() bool {
	return entry.packedFlags & tfSpent == tfSpent
}

// Clone returns a shallow copy of the vertex entry.
func (entry * BorderEntry) Clone() *BorderEntry {
	if entry == nil {
		return nil
	}

	return &BorderEntry{
		father:   entry.father,
		begin:    entry.begin,
		end:	  entry.end,
		children: entry.children,
		packedFlags: entry.packedFlags,
	}
}

// VtxViewpoint represents a view into the set of vertex definition
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.

type BorderViewpoint struct {
	entries  map[chainhash.Hash]*BorderEntry
	bestHash chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view * BorderViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view * BorderViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// LookupEntry returns information about a given vertex according to
// the current state of the view.  It will return nil if the passed vertex does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
func (view * BorderViewpoint) LookupEntry(p chainhash.Hash) * BorderEntry {
	return view.entries[p]
}

// addBorder adds the specified vertex to the view.
func (view * BorderViewpoint) addBorder(b *wire.BorderDef) {
	h := b.Hash()
	entry := view.LookupEntry(h)
	f := b.Father

	if entry == nil {
		entry = new(BorderEntry)
		entry.father = f
		entry.begin = b.Begin
		entry.end = b.End
		entry.packedFlags = tfModified
		entry.children = make([]chainhash.Hash, 0)
		view.entries[h] = entry
	}

	if f.IsEqual(&chainhash.Hash{}) {
		return
	}

	entry = view.LookupEntry(f)
	if entry == nil {
		entry = new(BorderEntry)
		entry.children = make([]chainhash.Hash, 0)
		view.entries[f] = entry
	}
	entry.children = append(entry.children, b.Hash())

	entry.packedFlags = tfModified
}

// AddVertices adds all vertex definitions in the passed transaction to the view.
func (view * BorderViewpoint) AddBorder(tx *btcutil.Tx) {
	// Loop all of the vertex definitions

	for _, txVtx := range tx.MsgTx().TxDef {
		switch txVtx.(type) {
			case *wire.BorderDef:
				view.addBorder(txVtx.(*wire.BorderDef))
			break
		}
	}
}

// connectTransactions updates the view by adding all new vertices created by all
// of the transactions in the passed block, and setting the best hash for the view
// to the passed block.
func (view * BorderViewpoint) connectTransactions(block *btcutil.Block) error {
	for _, tx := range block.Transactions() {
		view.AddBorder(tx)
	}

	// Update the best hash for view to include this block since all of its
	// transactions have been connected.
	view.SetBestHash(block.Hash())
	return nil
}

// fetchEntry attempts to find any vertex for the given hash by
// searching the entire view.  It checks the view first and then falls
// back to the database if needed.
func (view * BorderViewpoint) fetchEntry(db database.DB, hash *chainhash.Hash) (*BorderEntry, error) {
	// First attempt to find a utxo with the provided hash in the view.
	entry := view.LookupEntry(*hash)
	if entry != nil {
		return entry, nil
	}

	// Check the database since it doesn't exist in the view.  This will
	// often by the case since only specifically referenced vertex are loaded
	// into the view.
	err := db.View(func(dbTx database.Tx) error {
		e, err := dbFetchBorderEntry(dbTx, hash)
		entry = e
		return  err
	})
	if err != nil {
		return nil, err
	}
	view.entries[*hash] = entry
	return entry, nil
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (entry *BorderEntry) RollBack() {
	// Nothing to do if the output is already spent.
	if entry.toDelete() {
		return
	}

	// Mark the output as spent and modified.
	entry.packedFlags |= tfSpent | tfModified
}

// disconnectTransactions updates the view by removing all of the transactions
// created by the passed block, removing all vertices defined in the transactions,
// and setting the best hash for the view to the block before the passed block.
func (view * BorderViewpoint) disconnectTransactions(db database.DB, block *btcutil.Block) error {
	for _,tx := range block.Transactions() {
		for _, txDef := range tx.MsgTx().TxDef {
			switch txDef.(type) {
			case *wire.BorderDef:
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
func (view * BorderViewpoint) RemoveEntry(hash chainhash.Hash) {
	delete(view.entries, hash)
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view * BorderViewpoint) Entries() map[chainhash.Hash]*BorderEntry {
	return view.entries
}

// commit. this is to be called after data has been committed to db
func (view * BorderViewpoint) commit() {
	for outpoint, entry := range view.entries {
		if entry == nil || ((entry.packedFlags & tfSpent) == tfSpent) {
			delete(view.entries, outpoint)
			continue
		}

		entry.packedFlags ^= tfModified
	}
}

// fetchVertexMain fetches vertex data about the provided
// set of vertices from the point of view of the end of the main chain at the
// time of the call.
//
// Upon completion of this function, the view will contain an entry for each
// requested vertices.
func (view * BorderViewpoint) fetchBorderMain(db database.DB, b map[chainhash.Hash]struct{}) error {
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
			e, err := dbFetchBorderEntry(dbTx, &vtx)
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
func (view * BorderViewpoint) fetchBorder(db database.DB, b map[chainhash.Hash]struct{}) error {
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
	return view.fetchBorderMain(db, neededSet)
}

// NewVtxViewpoint returns a new empty vertex view.
func NewBorderViewpoint() * BorderViewpoint {
	return &BorderViewpoint{
		entries: make(map[chainhash.Hash]*BorderEntry),
	}
}

// FetchVtxEntry loads and returns the requested vertex definition
// from the point of view of the end of the main chain.
//
// NOTE: Requesting an definition for which there is no data will NOT return an
// error.  Instead both the entry and the error will be nil. In practice this means the
// caller must check if the returned entry is nil before invoking methods on it.
//
// This function is safe for concurrent access however the returned entry (if
// any) is NOT.
func (b *BlockChain) FetchBorderEntry(hash chainhash.Hash) (*BorderEntry, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	var entry *BorderEntry
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		e, err := dbFetchBorderEntry(dbTx, &hash)
		entry = e
		return err
	})
	if err != nil {
		return nil, err
	}

	return entry, nil
}
