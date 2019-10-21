// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package viewpoint

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	//	"github.com/btcsuite/btcd/txscript"
	//	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
	"fmt"
	"encoding/binary"
)

type BoundingBox struct {
	east int32
	west int32
	south int32
	north int32
}

// BorderEntry houses details about an individual Border definition in a definition
// view.
type BorderEntry struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.

	Father chainhash.Hash
	Begin chainhash.Hash
	End chainhash.Hash
	Children []chainhash.Hash
	Bound * BoundingBox

	// packedFlags contains additional info about vertex. Currently unused.
	PackedFlags txoFlags
}

func (b *BorderEntry) Lat(view * ViewPointSet, rev bool) int32 {
	var p * VtxEntry
	if rev {
		p,_ = view.Vertex.FetchEntry(view.Db, &b.End)
	} else {
		p,_ = view.Vertex.FetchEntry(view.Db, &b.Begin)
	}
	return int32(p.Lat)
}

func (b *BorderEntry) Lng(view * ViewPointSet, rev bool) int32 {
	var p * VtxEntry
	if rev {
		p,_ = view.Vertex.FetchEntry(view.Db, &b.End)
	} else {
		p,_ = view.Vertex.FetchEntry(view.Db, &b.Begin)
	}
	return int32(p.Lng)
}

func (b *BorderEntry) East(view * ViewPointSet) int32 {
	if b.Bound != nil {
		return b.Bound.east
	}
	bg,_ := view.Vertex.FetchEntry(view.Db, &b.Begin)
	ed,_ := view.Vertex.FetchEntry(view.Db, &b.End)
	if int32(bg.Lng) > int32(ed.Lng) {
		return int32(bg.Lng)
	}
	return int32(ed.Lng)
}

func (b *BorderEntry) West(view * ViewPointSet) int32 {
	if b.Bound != nil {
		return b.Bound.west
	}
	bg,_ := view.Vertex.FetchEntry(view.Db, &b.Begin)
	ed,_ := view.Vertex.FetchEntry(view.Db, &b.End)
	if int32(bg.Lng) < int32(ed.Lng) {
		return int32(bg.Lng)
	}
	return int32(ed.Lng)
}


func (b *BorderEntry) South(view * ViewPointSet) int32 {
	if b.Bound != nil {
		return b.Bound.south
	}
	bg,_ := view.Vertex.FetchEntry(view.Db, &b.Begin)
	ed,_ := view.Vertex.FetchEntry(view.Db, &b.End)
	if int32(bg.Lat) > int32(ed.Lat) {
		return int32(bg.Lat)
	}
	return int32(ed.Lat)
}

func (b *BorderEntry) North(view * ViewPointSet) int32 {
	if b.Bound != nil {
		return b.Bound.north
	}
	bg,_ := view.Vertex.FetchEntry(view.Db, &b.Begin)
	ed,_ := view.Vertex.FetchEntry(view.Db, &b.End)
	if int32(bg.Lat) < int32(ed.Lat) {
		return int32(bg.Lat)
	}
	return int32(ed.Lat)
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry * BorderEntry) isModified() bool {
	return entry.PackedFlags & TfModified == TfModified
}

func (entry * BorderEntry) toDelete() bool {
	return entry.PackedFlags & TfSpent == TfSpent
}

// Clone returns a shallow copy of the vertex entry.
func (entry * BorderEntry) Clone() *BorderEntry {
	if entry == nil {
		return nil
	}

	return &BorderEntry{
		Father:   entry.Father,
		Begin:    entry.Begin,
		End:	  entry.End,
		Children: entry.Children,
		Bound: entry.Bound,
		PackedFlags: entry.PackedFlags,
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
	q := chainhash.Hash{}
	q.SetBytes(p.CloneBytes())
	q[0] &= 0xFE
	return view.entries[q]
}

// addBorder adds the specified vertex to the view.
func (view * ViewPointSet) addBorder(b *token.BorderDef) bool {
	h := b.Hash()
	entry := view.Border.LookupEntry(h)
	f := b.Father

	if entry == nil {
		entry = new(BorderEntry)
		entry.Father = f
		entry.Begin = b.Begin
		entry.End = b.End
		entry.PackedFlags = TfModified
		entry.Children = make([]chainhash.Hash, 0)
		view.Border.entries[h] = entry

		bg,_ := view.Vertex.FetchEntry(view.Db, &b.Begin)
		ed,_ := view.Vertex.FetchEntry(view.Db, &b.End)

		var east, west, south, north int32

		if int32(bg.Lng) < int32(ed.Lng) {
			west = int32(bg.Lng)
			east = int32(ed.Lng)
		} else {
			east = int32(bg.Lng)
			west = int32(ed.Lng)
		}
		if int32(bg.Lat) < int32(ed.Lat) {
			south = int32(bg.Lat)
			north = int32(ed.Lat)
		} else {
			north  = int32(bg.Lat)
			south = int32(ed.Lat)
		}

		for !f.IsEqual(&chainhash.Hash{}) {
			view.Border.FetchEntry(view.Db, &f)
			fe := view.Border.LookupEntry(f)
			if fe == nil {
				delete(view.Border.entries, h)
				return false
			}
			if east <= fe.East(view) && west >= fe.West(view) &&
				south >= fe.South(view) && north <= fe.North(view) {
					return true
			} else {
				if fe.Bound == nil {
					fe.Bound = &BoundingBox{
						east: fe.East(view), west: fe.West(view),south: fe.South(view),north: fe.North(view),
					}
				}
				if east > fe.East(view) {
					fe.Bound.east = east
				}
				if west < fe.West(view) {
					fe.Bound.west = west
				}
				if north > fe.North(view) {
					fe.Bound.north = north
				}
				if south < fe.South(view) {
					fe.Bound.south = south
				}
				fe.PackedFlags |= TfModified
				east, west, south, north = fe.Bound.east,fe.Bound.west,fe.Bound.south,fe.Bound.north
				f = fe.Father
			}
		}
		return true
	}
	return false
	/*

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
	*/
}

func (view * ViewPointSet) AddOneBorder(b *token.BorderDef) bool {
	return view.addBorder(b)
}

// AddVertices adds all vertex definitions in the passed transaction to the view.
func (view * ViewPointSet) AddBorder(tx *btcutil.Tx) bool {
	// Loop all of the vertex definitions
	for _, txVtx := range tx.MsgTx().TxDef {
		switch txVtx.(type) {
		case *token.BorderDef:
			if !view.addBorder(txVtx.(*token.BorderDef)) {
				return false
			}
			break
		}
	}
	return true
}

// fetchEntry attempts to find any vertex for the given hash by
// searching the entire view.  It checks the view first and then falls
// back to the database if needed.
func (view * BorderViewpoint) FetchEntry(db database.DB, hash *chainhash.Hash) (*BorderEntry, error) {
	h := chainhash.Hash{}
	h.SetBytes(hash.CloneBytes())
	h[0] &= 0xFE

	// First attempt to find a utxo with the provided hash in the view.
	entry := view.LookupEntry(*hash)
	if entry != nil {
		return entry, nil
	}

	// Check the database since it doesn't exist in the view.  This will
	// often by the case since only specifically referenced vertex are loaded
	// into the view.
	err := db.View(func(dbTx database.Tx) error {
		e, err := DbFetchBorderEntry(dbTx, hash)
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
	entry.PackedFlags |= TfSpent | TfModified
}

// disconnectTransactions updates the view by removing all of the transactions
// created by the passed block, removing all vertices defined in the transactions,
// and setting the best hash for the view to the block before the passed block.
func (view * BorderViewpoint) disconnectTransactions(db database.DB, block *btcutil.Block) error {
	for _,tx := range block.Transactions() {
		for _, txDef := range tx.MsgTx().TxDef {
			switch txDef.(type) {
			case *token.BorderDef:
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
			e, err := DbFetchBorderEntry(dbTx, &vtx)
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
func (view * BorderViewpoint) FetchBorder(db database.DB, b map[chainhash.Hash]struct{}) error {
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


// dbPutVtxView uses an existing database transaction to update the vertex set
// in the database based on the provided utxo view contents and state. In
// particular, only the entries that have been marked as modified (meaning new)
// and not spent (meaning not to be deleted) are written to the database.
func DbPutBorderView(dbTx database.Tx, view *BorderViewpoint) error {
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

	s := chainhash.HashSize * (3 + len(entry.Children))
	p := s
	if entry.Bound != nil {
		s += 16
	}

	var serialized = make([]byte, s)
	copy(serialized[:], entry.Father[:])
	copy(serialized[chainhash.HashSize:], entry.Begin[:])
	copy(serialized[chainhash.HashSize * 2:], entry.End[:])

	pos := chainhash.HashSize * 3
	for _,v := range entry.Children {
		copy(serialized[pos:], v[:])
		pos += chainhash.HashSize
	}

	if entry.Bound != nil {
		binary.LittleEndian.PutUint32(serialized[p:], uint32(entry.Bound.west))
		binary.LittleEndian.PutUint32(serialized[p + 4:], uint32(entry.Bound.east))
		binary.LittleEndian.PutUint32(serialized[p + 8:], uint32(entry.Bound.south))
		binary.LittleEndian.PutUint32(serialized[p + 12:], uint32(entry.Bound.north))
	}

	return serialized, nil
}

func DbFetchBorderEntry(dbTx database.Tx, hash *chainhash.Hash) (*BorderEntry, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(borderSetBucketName)
	serialized := hashIndex.Get(hash[:])

	if serialized == nil {
		str := fmt.Sprintf("border %s does not exist in the main chain", hash)
		return nil, ViewPointError(str)
	}

	b := BorderEntry{}

	copy(b.Father[:], serialized[:chainhash.HashSize])
	copy(b.Begin[:], serialized[chainhash.HashSize:chainhash.HashSize * 2])
	copy(b.End[:], serialized[chainhash.HashSize * 2:chainhash.HashSize * 3])
	b.Children = make([]chainhash.Hash, (len(serialized) - 3 * chainhash.HashSize) / chainhash.HashSize)

	for i := 0; i < len(b.Children); i ++ {
		copy(b.Children[i][:], serialized[(i + 3) * chainhash.HashSize:])
	}

	p := chainhash.HashSize * (len(b.Children) + 3)
	if len(serialized) == p {
		return &b, nil
	}

	b.Bound = &BoundingBox{}
	b.Bound.west = int32(binary.LittleEndian.Uint32(serialized[p:]))
	b.Bound.east = int32(binary.LittleEndian.Uint32(serialized[p + 4:]))
	b.Bound.south = int32(binary.LittleEndian.Uint32(serialized[p + 8:]))
	b.Bound.north = int32(binary.LittleEndian.Uint32(serialized[p + 12:]))

	return &b, nil
}

func dbRemoveBorder(dbTx database.Tx, hash *chainhash.Hash) error {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(borderSetBucketName)

	// remove border itself
	return hashIndex.Delete(hash[:])
}
