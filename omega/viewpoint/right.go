/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package viewpoint

import (
	"fmt"

	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	//	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega"
	"github.com/omegasuite/omega/token"
)

type RightEntry struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.

	Father chainhash.Hash
	Root   chainhash.Hash
	Depth  int32
	Desc   []byte
	Attrib uint8

	// packedFlags contains additional info about vertex. Currently unused.
	PackedFlags txoFlags
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry *RightEntry) isModified() bool {
	return entry.PackedFlags&TfModified == TfModified
}

func (entry *RightEntry) toDelete() bool {
	return entry.PackedFlags&TfSpent == TfSpent
}

func (entry *RightEntry) ToToken() *token.RightDef {
	t := token.RightDef{
		Father: entry.Father,
		Attrib: entry.Attrib,
		Desc:   entry.Desc,
	}
	return &t
}

func (entry *RightEntry) toRightSet() *token.RightSetDef {
	t := token.RightSetDef{
		Rights: make([]chainhash.Hash, 1),
	}
	t.Rights[0] = entry.ToToken().Hash()

	return &t
}

func (entry *RightEntry) Sibling() chainhash.Hash {
	s := entry.ToToken()
	if s.Attrib&(token.Monitor|token.Monitored) == 0 {
		s.Attrib &^= token.NegativeRight
	} else if s.Attrib&token.IsMonitorCall != 0 {
		if (s.Attrib & token.Monitor) != 0 {
			s.Attrib &^= token.Monitor
			s.Attrib |= token.Monitored | token.NegativeRight
		} else {
			s.Attrib &^= token.Monitored | token.NegativeRight
			s.Attrib |= token.Monitor
		}
	} else {
		s.Attrib &^= token.NegativeRight
	}

	return s.Hash()
}

func (entry *RightEntry) Monitoring() chainhash.Hash {
	s := entry.ToToken()
	if s.Attrib&token.Monitored == 0 || s.Attrib&token.IsMonitorCall == 0 {
		return chainhash.Hash{}
	}

	s.Attrib |= token.Monitor
	s.Attrib &^= token.NegativeRight | token.Monitored

	return s.Hash()
}

// Clone returns a shallow copy of the vertex entry.
func (entry *RightEntry) Clone() *RightEntry {
	if entry == nil {
		return nil
	}

	return &RightEntry{
		Father:      entry.Father,
		Desc:        entry.Desc,
		Attrib:      entry.Attrib,
		Root:        entry.Root,
		Depth:       entry.Depth,
		PackedFlags: entry.PackedFlags,
	}
}

type RightSetEntry struct {
	Rights []chainhash.Hash

	// packedFlags contains additional info about vertex. Currently unused.
	PackedFlags txoFlags
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry *RightSetEntry) isModified() bool {
	return entry.PackedFlags&TfModified == TfModified
}

func (entry *RightSetEntry) toDelete() bool {
	return entry.PackedFlags&TfSpent == TfSpent
}

func (entry *RightSetEntry) ToToken() *token.RightSetDef {
	t := token.RightSetDef{
		Rights: make([]chainhash.Hash, len(entry.Rights)),
	}
	for i, r := range entry.Rights {
		copy(t.Rights[i][:], r[:])
	}
	return &t
}

func (entry *RightSetEntry) toRightSet() *token.RightSetDef {
	t := token.RightSetDef{
		Rights: make([]chainhash.Hash, len(entry.Rights)),
	}
	for i, r := range entry.Rights {
		copy(t.Rights[i][:], r[:])
	}
	return &t
}

// Clone returns a shallow copy of the vertex entry.
func (entry *RightSetEntry) Clone() *RightSetEntry {
	if entry == nil {
		return nil
	}

	return &RightSetEntry{
		Rights:      entry.Rights,
		PackedFlags: entry.PackedFlags,
	}
}

func (entry *RightSetEntry) RollBack() {
	// Nothing to do if the output is already spent.
	if entry.toDelete() {
		return
	}

	// Mark the output as spent and modified.
	entry.PackedFlags |= TfSpent | TfModified
}

func SetOfRights(view *ViewPointSet, r interface{}) []*RightEntry {
	if r == nil {
		return nil
	}
	switch r.(type) {
	case *RightEntry:
		return []*RightEntry{r.(*RightEntry)}
	case *RightSetEntry:
		rs := make([]*RightEntry, 0, len(r.(*RightSetEntry).Rights))
		for _, r := range r.(*RightSetEntry).Rights {
			p, _ := view.FetchRightEntry(&r)
			if p != nil {
				rs = append(rs, p.(*RightEntry))
			}
		}
		return rs
	}
	return nil
}

func InSet(view *ViewPointSet, r chainhash.Hash, s *chainhash.Hash) bool {
	if s == nil {
		return false
	}
	p, _ := view.FetchRightEntry(s)
	if p == nil {
		return false
	}
	switch p.(type) {
	case *RightEntry:
		h := p.(*RightEntry).ToToken().Hash()
		return h.IsEqual(&r)
	case *RightSetEntry:
		for _, t := range p.(*RightSetEntry).Rights {
			if t.IsEqual(&r) {
				return true
			}
		}
	}
	return false
}

// VtxViewpoint represents a view into the set of vertex definition
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.

type RightViewpoint struct {
	entries  map[chainhash.Hash]interface{}
	bestHash chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view *RightViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view *RightViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// LookupEntry returns information about a given vertex according to
// the current state of the view.  It will return nil if the passed vertex does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
func (view *RightViewpoint) LookupRightEntry(p chainhash.Hash) *RightEntry {
	r, ok := view.entries[p]
	if !ok {
		return nil
	}
	switch r.(type) {
	case *RightEntry:
		return r.(*RightEntry)
	}
	return nil
}

func (view *RightViewpoint) LookupRightSetEntry(p chainhash.Hash) *RightSetEntry {
	r := view.entries[p]
	switch r.(type) {
	case *RightSetEntry:
		return r.(*RightSetEntry)
	}
	return nil
}

func (view *RightViewpoint) LookupEntry(p chainhash.Hash) interface{} {
	return view.entries[p]
}

func isContract(netid byte) bool {
	return netid&64 == 64
}

func (view *ViewPointSet) contractExists(contract []byte) bool {
	err := view.Db.View(func(dbTx database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("storage" + string(contract[:])))

		if bucket == nil {
			return omega.ScriptError(omega.ErrInternal, "Bucket not exist.")
		}

		return nil
	})
	return err == nil
}

// addRight adds the specified right to the view.
func (view *ViewPointSet) AddRight(b *token.RightDef) bool {
	h := b.Hash()
	entry := view.Rights.LookupRightEntry(h)
	if entry == nil {
		if b.Attrib&(token.Monitored|token.Monitor) == (token.Monitored | token.Monitor) {
			// can't be both side, but can be neither
			return false
		}

		if b.Attrib&(token.Monitored|token.Monitor|token.IsMonitorCall) == token.IsMonitorCall {
			// can't be both side, but can be neither
			return false
		}

		if b.Attrib&(token.Monitor|token.Unsplittable) == token.Monitor {
			// a monitor right must not be splittable
			return false
		}

		if b.Attrib&token.IsMonitorCall != 0 && (len(b.Desc) < 25 ||
			!isContract(b.Desc[0]) || !view.contractExists(b.Desc[1:21])) {
			// right description must be a contract call. check whether the contract exists
			return false
		}

		entry = new(RightEntry)
		entry.Father = b.Father
		entry.Desc = b.Desc
		entry.Attrib = b.Attrib
		entry.PackedFlags = TfModified

		if b.Father.IsEqual(&chainhash.Hash{}) {
			entry.Depth = 0
			entry.Root = h
		} else {
			f, _ := view.FetchRightEntry(&b.Father)
			if f == nil {
				return false
			}
			if f.(*RightEntry).Attrib&token.Unsplittable != 0 {
				return false
			}
			if f.(*RightEntry).Attrib&token.Monitor != 0 && b.Attrib&token.Monitor == 0 {
				return false
			}

			entry.Root = f.(*RightEntry).Root
			entry.Depth = f.(*RightEntry).Depth + 1
		}

		view.Rights.entries[h] = entry

		return true
	}
	return true
}

// addVertex adds the specified right to the view.
func (view *RightViewpoint) AddRightSet(b *token.RightSetDef) bool {
	h := b.Hash()
	entry := view.LookupRightSetEntry(h)
	if entry == nil {
		entry = new(RightSetEntry)
		entry.Rights = make([]chainhash.Hash, len(b.Rights))

		for i, r := range b.Rights {
			copy(entry.Rights[i][:], r[:])
		}

		entry.PackedFlags = TfModified

		view.entries[h] = entry

		return true
	}
	return true
}

// AddVertices adds all vertex definitions in the passed transaction to the view.
func (view *ViewPointSet) AddRights(tx *btcutil.Tx) bool {
	// Loop all of the vertex definitions

	for _, txVtx := range tx.MsgTx().TxDef {
		if txVtx.IsSeparator() {
			continue
		}
		switch txVtx.(type) {
		case *token.RightDef:
			if !view.AddRight(txVtx.(*token.RightDef)) {
				return false
			}
			break
		case *token.RightSetDef:
			view.Rights.AddRightSet(txVtx.(*token.RightSetDef))
			break
		}
	}
	return true
}

func (views *ViewPointSet) TokenRights(x *UtxoEntry) []chainhash.Hash {
	//	hasneg := []chainhash.Hash{{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	//		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,},}

	var tokenType uint64
	var rs *chainhash.Hash

	tokenType = x.TokenType
	rs = x.Rights

	if rs == nil || rs.IsEqual(&chainhash.Hash{}) {
		return []chainhash.Hash{}
	}

	var y []chainhash.Hash
	if tokenType&2 == 0 {
		return []chainhash.Hash{}
	} else {
		t, _ := views.FetchRightEntry(rs)
		if yy := SetOfRights(views, t); yy != nil {
			y := make([]chainhash.Hash, 0, len(yy))
			for _, r := range yy {
				y = append(y, r.ToToken().Hash())
			}
		}
	}
	return y
}

// fetchEntry attempts to find any vertex for the given hash by
// searching the entire view.  It checks the view first and then falls
// back to the database if needed.
func (view *ViewPointSet) FetchRightEntry(hash *chainhash.Hash) (interface{}, error) {
	// First attempt to find a utxo with the provided hash in the view.
	entry := view.Rights.LookupEntry(*hash)
	if entry != nil {
		return entry, nil
	}

	// Check the database since it doesn't exist in the view.  This will
	// often by the case since only specifically referenced vertex are loaded
	// into the view.
	err := view.Db.View(func(dbTx database.Tx) error {
		e, err := DbFetchRight(dbTx, hash)
		if e != nil {
			view.Rights.entries[*hash] = e
			entry = e
		}
		return err
	})
	return entry, err
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (entry *RightEntry) RollBack() {
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
func (view *ViewPointSet) disconnectRightTransactions(block *btcutil.Block) error {
	for _, tx := range block.Transactions() {
		for _, txDef := range tx.MsgTx().TxDef {
			if txDef.IsSeparator() {
				continue
			}
			switch txDef.(type) {
			case *token.RightDef:
				h := txDef.Hash()
				p := view.Rights.LookupEntry(h)
				if p == nil {
					p, _ = view.FetchRightEntry(&h)
				}
				if p != nil {
					p.(*RightEntry).RollBack()
				}

			case *token.RightSetDef:
				h := txDef.Hash()
				p := view.Rights.LookupEntry(h)
				if p == nil {
					p, _ = view.FetchRightEntry(&h)
				}
				if p != nil {
					p.(*RightSetEntry).RollBack()
				}
			}
		}
	}

	// Update the best hash for view to the previous block since all of the
	// transactions for the current block have been disconnected.
	view.Rights.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return nil
}

// RemoveEntry removes the given transaction output from the current state of
// the view.  It will have no effect if the passed output does not exist in the
// view.
func (view *RightViewpoint) RemoveEntry(hash chainhash.Hash) {
	delete(view.entries, hash)
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view *RightViewpoint) Entries() map[chainhash.Hash]interface{} {
	return view.entries
}

// commit. this is to be called after data has been committed to db
func (view *RightViewpoint) commit() {
	for outpoint, entry := range view.entries {
		switch entry.(type) {
		case *RightEntry:
			if entry.(*RightEntry) == nil || ((entry.(*RightEntry).PackedFlags & TfSpent) == TfSpent) {
				delete(view.entries, outpoint)
				continue
			}
			entry.(*RightEntry).PackedFlags &^= TfModified

		case *RightSetEntry:
			if entry.(*RightSetEntry) == nil || ((entry.(*RightSetEntry).PackedFlags & TfSpent) == TfSpent) {
				delete(view.entries, outpoint)
				continue
			}
			entry.(*RightSetEntry).PackedFlags &^= TfModified
		}

	}
}

// fetchVertexMain fetches vertex data about the provided
// set of vertices from the point of view of the end of the main chain at the
// time of the call.
//
// Upon completion of this function, the view will contain an entry for each
// requested vertices.
func (view *RightViewpoint) fetchRightMain(db database.DB, b map[chainhash.Hash]struct{}) error {
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
		for vtx, _ := range b {
			e, err := DbFetchRight(dbTx, &vtx)

			if e == nil || err != nil {
				return err
			}

			switch e.(type) {
			case *RightEntry:
				e.(*RightEntry).PackedFlags = 0
				view.entries[vtx] = e.(*RightEntry)
			case *RightSetEntry:
				e.(*RightSetEntry).PackedFlags = 0
				view.entries[vtx] = e.(*RightSetEntry)
			}
		}

		return nil
	})
}

func (view *RightViewpoint) GetRight(db database.DB, hash chainhash.Hash) interface{} {
	if hash.IsEqual(&zerohash) {
		return nil
	}
	e := view.LookupRightEntry(hash)
	if e != nil {
		return e
	} else {
		e := view.LookupRightSetEntry(hash)
		if e != nil {
			return e
		}
	}
	view.FetchRight(db, map[chainhash.Hash]struct{}{hash: {}})
	e = view.LookupRightEntry(hash)
	if e != nil {
		return e
	} else {
		return view.LookupRightSetEntry(hash)
	}
}

// fetchVertex loads the vertices for the provided set into the view
// from the database as needed unless they already exist
// in the view in which case they are ignored.
func (view *RightViewpoint) FetchRight(db database.DB, b map[chainhash.Hash]struct{}) error {
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
	return view.fetchRightMain(db, neededSet)
}

// NewVtxViewpoint returns a new empty vertex view.
func NewRightViewpoint() *RightViewpoint {
	return &RightViewpoint{
		entries: make(map[chainhash.Hash]interface{}),
	}
}

// dbPutRightView uses an existing database transaction to update the right set
// in the database based on the provided right view contents and state. In
// particular, only the entries that have been marked as modified (meaning new)
// and not spent (meaning not to be deleted) are written to the database.

func DbPutRightView(dbTx database.Tx, view *RightViewpoint) error {
	bucket := dbTx.Metadata().Bucket(rightSetBucketName)
	for hash, entry := range view.Entries() {
		// No need to update the database if the entry was not modified.
		if entry == nil {
			continue
		}

		mod := false
		todel := false

		switch entry.(type) {
		case *RightSetEntry:
			mod = entry.(*RightSetEntry).isModified()
			todel = entry.(*RightSetEntry).toDelete()
		case *RightEntry:
			mod = entry.(*RightEntry).isModified()
			todel = entry.(*RightEntry).toDelete()
		}
		if !mod {
			continue
		}

		// Remove the utxo entry if it is spent.
		if todel {
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
func serializeRightEntry(entry interface{}) ([]byte, error) {
	// Spent outputs have no serialization.
	var serialized []byte

	switch entry.(type) {
	case *RightEntry:
		if entry.(*RightEntry).toDelete() {
			return nil, nil
		}

		serialized = make([]byte, chainhash.HashSize*2+len(entry.(*RightEntry).Desc)+6)
		serialized[0] = 0
		copy(serialized[1:], entry.(*RightEntry).Father[:])
		serialized[chainhash.HashSize+1] = entry.(*RightEntry).Attrib
		copy(serialized[chainhash.HashSize+2:], entry.(*RightEntry).Root[:])
		byteOrder.PutUint32(serialized[chainhash.HashSize*2+2:], uint32(entry.(*RightEntry).Depth))
		copy(serialized[chainhash.HashSize*2+6:], entry.(*RightEntry).Desc[:])
		break
	case *RightSetEntry:
		if entry.(*RightSetEntry).toDelete() {
			return nil, nil
		}

		serialized = make([]byte, chainhash.HashSize*len(entry.(*RightSetEntry).Rights)+1)
		serialized[0] = 1
		p := 1
		for _, r := range entry.(*RightSetEntry).Rights {
			copy(serialized[p:], r[:])
			p += chainhash.HashSize
		}
		break
	}

	return serialized, nil
}

func dbPutRight(dbTx database.Tx, d interface{}) error {
	meta := dbTx.Metadata()
	bkt := meta.Bucket(rightSetBucketName)

	serialized, _ := serializeRightEntry(d)

	var h chainhash.Hash

	switch d.(type) {
	case *RightEntry:
		h = d.(*RightEntry).ToToken().Hash()
		break
	case *RightSetEntry:
		h = d.(*RightSetEntry).ToToken().Hash()
		break
	}

	return bkt.Put(h[:], serialized[:])
}

func DbFetchRight(dbTx database.Tx, hash *chainhash.Hash) (interface{}, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(rightSetBucketName)
	serialized := hashIndex.Get((*hash)[:])

	if serialized == nil {
		return nil, fmt.Errorf("Right entry does not exists in DB.")
	}

	switch serialized[0] {
	case 0:
		var d RightEntry

		copy(d.Father[:], serialized[1:])
		d.Attrib = serialized[chainhash.HashSize+1]

		copy(d.Root[:], serialized[chainhash.HashSize+2:])

		d.Depth = int32(byteOrder.Uint32(serialized[chainhash.HashSize*2+2:]))

		d.Desc = make([]byte, len(serialized)-(chainhash.HashSize*2+6))
		copy(d.Desc, serialized[chainhash.HashSize*2+6:])

		return &d, nil
	case 1:
		var d RightSetEntry

		d.Rights = make([]chainhash.Hash, (len(serialized)-1)/chainhash.HashSize)

		for i, p := 0, 1; p < len(serialized); p += chainhash.HashSize {
			copy(d.Rights[i][:], serialized[p:])
			i++
		}

		return &d, nil
	}
	return nil, nil
}

func dbRemoveRight(dbTx database.Tx, hash *chainhash.Hash) error {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(rightSetBucketName)

	return hashIndex.Delete(hash[:])
}
