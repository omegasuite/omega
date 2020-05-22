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
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	//	"github.com/btcsuite/btcd/txscript"
	//	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
	"fmt"
	"encoding/binary"
)

var borderBoxSetBucketName = []byte("borderboxes")

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
	Begin token.VertexDef
	End token.VertexDef
	Children []chainhash.Hash
	Bound * BoundingBox
	newchildren bool
	RefCnt int32		// reference count. record may be deleted when dropped to 0
	refChg int32		// change in reference count. not stored.

	// packedFlags contains additional info about vertex. Currently unused.
	PackedFlags txoFlags
}

func (b *BorderEntry) Enclose(d *BorderEntry) bool {
	return b.Bound.west <= d.Bound.west && b.Bound.south <= d.Bound.south &&
		b.Bound.east >= d.Bound.east && b.Bound.north >= d.Bound.north
}

func (b *BorderEntry) Joint(d *BorderEntry) bool {
	return !(b.Bound.west >= d.Bound.east || b.Bound.south >= d.Bound.north ||
		d.Bound.west >= b.Bound.east || d.Bound.south >= b.Bound.north)
}

func (b *BorderEntry) Lat(view * ViewPointSet, rev bool) int32 {
	var p * token.VertexDef
	if rev {
		p = &b.End
	} else {
		p = &b.Begin
	}
	return int32(p.Lat())
}

func (b *BorderEntry) Lng(view * ViewPointSet, rev bool) int32 {
	var p * token.VertexDef
	if rev {
		p = &b.End
	} else {
		p = &b.Begin
	}
	return int32(p.Lng())
}

func (b *BorderEntry) East(view * ViewPointSet) int32 {
	if b.Bound != nil {
		return b.Bound.east
	}
	bg := &b.Begin
	ed := &b.End
	if int32(bg.Lng()) > int32(ed.Lng()) {
		return int32(bg.Lng())
	}
	return int32(ed.Lng())
}

func (b *BorderEntry) West(view * ViewPointSet) int32 {
	if b.Bound != nil {
		return b.Bound.west
	}
	bg := &b.Begin
	ed := &b.End
	if int32(bg.Lng()) < int32(ed.Lng()) {
		return int32(bg.Lng())
	}
	return int32(ed.Lng())
}

func (b *BorderEntry) South(view * ViewPointSet) int32 {
	if b.Bound != nil {
		return b.Bound.south
	}
	bg := &b.Begin
	ed := &b.End
	if int32(bg.Lat()) > int32(ed.Lat()) {
		return int32(bg.Lat())
	}
	return int32(ed.Lat())
}

func (b *BorderEntry) North(view * ViewPointSet) int32 {
	if b.Bound != nil {
		return b.Bound.north
	}
	bg := &b.Begin
	ed := &b.End
	if int32(bg.Lat()) < int32(ed.Lat()) {
		return int32(bg.Lat())
	}
	return int32(ed.Lat())
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry * BorderEntry) isModified() bool {
	return entry.PackedFlags & TfModified == TfModified || entry.refChg != 0
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
		newchildren: entry.newchildren,
		PackedFlags: entry.PackedFlags,
	}
}

func (entry * BorderEntry) deReference() {
	entry.refChg--
}

func (entry * BorderEntry) reference() {
	entry.refChg++
}

func (entry * BorderEntry) Anciesters(view * ViewPointSet) map[chainhash.Hash]struct{} {
	as := make(map[chainhash.Hash]struct{})
	e := entry
	for !e.Father.IsEqual(&chainhash.Hash{}) {
		as[e.Father] = struct{}{}
		e,_ = view.Border.FetchEntry(view.Db, &e.Father)
	}
	return as
}

func (entry * BorderEntry) ToToken() * token.BorderDef {
	return token.NewBorderDef(entry.Begin, entry.End, entry.Father)
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

func NewBound(x1, x2, y1, y2 int32) * BoundingBox {
	b := BoundingBox {	x1, x1, y1, y1	}
	if x1 < x2 {
		b.east = x2
	} else {
		b.west = x2
	}
	if y1 < y2 {
		b.north = y2
	} else {
		b.south = y2
	}
	return &b
}

func (box  * BoundingBox) Clone() * BoundingBox {
	b := new(BoundingBox)
	*b = *box
	return b
}

func (box  * BoundingBox) Merge(b * BoundingBox) bool {
	c := false
	if b.east > box.east {
		box.east, c = b.east, true
	}
	if b.west < box.west {
		box.west, c = b.west, true
	}
	if b.north > box.north {
		box.north, c = b.north, true
	}
	if b.south < box.south {
		box.south, c = b.south, true
	}
	return c
}

func (fe * BorderEntry) mergeBound(view * ViewPointSet, b * BoundingBox) (* BoundingBox, bool) {
	var box * BoundingBox
	if fe.Bound == nil {
		box = &BoundingBox{
			east: fe.East(view), west: fe.West(view),south: fe.South(view),north: fe.North(view),
		}
	} else {
		box = fe.Bound
	}
	c := box.Merge(b)

	if c {
		fe.PackedFlags |= TfModified
		fe.Bound = box
	}
	return box, c
}

func (fe * BorderEntry) HasChild(h chainhash.Hash) bool {
	for _, hs := range fe.Children {
		if hs.IsEqual(&h) {
			return true
		}
	}
	return false
}
// addBorder adds the specified BorderDef to the view.
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

		bg := &b.Begin
		ed := &b.End

		box := NewBound(int32(bg.Lng()), int32(ed.Lng()), int32(bg.Lat()), int32(ed.Lat()))

		for !f.IsEqual(&chainhash.Hash{}) {
			view.Border.FetchEntry(view.Db, &f)
			fe := view.Border.LookupEntry(f)
			if fe == nil {
				delete(view.Border.entries, h)
				return false
			}
			var c bool
			box,c = fe.mergeBound(view, box)

			if !fe.HasChild(h) {
				fe.Children = append(fe.Children, h)
				fe.PackedFlags = TfModified
				fe.newchildren = true
			}

			if !c {
				return true
			} else {
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
				h := txDef.Hash()
				p := view.LookupEntry(h)
				if p == nil {
					p,_ = view.FetchEntry(db, &h)
				}
				if p != nil {
					p.RollBack()
				}
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

		entry.PackedFlags &^= TfModified
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

func (entry *BorderEntry) boxindex() uint64 {
	xb := uint32(entry.Begin.Lat()) + 0x80000000
	xe := uint32(entry.End.Lat()) + 0x80000000
	yb := uint32(entry.Begin.Lng()) + 0x80000000
	ye := uint32(entry.End.Lng()) + 0x80000000
	x := xb ^ xe
	y := yb ^ ye
	w := x
	if y > w {
		w = y
	}
	lbh := uint64(1)
	for w != 0 {
		w &= ^uint32(lbh)
		lbh <<= 1
	}
	lbh >>= 1
	m := lbh - 1

	x = xb & ^uint32(m)
	xe = xe & ^uint32(m)
	if xe > x {
		x = xe
	}
	x |= uint32(lbh)
	y = yb & ^uint32(m)
	ye = ye & ^uint32(m)
	if ye > y {
		y = ye
	}
	y |= uint32(lbh)

	return uint64(x) | (uint64(y) << 32)
}

func addbbox(boxbucket database.Bucket, boxindex uint64, w uint32, hash chainhash.Hash) error {
	var bx [8]byte
	qw := uint64(w - 1)
	qw |= qw << 32
	ww := uint64(w) | (uint64(w) << 32)
	binary.LittleEndian.PutUint64(bx[:], (boxindex & ^qw) | ww)
	bucket := boxbucket.Bucket(bx[:])
	if bucket == nil {
		var err error
		if bucket,err = boxbucket.CreateBucket(bx[:]); err != nil {
			return err
		}
	}
	if (boxindex & qw) == 0 {
		return bucket.Put(hash[:], []byte{1})
	}
	return addbbox(bucket, boxindex, w >> 1, hash)
}

func removebbox(boxbucket database.Bucket, boxindex uint64, w uint32, hash chainhash.Hash) {
	var bx [8]byte
	qw := uint64(w - 1)
	qw |= qw << 32
	ww := uint64(w) | (uint64(w) << 32)
	binary.LittleEndian.PutUint64(bx[:], (boxindex & ^qw) | ww)
	bucket := boxbucket.Bucket(bx[:])
	if bucket == nil {
		return
	}
	if (boxindex & qw) == 0 {
		bucket.Delete(hash[:])
		return
	}
	removebbox(bucket, boxindex, w >> 1, hash)
}

func inside(boxindex uint64, box [4]uint32, bit byte) bool {
	left := uint32(boxindex & 0xFFFFFFFF) - (1 << bit)
	right := uint32(boxindex & 0xFFFFFFFF) + (1 << bit)
	bottom := uint32(boxindex >> 32) - (1 << bit)
	top := uint32(boxindex >> 32) + (1 << bit)
	return left >= box[0] && right <= box[1] && bottom >= box[2] && top <= box[3]
}

func intersects(boxindex uint64, box [4]uint32, bit byte) bool {
	left := (boxindex & 0xFFFFFFFF) - (1 << bit)
	right := (boxindex & 0xFFFFFFFF) + (1 << bit)
	bottom := (boxindex >> 32) - (1 << bit)
	top := (boxindex >> 32) + (1 << bit)
	return !(left > uint64(box[1]) || right < uint64(box[0]) || bottom > uint64(box[3]) || top < uint64(box[2]))
}

func Findborders(dbTx database.Tx, box [4]uint32, lod byte) []chainhash.Hash {
	boxbucket := dbTx.Metadata().Bucket(borderBoxSetBucketName)
	bucket := boxbucket.Bucket([]byte{0, 0, 0, 0x80, 0, 0, 0, 0x80})

	if bucket == nil {
		return []chainhash.Hash{}
	}

	return findborders(dbTx, bucket, box, 0x8000000080000000, 31, lod, false)
}

func borderintersects(dbTx database.Tx, d *chainhash.Hash, box [4]uint32) bool {
	e, err := DbFetchBorderEntry(dbTx, d)
	if err != nil {
		return false
	}

	bx := uint32(e.Begin.Lat()) + 0x80000000
	ex := uint32(e.End.Lat()) + 0x80000000
	by := uint32(e.Begin.Lng()) + 0x80000000
	ey := uint32(e.End.Lng()) + 0x80000000
	var left, right, bottom, top uint32
	if bx > ex {
		left = ex
		right = bx
	} else {
		left = bx
		right = ex
	}
	if by > ey {
		bottom = ey
		top = by
	} else {
		bottom = by
		top = ey
	}
	if !(left > box[1] || right < box[0] || bottom > box[3] || top < box[2]) {
		return false
	}

	px := 0
	py := 0

	if ey - by > 0 {
		px = 1
	}
	if ex - bx > 0 {
		py = 1
	}

	if (bx - box[px]) * (ey - by) - (by - box[py + 2]) * (ex - bx) < 0 {
		return false
	}

	if (bx - box[1 - px]) * (ey - by) - (by - box[3 - py]) * (ex - bx) < 0 {
		return false
	}

	return true
}

func mergeborders(dbTx database.Tx, e []chainhash.Hash) []chainhash.Hash {
	fathers := make(map[chainhash.Hash]*[]chainhash.Hash)
	merged := make([]chainhash.Hash, 0)
	zeroHash := chainhash.Hash{}

	for _, g := range e {
		f, err := DbFetchBorderEntry(dbTx, &g)
		if err != nil {	// never happens
			continue
		}
		if f.Father.IsEqual(&zeroHash) {
			merged = append(merged, g)
		} else {
			if p,ok := fathers[f.Father]; !ok {
				t := make([]chainhash.Hash, 1)
				t[0] = g
				fathers[f.Father] = &t
			} else {
				*fathers[f.Father] = append(*p, g)
			}
		}
	}

	for len(fathers) != 0 {
		for f, s := range fathers {
			ft, _ := DbFetchBorderEntry(dbTx, &f)
			if len(ft.Children) != len(*s) {
				for _, q := range *s {
					merged = append(merged, q)
				}
			} else {
				if p, ok := fathers[ft.Father]; !ok {
					t := make([]chainhash.Hash, 1)
					t[0] = f
					fathers[ft.Father] = &t
				} else {
					*fathers[ft.Father] = append(*p, f)
				}
			}
			delete(fathers, f)
		}
	}
	return merged
}

func findborders(dbTx database.Tx, boxbucket database.Bucket, box [4]uint32, boxindex uint64, bit, lod byte, mode bool) []chainhash.Hash {
	res := make([]chainhash.Hash, 0)

	cursor := boxbucket.Cursor()
	for ok := cursor.First(); ok; ok = cursor.Next() {
		d := cursor.Key()
		if len(d) != 32 {
			continue
		}
		h := chainhash.Hash{}
		copy(h[:], d)
		if mode || borderintersects(dbTx, &h, box) {
			res = append(res, h)
		}
	}

	if bit == 0 {
		if bit < lod {
			res = mergeborders(dbTx, res)
		}

		return res
	}

	if inside(boxindex, box, bit) {
		mode = true
	}

	boxindex &^= (uint64(1) << bit) | (uint64(1) << (bit + 32))
	boxindex |= (uint64(1) << (bit - 1)) | (uint64(1) << (bit + 31))

	var bws [4]uint64
	bws[0] = boxindex
	bws[1] = boxindex | (uint64(1) << bit)
	bws[2] = bws[0] | (uint64(1) << (bit + 32))
	bws[3] = bws[1] | (uint64(1) << (bit + 32))

	for i := 0; i < 4; i++ {
		var bx [8]byte
		bw := bws[i]
		binary.LittleEndian.PutUint64(bx[:], bw)
		bucket := boxbucket.Bucket(bx[:])
		if bucket == nil {
			continue
		}
		if mode || intersects(bw, box, bit) {
			res = append(res, findborders(dbTx, bucket, box, bw, bit-1, lod, mode)...)
		}
	}

	if bit < lod {
		res = mergeborders(dbTx, res)
	}

	return res
}

// dbPutVtxView uses an existing database transaction to update the vertex set
// in the database based on the provided utxo view contents and state. In
// particular, only the entries that have been marked as modified (meaning new)
// and not spent (meaning not to be deleted) are written to the database.
func DbPutBorderView(dbTx database.Tx, view *BorderViewpoint) error {
	bucket := dbTx.Metadata().Bucket(borderSetBucketName)
	boxbucket := dbTx.Metadata().Bucket(borderBoxSetBucketName)

	for hash, entry := range view.Entries() {
		// No need to update the database if the entry was not modified.
		if entry == nil || !entry.isModified() {
			continue
		}

		boxindex := entry.boxindex()

		// Remove the utxo entry if it is spent.
		if entry.toDelete() {
			if err := bucket.Delete(hash[:]); err != nil {
				return err
			}
			if len(entry.Children) == 0 {
				// remove box
				removebbox(boxbucket, boxindex, 0x80000000, hash)
			}
			entry.PackedFlags &^= TfModified
			return nil
		}

		// Serialize and store the utxo entry.
		serialized, err := serializeBorderEntry(entry)
		if err != nil {
			return err
		}

		if err = bucket.Put(hash[:], serialized); err != nil {
			return err
		}
		if len(entry.Children) > 0 && entry.newchildren {
			// remove box
			removebbox(boxbucket, boxindex, 0x80000000, hash)
		} else if len(entry.Children) == 0  {
			addbbox(boxbucket, boxindex, 0x80000000, hash)
		}

		entry.PackedFlags &^= TfModified
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

	if entry.refChg != 0 {
		entry.RefCnt += entry.refChg
		entry.refChg = 0
	}

	s := 4 + chainhash.HashSize * (3 + len(entry.Children))
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

	binary.LittleEndian.PutUint32(serialized[pos:], uint32(entry.RefCnt))

	if entry.Bound != nil {
		binary.LittleEndian.PutUint32(serialized[pos + 4:], uint32(entry.Bound.west))
		binary.LittleEndian.PutUint32(serialized[pos + 8:], uint32(entry.Bound.east))
		binary.LittleEndian.PutUint32(serialized[pos + 12:], uint32(entry.Bound.south))
		binary.LittleEndian.PutUint32(serialized[pos + 16:], uint32(entry.Bound.north))
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
	b.RefCnt = int32(binary.LittleEndian.Uint32(serialized[p:]))
	p += 4

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
