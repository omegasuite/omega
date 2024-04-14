/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package viewpoint

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/omegasuite/btcd/blockchain/bccompress"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/token"
)

// txoFlags is a bitmask defining additional information and state for a
// transaction output in a utxo view.

const (
	// tfCoinBase indicates that a txout was contained in a coinbase tx.
	TfCoinBase txoFlags = 1 << iota

	// tfSpent indicates that a txout is spent / to be deleted in case of a definition.
	TfSpent

	// tfModified indicates that a txout/definition has been modified since it was loaded
	// or created

	TfModified

	// TfMonitoring indicates this UTXO is a monitoring token
	TfMonitoring
)

// AssertError identifies an error that indicates an internal code consistency
// issue and should be treated as a critical and unrecoverable error.
type AssertError string

// Error returns the assertion error as a human-readable string and satisfies
// the error interface.
func (e AssertError) Error() string {
	return "assertion failed: " + string(e)
}

// UtxoEntry houses details about an individual transaction output in a utxo
// view such as whether or not it was contained in a coinbase tx, the height of
// the block that contains the tx, whether or not it is spent, its public key
// script, and how much it pays.
type UtxoEntry struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.
	TokenType   uint64
	Amount      token.TokenValue
	Rights      *chainhash.Hash
	pkScript    []byte // The public key script for the output.
	blockHeight int32  // Height of block containing tx.

	// packedFlags contains additional info about output such as whether it
	// is a coinbase, whether it is spent, and whether it has been modified
	// since it was loaded.  This approach is used in order to reduce memory
	// usage since there will be a lot of these in memory.
	packedFlags txoFlags

	// Monitor to add
	monitor []byte
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry *UtxoEntry) isModified() bool {
	return entry.packedFlags&TfModified == TfModified
}

// IsCoinBase returns whether or not the output was contained in a coinbase
// transaction.
func (entry *UtxoEntry) IsCoinBase() bool {
	return entry.packedFlags&TfCoinBase == TfCoinBase
}

// BlockHeight returns the height of the block containing the output.
func (entry *UtxoEntry) BlockHeight() int32 {
	return entry.blockHeight
}

// IsSpent returns whether or not the output has been spent based upon the
// current state of the unspent transaction output view it was obtained from.
func (entry *UtxoEntry) IsSpent() bool {
	return entry.packedFlags&TfSpent == TfSpent
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (entry *UtxoEntry) Spend() {
	// Nothing to do if the output is already spent.
	if entry.IsSpent() {
		return
	}

	// Mark the output as spent and modified.
	entry.packedFlags |= TfSpent | TfModified
}

// Amount returns the amount of the output.
func (entry *UtxoEntry) NumAmount() int64 {
	if entry.TokenType&1 != 0 {
		panic("Incorrect TokenType. -- UtxoEntry.NumAmount()")
	}
	return entry.Amount.(*token.NumToken).Val
}

func (entry *UtxoEntry) RawAmount() token.TokenValue {
	return entry.Amount
}

// PkScript returns the public key script for the output.
func (entry *UtxoEntry) PkScript() []byte {
	return entry.pkScript
}

// Clone returns a shallow copy of the utxo entry.
func (entry *UtxoEntry) Clone() *UtxoEntry {
	if entry == nil {
		return nil
	}

	var r *chainhash.Hash
	if entry.Rights != nil {
		r, _ = chainhash.NewHash((*entry.Rights)[:])
	} else {
		r = nil
	}

	return &UtxoEntry{
		TokenType:   entry.TokenType,
		Amount:      entry.Amount,
		pkScript:    entry.pkScript,
		Rights:      r,
		blockHeight: entry.blockHeight,
		packedFlags: entry.packedFlags,
	}
}

func (entry *UtxoEntry) ToTxOut() *wire.TxOut {
	t := wire.TxOut{}
	var r *chainhash.Hash
	if entry.Rights != nil {
		r, _ = chainhash.NewHash((*entry.Rights)[:])
	} else {
		r = nil
	}
	t.Token = token.Token{
		entry.TokenType,
		entry.Amount,
		r,
	}
	t.PkScript = entry.pkScript
	return &t
}

// SpentTxOut contains a spent transaction output and potentially additional
// contextual information such as whether or not it was contained in a coinbase
// transaction, the version of the transaction it was contained in, and which
// block height the containing transaction was included in.  As described in
// the comments above, the additional contextual information will only be valid
// when this spent txout is spending the last unspent output of the containing
// transaction.
type SpentTxOut struct {
	TokenType uint64

	// Amount is the amount/value of the output.
	Amount token.TokenValue

	Rights *chainhash.Hash

	// PkScipt is the the public key script for the output.
	PkScript []byte

	// Height is the height of the the block containing the creating tx.
	Height int32

	// Denotes if the creating tx is a coinbase.
	IsCoinBase bool
}

// UtxoViewpoint represents a view into the set of unspent transaction outputs
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.
//
// The unspent outputs are needed by other transactions for things such as
// script validation and double spend prevention.
type UtxoViewpoint struct {
	entries  map[wire.OutPoint]*UtxoEntry
	bestHash chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view *UtxoViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view *UtxoViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// LookupEntry returns information about a given transaction output according to
// the current state of the view.  It will return nil if the passed output does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
func (view *UtxoViewpoint) LookupEntry(outpoint wire.OutPoint) *UtxoEntry {
	return view.entries[outpoint]
}

// addTxOut adds the specified output to the view if it is not provably
// unspendable.  When the view already has an entry for the output, it will be
// marked unspent.  All fields will be updated for existing entries since it's
// possible it has changed during a reorg.
func (view *UtxoViewpoint) addTxOut(outpoint wire.OutPoint, txOut *wire.TxOut, isCoinBase bool, blockHeight int32) *UtxoEntry {
	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	entry := view.LookupEntry(outpoint)
	if entry == nil {
		entry = new(UtxoEntry)
		view.entries[outpoint] = entry
	}

	entry.TokenType = txOut.TokenType
	if txOut.Rights != nil {
		entry.Rights, _ = chainhash.NewHash((*txOut.Rights)[:])
	} else {
		entry.Rights = nil
	}
	entry.Amount = txOut.Value
	entry.pkScript = txOut.PkScript
	entry.blockHeight = blockHeight
	entry.packedFlags = TfModified
	if isCoinBase {
		entry.packedFlags |= TfCoinBase
	}

	return entry
}

func (view *UtxoViewpoint) AddRawTxOut(outpoint wire.OutPoint, txOut *wire.TxOut, isCoinBase bool, blockHeight int32) *UtxoEntry {
	return view.addTxOut(outpoint, txOut, isCoinBase, blockHeight)
}

// AddTxOut adds the specified output of the passed transaction to the view if
// it exists and is not provably unspendable.  When the view already has an
// entry for the output, it will be marked unspent.  All fields will be updated
// for existing entries since it's possible it has changed during a reorg.
func (view *ViewPointSet) AddTxOut(tx *btcutil.Tx, txOutIdx uint32, blockHeight int32) {
	// Can't add an output for an out of bounds index.
	if txOutIdx >= uint32(len(tx.MsgTx().TxOut)) {
		return
	}

	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	prevOut := wire.OutPoint{Hash: *tx.Hash(), Index: txOutIdx}
	txOut := tx.MsgTx().TxOut[txOutIdx]

	if txOut.IsSeparator() {
		return
	}

	coinbase := tx.IsCoinBase()
	if coinbase {
		for i, u := range tx.MsgTx().TxOut {
			if u.IsSeparator() && i < int(txOutIdx) {
				coinbase = false
				break
			}
		}
	}

	if txOut.IsNopaying() {
		return
	}

	e := view.Utxo.addTxOut(prevOut, txOut, coinbase, blockHeight)

	// if it has a monitor right, add a monitor index
	y := view.TokenRights(e)
	for _, r := range y {
		re, _ := view.FetchRightEntry(&r)
		if re.(*RightEntry).Attrib&token.Monitor != 0 {
			e.packedFlags |= TfMonitoring | TfModified
			e.monitor = make([]byte, 52)
			copy(e.monitor, re.(*RightEntry).Desc[1:21])
			copy(e.monitor[20:], txOut.Value.(*token.HashToken).Hash[:])
		}
	}
}

// AddTxOuts adds all outputs in the passed transaction which are not provably
// unspendable to the view.  When the view already has entries for any of the
// outputs, they are simply marked unspent.  All fields will be updated for
// existing entries since it's possible it has changed during a reorg.
func (view *ViewPointSet) AddTxOuts(tx *btcutil.Tx, blockHeight int32) {
	// Loop all of the transaction outputs and add those which are not
	// provably unspendable.
	isCoinBase := tx.IsCoinBase()
	prevOut := wire.OutPoint{Hash: *tx.Hash()}
	for txOutIdx, txOut := range tx.MsgTx().TxOut {
		if txOut.IsSeparator() {
			continue
		}
		if txOut.IsNopaying() {
			continue
		}
		// Update existing entries.  All fields are updated because it's
		// possible (although extremely unlikely) that the existing
		// entry is being replaced by a different transaction with the
		// same hash.  This is allowed so long as the previous
		// transaction is fully spent.
		prevOut.Index = uint32(txOutIdx)
		e := view.Utxo.addTxOut(prevOut, txOut, isCoinBase, blockHeight)

		// if it has a monitor right, add a monitor index
		y := view.TokenRights(e)
		for _, r := range y {
			re, _ := view.FetchRightEntry(&r)
			if re.(*RightEntry).Attrib&token.Monitor != 0 {
				e.packedFlags |= TfMonitoring
				e.monitor = make([]byte, 52)
				copy(e.monitor, re.(*RightEntry).Desc[1:21])
				copy(e.monitor[20:], txOut.Value.(*token.HashToken).Hash[:])
			}
		}
	}
}

// connectTransaction updates the view by adding all new utxos created by the
// passed transaction and marking all utxos that the transactions spend as
// spent.  In addition, when the 'stxos' argument is not nil, it will be updated
// to append an entry for each spent txout.  An error will be returned if the
// view does not contain the required utxos.
func (view *ViewPointSet) ConnectTransaction(tx *btcutil.Tx, blockHeight int32, stxos *[]SpentTxOut) error {
	// Coinbase transactions don't have any inputs to spend.
	if tx.IsCoinBase() {
		// Add the transaction's outputs as available utxos.
		view.AddTxOuts(tx, blockHeight)
		return nil
	}

	// Spend the referenced utxos by marking them spent in the view and,
	// if a slice was provided for the spent txout details, append an entry
	// to it.
	for _, txIn := range tx.MsgTx().TxIn {
		if txIn.PreviousOutPoint.Hash.IsEqual(&zerohash) {
			continue
		}
		// Ensure the referenced utxo exists in the view.  This should
		// never happen unless there is a bug is introduced in the code.
		entry := view.Utxo.entries[txIn.PreviousOutPoint]
		if entry == nil {
			return AssertError(fmt.Sprintf("view missing input %v",
				txIn.PreviousOutPoint))
		}

		// Only create the stxo details if requested.
		if stxos != nil {
			// Populate the stxo details using the utxo entry.
			var nr *chainhash.Hash
			if entry.Rights != nil {
				nr, _ = chainhash.NewHash((*entry.Rights)[:])
			} else {
				nr = nil
			}
			var stxo = SpentTxOut{
				TokenType:  entry.TokenType,
				Rights:     nr,
				Amount:     entry.Amount,
				PkScript:   entry.PkScript(),
				Height:     entry.BlockHeight(),
				IsCoinBase: entry.IsCoinBase(),
			}
			*stxos = append(*stxos, stxo)
		}

		// Mark the entry as spent.  This is not done until after the
		// relevant details have been accessed since spending it might
		// clear the fields from memory in the future.
		entry.Spend()
	}

	// Add the transaction's outputs as available utxos.
	view.AddTxOuts(tx, blockHeight)
	return nil
}

// disconnectTransactions updates the view by removing all of the transactions
// created by the passed block, restoring all utxos the transactions spent by
// using the provided spent txo information, and setting the best hash for the
// view to the block before the passed block.
func (view *ViewPointSet) disconnectTransactions(db database.DB, block *btcutil.Block, stxos []SpentTxOut) error {
	// Sanity check the correct number of stxos are provided.
	if len(stxos) != block.CountSpentOutputs() {
		return AssertError("disconnectTransactions called with bad " +
			"spent transaction out information")
	}

	// Loop backwards through all transactions so everything is unspent in
	// reverse order.  This is necessary since transactions later in a block
	// can spend from previous ones.
	stxoIdx := len(stxos) - 1
	transactions := block.Transactions()
	for txIdx := len(transactions) - 1; txIdx > -1; txIdx-- {
		tx := transactions[txIdx]

		// All entries will need to potentially be marked as a coinbase.
		var packedFlags txoFlags
		isCoinBase := txIdx == 0
		if isCoinBase {
			packedFlags |= TfCoinBase
		}

		// Mark all of the spendable outputs originally created by the
		// transaction as spent.  It is instructive to note that while
		// the outputs aren't actually being spent here, rather they no
		// longer exist, since a pruned utxo set is used, there is no
		// practical difference between a utxo that does not exist and
		// one that has been spent.
		//
		// When the utxo does not already exist in the view, add an
		// entry for it and then mark it spent.  This is done because
		// the code relies on its existence in the view in order to
		// signal modifications have happened.
		txHash := tx.Hash()
		prevOut := wire.OutPoint{Hash: *txHash}
		for txOutIdx, txOut := range tx.MsgTx().TxOut {
			if txOut.IsSeparator() {
				packedFlags &= ^TfCoinBase
				continue
			}
			if txOut.IsNopaying() {
				continue
			}
			prevOut.Index = uint32(txOutIdx)
			entry := view.Utxo.entries[prevOut]
			if entry == nil {
				var r *chainhash.Hash
				if txOut.Rights != nil {
					r, _ = chainhash.NewHash(txOut.Rights[:])
				} else {
					r = nil
				}
				entry = &UtxoEntry{
					TokenType:   txOut.TokenType,
					Amount:      txOut.Value,
					Rights:      r,
					pkScript:    txOut.PkScript,
					blockHeight: block.Height(),
					packedFlags: packedFlags,
				}

				view.Utxo.entries[prevOut] = entry
			}

			// if it has a monitor right, add a monitor index
			y := view.TokenRights(entry)
			for _, r := range y {
				re, _ := view.FetchRightEntry(&r)
				if re.(*RightEntry).Attrib&token.Monitor != 0 {
					entry.packedFlags |= TfMonitoring | TfModified
					entry.monitor = make([]byte, 52)
					copy(entry.monitor, re.(*RightEntry).Desc[1:21])
					copy(entry.monitor[20:], txOut.Value.(*token.HashToken).Hash[:])
				}
			}

			if txOut.TokenType == 3 {
				t := view.Polygon.LookupEntry(txOut.Token.Value.(*token.HashToken).Hash)
				if t == nil {
					view.FetchPolygonEntry(&entry.Amount.(*token.HashToken).Hash)
					t = view.Polygon.LookupEntry(entry.Amount.(*token.HashToken).Hash)
				}
				if t == nil {
					return fmt.Errorf("Missing polygon definition %s", entry.Amount.(*token.HashToken).Hash.String())
				}
				t.deReference(view)
			}

			entry.Spend()
		}

		// Loop backwards through all of the transaction inputs (except
		// for the coinbase which has no inputs) and unspend the
		// referenced txos.  This is necessary to match the order of the
		// spent txout entries.
		if isCoinBase {
			continue
		}
		for txInIdx := len(tx.MsgTx().TxIn) - 1; txInIdx > -1; txInIdx-- {
			if tx.MsgTx().TxIn[txInIdx].PreviousOutPoint.Hash.IsEqual(&zerohash) {
				continue
			}
			// Ensure the spent txout index is decremented to stay
			// in sync with the transaction input.
			stxo := &stxos[stxoIdx]
			stxoIdx--

			// When there is not already an entry for the referenced
			// output in the view, it means it was previously spent,
			// so create a new utxo entry in order to resurrect it.
			originOut := &tx.MsgTx().TxIn[txInIdx].PreviousOutPoint
			entry := view.Utxo.entries[*originOut]
			if entry == nil {
				entry = new(UtxoEntry)
				view.Utxo.entries[*originOut] = entry
			}

			// The legacy v1 spend journal format only stored the
			// coinbase flag and height when the output was the last
			// unspent output of the transaction.  As a result, when
			// the information is missing, search for it by scanning
			// all possible outputs of the transaction since it must
			// be in one of them.
			//
			// It should be noted that this is quite inefficient,
			// but it realistically will almost never run since all
			// new entries include the information for all outputs
			// and thus the only way this will be hit is if a long
			// enough reorg happens such that a block with the old
			// spend data is being disconnected.  The probability of
			// that in practice is extremely low to begin with and
			// becomes vanishingly small the more new blocks are
			// connected.  In the case of a fresh database that has
			// only ever run with the new v2 format, this code path
			// will never run.
			if stxo.Height == 0 {
				utxo, err := view.Utxo.fetchEntryByHash(db, txHash)
				if err != nil {
					return err
				}
				if utxo == nil {
					return AssertError(fmt.Sprintf("unable "+
						"to resurrect legacy stxo %v",
						*originOut))
				}

				stxo.Height = utxo.BlockHeight()
				stxo.IsCoinBase = utxo.IsCoinBase()
			}

			// Restore the utxo using the stxo data from the spend
			// journal and mark it as modified.
			entry.TokenType = stxo.TokenType
			entry.Amount = stxo.Amount
			entry.Rights = stxo.Rights
			entry.pkScript = stxo.PkScript
			entry.blockHeight = stxo.Height
			entry.packedFlags = TfModified
			if stxo.IsCoinBase {
				entry.packedFlags |= TfCoinBase
			}

			if entry.TokenType == 3 {
				t := view.Polygon.LookupEntry(entry.Amount.(*token.HashToken).Hash)
				if t == nil {
					view.FetchPolygonEntry(&entry.Amount.(*token.HashToken).Hash)
					t = view.Polygon.LookupEntry(entry.Amount.(*token.HashToken).Hash)
				}
				if t == nil {
					return fmt.Errorf("Missing polygon definition %s", entry.Amount.(*token.HashToken).Hash.String())
				}
				t.reference(view)
			}

			// if it has a monitor right, add a monitor index
			y := view.TokenRights(entry)
			for _, r := range y {
				re, _ := view.FetchRightEntry(&r)
				if re.(*RightEntry).Attrib&token.Monitor != 0 {
					entry.packedFlags |= TfMonitoring
					entry.monitor = make([]byte, 52)
					copy(entry.monitor, re.(*RightEntry).Desc[1:21])
					copy(entry.monitor[20:], entry.Amount.(*token.HashToken).Hash[:])
				}
			}
		}
	}

	// Update the best hash for view to the previous block since all of the
	// transactions for the current block have been disconnected.
	view.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return nil
}

// OutpointKey returns a key suitable for use as a database key in the utxo set
// while making use of a free list.  A new buffer is allocated if there are not
// already any available on the free list.  The returned byte slice should be
// returned to the free list by using the recycleOutpointKey function when the
// caller is done with it _unless_ the slice will need to live for longer than
// the caller can calculate such as when used to write to the database.
func OutpointKey(outpoint wire.OutPoint) *[]byte {
	// A VLQ employs an MSB encoding, so they are useful not only to reduce
	// the amount of storage space, but also so iteration of utxos when
	// doing byte-wise comparisons will produce them in order.
	key := outpointKeyPool.Get().(*[]byte)
	idx := uint64(outpoint.Index)
	*key = (*key)[:chainhash.HashSize+bccompress.SerializeSizeVLQ(idx)]
	copy(*key, outpoint.Hash[:])
	bccompress.PutVLQ((*key)[chainhash.HashSize:], idx)
	return key
}

func Key2Outpoint(key []byte) wire.OutPoint {
	var outpoint wire.OutPoint
	copy(outpoint.Hash[:], key[:chainhash.HashSize])
	x, _ := bccompress.DeserializeVLQ(key[chainhash.HashSize:])
	outpoint.Index = uint32(x)
	return outpoint
}

// maxUint32VLQSerializeSize is the maximum number of bytes a max uint32 takes
// to serialize as a VLQ.
var maxUint32VLQSerializeSize = bccompress.SerializeSizeVLQ(1<<32 - 1)

// outpointKeyPool defines a concurrent safe free list of byte slices used to
// provide temporary buffers for outpoint database keys.
var outpointKeyPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, chainhash.HashSize+maxUint32VLQSerializeSize)
		return &b // Pointer to slice to avoid boxing alloc.
	},
}

// find a polygon utxo identified owner and polygon
func (view *ViewPointSet) FindMonitor(addr []byte, hash chainhash.Hash) *UtxoEntry {
	serialized := []byte(nil)

	key := make([]byte, len(addr)+len(hash))
	copy(key, addr)
	copy(key[len(addr):], hash[:])

	view.Db.View(func(dbTx database.Tx) error {
		utxoBucket := dbTx.Metadata().Bucket(utxoSetBucketName)
		serialized = utxoBucket.Get(key)

		if serialized == nil || len(serialized) == 0 {
			return nil
		}

		// take serialized as an outpoint to find it out
		serialized = utxoBucket.Get(serialized)
		return nil
	})

	if serialized == nil || len(serialized) == 0 {
		return nil
	}

	// Deserialize the utxo entry and return it.
	entry, _ := DeserializeUtxoEntry(serialized)

	return entry
}

// recycleOutpointKey puts the provided byte slice, which should have been
// obtained via the OutpointKey function, back on the free list.
func recycleOutpointKey(key *[]byte) {
	outpointKeyPool.Put(key)
}

// dbFetchUtxoEntryByHash attempts to find and fetch a utxo for the given hash.
// It uses a cursor and seek to try and do this as efficiently as possible.
//
// When there are no entries for the provided hash, nil will be returned for the
// both the entry and the error.
func dbFetchUtxoEntryByHash(dbTx database.Tx, hash *chainhash.Hash) (*UtxoEntry, error) {
	// Attempt to find an entry by seeking for the hash along with a zero
	// index.  Due to the fact the keys are serialized as <hash><index>,
	// where the index uses an MSB encoding, if there are any entries for
	// the hash at all, one will be found.
	cursor := dbTx.Metadata().Bucket(utxoSetBucketName).Cursor()
	key := OutpointKey(wire.OutPoint{Hash: *hash, Index: 0})
	ok := cursor.Seek(*key)
	recycleOutpointKey(key)
	if !ok {
		return nil, nil
	}

	// An entry was found, but it could just be an entry with the next
	// highest hash after the requested one, so make sure the hashes
	// actually match.
	cursorKey := cursor.Key()
	if len(cursorKey) < chainhash.HashSize {
		return nil, nil
	}
	if !bytes.Equal(hash[:], cursorKey[:chainhash.HashSize]) {
		return nil, nil
	}

	return DeserializeUtxoEntry(cursor.Value())
}

// DeserializeUtxoEntry decodes a utxo entry from the passed serialized byte
// slice into a new UtxoEntry using a format that is suitable for long-term
// storage.  The format is described in detail above.
func DeserializeUtxoEntry(serialized []byte) (*UtxoEntry, error) {
	// Ensure there are bytes to decode.
	if len(serialized) == 0 {
		return nil, bccompress.ErrDeserialize("no serialized bytes")
	}

	// Deserialize the header code.
	code, offset := bccompress.DeserializeVLQ(serialized)
	if offset >= len(serialized) {
		return nil, bccompress.ErrDeserialize("unexpected end of data after header")
	}

	// Decode the header code.
	//
	// Bit 0 indicates whether the containing transaction is a coinbase.
	// Bits 1-x encode height of containing transaction.
	isCoinBase := code&0x01 != 0
	blockHeight := int32(code >> 1)

	entry := &UtxoEntry{
		blockHeight: blockHeight,
		packedFlags: 0,
	}
	if isCoinBase {
		entry.packedFlags |= TfCoinBase
	}

	code, bytesRead := bccompress.DeserializeVLQ(serialized[offset:])
	offset += bytesRead
	entry.TokenType = code

	if (entry.TokenType & 1) == 0 {
		// Decode the compressed unspent transaction output.
		compressedAmount, bytesRead := bccompress.DeserializeVLQ(serialized[offset:])
		amount := bccompress.DecompressTxOutAmount(compressedAmount)

		offset += bytesRead
		entry.Amount = &token.NumToken{
			Val: int64(amount),
		}
	} else {
		var hash chainhash.Hash
		copy(hash[:], serialized[offset:])
		offset += chainhash.HashSize
		entry.Amount = &token.HashToken{
			Hash: hash,
		}
	}

	if (entry.TokenType & 2) == 2 {
		entry.Rights = &chainhash.Hash{}
		copy(entry.Rights[:], serialized[offset:])
		offset += chainhash.HashSize
	}
	entry.pkScript = serialized[offset:]

	return entry, nil
}

// fetchEntryByHash attempts to find any available utxo for the given hash by
// searching the entire set of possible outputs for the given hash.  It checks
// the view first and then falls back to the database if needed.
func (view *UtxoViewpoint) fetchEntryByHash(db database.DB, hash *chainhash.Hash) (*UtxoEntry, error) {
	// First attempt to find a utxo with the provided hash in the view.
	prevOut := wire.OutPoint{Hash: *hash}
	for idx := uint32(0); idx < chaincfg.MaxOutputsPerTx; idx++ {
		prevOut.Index = idx
		entry := view.LookupEntry(prevOut)
		if entry != nil {
			return entry, nil
		}
	}

	// Check the database since it doesn't exist in the view.  This will
	// often by the case since only specifically referenced utxos are loaded
	// into the view.
	var entry *UtxoEntry
	err := db.View(func(dbTx database.Tx) error {
		var err error
		entry, err = dbFetchUtxoEntryByHash(dbTx, hash)
		return err
	})
	return entry, err
}

// DbFetchUtxoEntry uses an existing database transaction to fetch the specified
// transaction output from the utxo set.
//
// When there is no entry for the provided output, nil will be returned for both
// the entry and the error.
func DbFetchUtxoEntry(dbTx database.Tx, outpoint wire.OutPoint) (*UtxoEntry, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	key := OutpointKey(outpoint)
	utxoBucket := dbTx.Metadata().Bucket(utxoSetBucketName)
	serializedUtxo := utxoBucket.Get(*key)
	recycleOutpointKey(key)
	if serializedUtxo == nil {
		return nil, nil
	}

	// A non-nil zero-length entry means there is an entry in the database
	// for a spent transaction output which should never be the case.
	if len(serializedUtxo) == 0 {
		return nil, AssertError(fmt.Sprintf("database contains entry "+
			"for spent tx output %v", outpoint))
	}

	// Deserialize the utxo entry and return it.
	entry, err := DeserializeUtxoEntry(serializedUtxo)
	if err != nil {
		// Ensure any deserialization errors are returned as database
		// corruption errors.
		if bccompress.IsDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt utxo entry "+
					"for %v: %v", outpoint, err),
			}
		}

		return nil, err
	}

	return entry, nil
}

// RemoveEntry removes the given transaction output from the current state of
// the view.  It will have no effect if the passed output does not exist in the
// view.
func (view *UtxoViewpoint) RemoveEntry(outpoint wire.OutPoint) {
	delete(view.entries, outpoint)
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view *UtxoViewpoint) Entries() map[wire.OutPoint]*UtxoEntry {
	return view.entries
}

// commit prunes all entries marked modified that are now fully spent and marks
// all entries as unmodified.
func (view *UtxoViewpoint) commit() {
	for outpoint, entry := range view.entries {
		if entry == nil || (entry.isModified() && entry.IsSpent()) {
			delete(view.entries, outpoint)
			continue
		}

		entry.packedFlags &^= TfModified
	}
}

// fetchUtxosMain fetches unspent transaction output data about the provided
// set of outpoints from the point of view of the end of the main chain at the
// time of the call.
//
// Upon completion of this function, the view will contain an entry for each
// requested outpoint.  Spent outputs, or those which otherwise don't exist,
// will result in a nil entry in the view.
func (view *UtxoViewpoint) FetchUtxosMain(db database.DB, outpoints map[wire.OutPoint]struct{}) error {
	// Nothing to do if there are no requested outputs.
	if len(outpoints) == 0 {
		return nil
	}

	for outpoint, _ := range outpoints {
		if _, ok := view.entries[outpoint]; ok {
			delete(outpoints, outpoint)
		}
	}

	// Load the requested set of unspent transaction outputs from the point
	// of view of the end of the main chain.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the store as a way
	// to unnecessarily avoid attempting to reload it from the database.
	return db.View(func(dbTx database.Tx) error {
		for outpoint, _ := range outpoints {
			entry, err := DbFetchUtxoEntry(dbTx, outpoint)
			if err != nil {
				return err
			}

			view.entries[outpoint] = entry
		}

		return nil
	})
}

// fetchUtxos loads the unspent transaction outputs for the provided set of
// outputs into the view from the database as needed unless they already exist
// in the view in which case they are ignored.
func (view *ViewPointSet) GetUtxo(outpoint wire.OutPoint) *UtxoEntry {
	// Already loaded into the current view.
	if _, ok := view.Utxo.entries[outpoint]; ok {
		return view.Utxo.entries[outpoint]
	}
	// Filter entries that are already in the view.
	neededSet := make(map[wire.OutPoint]struct{})
	neededSet[outpoint] = struct{}{}

	// Request the input utxos from the database.
	if view.Utxo.FetchUtxosMain(view.Db, neededSet) != nil {
		return nil
	}

	return view.Utxo.entries[outpoint]
}

// fetchInputUtxos loads the unspent transaction outputs for the inputs
// referenced by the transactions in the given block into the view from the
// database as needed.  In particular, referenced entries that are earlier in
// the block are added to the view and entries that are already in the view are
// not modified.
func (view *ViewPointSet) FetchInputUtxos(block *btcutil.Block) error {
	// Build a map of in-flight transactions because some of the inputs in
	// this block could be referencing other transactions earlier in this
	// block which are not yet in the chain.
	txInFlight := map[chainhash.Hash]int{}
	transactions := block.Transactions()
	for i, tx := range transactions {
		txInFlight[*tx.Hash()] = i
	}

	// Loop through all of the transaction inputs (except for the coinbase
	// which has no inputs) collecting them into sets of what is needed and
	// what is already known (in-flight).
	neededSet := make(map[wire.OutPoint]struct{})
	for i, tx := range transactions[1:] {
		for _, txIn := range tx.MsgTx().TxIn {
			if txIn.PreviousOutPoint.Hash.IsEqual(&zerohash) {
				continue
			}
			// It is acceptable for a transaction input to reference
			// the output of another transaction in this block only
			// if the referenced transaction comes before the
			// current one in this block.  Add the outputs of the
			// referenced transaction as available utxos when this
			// is the case.  Otherwise, the utxo details are still
			// needed.
			//
			// NOTE: The >= is correct here because i is one less
			// than the actual position of the transaction within
			// the block due to skipping the coinbase.
			originHash := &txIn.PreviousOutPoint.Hash
			if inFlightIndex, ok := txInFlight[*originHash]; ok &&
				i >= inFlightIndex {

				originTx := transactions[inFlightIndex]
				view.AddTxOuts(originTx, block.Height())
				continue
			}

			// Don't request entries that are already in the view
			// from the database.
			if _, ok := view.Utxo.entries[txIn.PreviousOutPoint]; ok {
				continue
			}

			neededSet[txIn.PreviousOutPoint] = struct{}{}
		}
	}

	// Request the input utxos from the database.
	return view.Utxo.FetchUtxosMain(view.Db, neededSet)
}

// NewUtxoViewpoint returns a new empty unspent transaction output view.
func NewUtxoViewpoint() *UtxoViewpoint {
	return &UtxoViewpoint{
		entries: make(map[wire.OutPoint]*UtxoEntry),
	}
}

// dbPutUtxoView uses an existing database transaction to update the utxo set
// in the database based on the provided utxo view contents and state.  In
// particular, only the entries that have been marked as modified are written
// to the database.
func DbPutUtxoView(dbTx database.Tx, view *UtxoViewpoint) error {
	utxoBucket := dbTx.Metadata().Bucket(utxoSetBucketName)
	for outpoint, entry := range view.entries {
		// No need to update the database if the entry was not modified.
		if entry == nil || !entry.isModified() {
			continue
		}

		// Remove the utxo entry if it is spent.
		if entry.IsSpent() {
			key := OutpointKey(outpoint)
			err := utxoBucket.Delete(*key)
			recycleOutpointKey(key)
			if err != nil {
				return err
			}

			if entry.packedFlags&TfMonitoring != 0 {
				utxoBucket.Delete(entry.monitor)
			}

			continue
		}

		// Serialize and store the utxo entry.
		serialized, err := SerializeUtxoEntry(entry)
		if err != nil {
			return err
		}
		key := OutpointKey(outpoint)
		err = utxoBucket.Put(*key, serialized)

		// NOTE: The key is intentionally not recycled here since the
		// database interface contract prohibits modifications.  It will
		// be garbage collected normally when the database is done with
		// it.
		if err != nil {
			return err
		}

		if entry.packedFlags&TfMonitoring != 0 {
			utxoBucket.Put(entry.monitor, *key)
		}
	}

	return nil
}

// SerializeUtxoEntry returns the entry serialized to a format that is suitable
// for long-term storage.  The format is described in detail above.
func SerializeUtxoEntry(entry *UtxoEntry) ([]byte, error) {
	// Spent outputs have no serialization.
	if entry.IsSpent() {
		return nil, nil
	}

	// Encode the header code.
	headerCode, err := utxoEntryHeaderCode(entry)
	if err != nil {
		return nil, err
	}

	size := bccompress.SerializeSizeVLQ(headerCode) + bccompress.SerializeSizeVLQ(entry.TokenType)
	// Calculate the size needed to serialize the entry.
	if entry.TokenType&1 == 0 {
		size += bccompress.SerializeSizeVLQ(bccompress.CompressTxOutAmount(uint64(entry.Amount.(*token.NumToken).Val)))
	} else {
		size += chainhash.HashSize
	}
	if entry.TokenType&2 == 2 {
		size += chainhash.HashSize
	}
	size += len(entry.PkScript())

	// Serialize the header code followed by the compressed unspent
	// transaction output.
	serialized := make([]byte, size)
	offset := bccompress.PutVLQ(serialized, headerCode)
	offset += bccompress.PutVLQ(serialized[offset:], entry.TokenType)
	if entry.TokenType&1 == 0 {
		offset += bccompress.PutVLQ(serialized[offset:], bccompress.CompressTxOutAmount(uint64(entry.Amount.(*token.NumToken).Val)))
	} else {
		copy(serialized[offset:], entry.Amount.(*token.HashToken).Hash[:])
		offset += chainhash.HashSize
	}
	if entry.TokenType&2 == 2 {
		//		if entry.Rights != nil {
		copy(serialized[offset:], (*entry.Rights)[:])
		//		}
		offset += chainhash.HashSize
	}
	copy(serialized[offset:], entry.PkScript())

	return serialized, nil
}

// -----------------------------------------------------------------------------
// The unspent transaction output (utxo) set consists of an entry for each
// unspent output using a format that is optimized to reduce space using domain
// specific compression algorithms.  This format is a slightly modified version
// of the format used in Bitcoin Core.
//
// Each entry is keyed by an outpoint as specified below.  It is important to
// note that the key encoding uses a VLQ, which employs an MSB encoding so
// iteration of utxos when doing byte-wise comparisons will produce them in
// order.
//
// The serialized key format is:
//   <hash><output index>
//
//   Field                Type             Size
//   hash                 chainhash.Hash   chainhash.HashSize
//   output index         VLQ              variable
//
// The serialized value format is:
//
//   <header code><compressed txout>
//
//   Field                Type     Size
//   header code          VLQ      variable
//   compressed txout
//     compressed amount  VLQ      variable
//     compressed script  []byte   variable
//
// The serialized header code format is:
//   bit 0 - containing transaction is a coinbase
//   bits 1-x - height of the block that contains the unspent txout
//
// Example 1:
// From tx in main blockchain:
// Blk 1, 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098:0
//
//    03320496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52
//    <><------------------------------------------------------------------>
//     |                                          |
//   header code                         compressed txout
//
//  - header code: 0x03 (coinbase, height 1)
//  - compressed txout:
//    - 0x32: VLQ-encoded compressed amount for 5000000000 (50 OMC)
//    - 0x04: special script type pay-to-pubkey
//    - 0x96...52: x-coordinate of the pubkey
//
// Example 2:
// From tx in main blockchain:
// Blk 113931, 4a16969aa4764dd7507fc1de7f0baa4850a246de90c45e59a3207f9a26b5036f:2
//
//    8cf316800900b8025be1b3efc63b0ad48e7f9f10e87544528d58
//    <----><------------------------------------------>
//      |                             |
//   header code             compressed txout
//
//  - header code: 0x8cf316 (not coinbase, height 113931)
//  - compressed txout:
//    - 0x8009: VLQ-encoded compressed amount for 15000000 (0.15 OMC)
//    - 0x00: special script type pay-to-pubkey-hash
//    - 0xb8...58: pubkey hash
//
// Example 3:
// From tx in main blockchain:
// Blk 338156, 1b02d1c8cfef60a189017b9a420c682cf4a0028175f2f563209e4ff61c8c3620:22
//
//    a8a2588ba5b9e763011dd46a006572d820e448e12d2bbb38640bc718e6
//    <----><-------------------------------------------------->
//      |                             |
//   header code             compressed txout
//
//  - header code: 0xa8a258 (not coinbase, height 338156)
//  - compressed txout:
//    - 0x8ba5b9e763: VLQ-encoded compressed amount for 366875659 (3.66875659 OMC)
//    - 0x01: special script type pay-to-script-hash
//    - 0x1d...e6: script hash
// -----------------------------------------------------------------------------

// utxoEntryHeaderCode returns the calculated header code to be used when
// serializing the provided utxo entry.
func utxoEntryHeaderCode(entry *UtxoEntry) (uint64, error) {
	if entry.IsSpent() {
		return 0, AssertError("attempt to serialize spent utxo header")
	}

	// As described in the serialization format comments, the header code
	// encodes the height shifted over one bit and the coinbase flag in the
	// lowest bit.
	headerCode := uint64(entry.BlockHeight()) << 1
	if entry.IsCoinBase() {
		headerCode |= 0x01
	}

	return headerCode, nil
}
