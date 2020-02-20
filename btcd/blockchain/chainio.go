// Copyright (c) 2015-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/btcsuite/btcd/blockchain/chainutil"
	"time"

	"github.com/btcsuite/btcd/blockchain/bccompress"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/ovm"
	"github.com/btcsuite/omega/token"
	"github.com/btcsuite/omega/viewpoint"
)

const (
	// blockHdrSize is the size of a block header.  This is simply the
	// constant from wire and is only provided here for convenience since
	// wire.MaxBlockHeaderPayload is quite long.
	blockHdrSize = wire.MaxBlockHeaderPayload

	// latestUtxoSetBucketVersion is the current version of the utxo set
	// bucket that is used to track all unspent outputs.
	latestUtxoSetBucketVersion = 2

	// latestSpendJournalBucketVersion is the current version of the spend
	// journal bucket that is used to track all spent transactions for use
	// in reorgs.
	latestSpendJournalBucketVersion = 1
)

var (
	// blockIndexBucketName is the name of the db bucket used to house to the
	// block headers and contextual information.
	blockIndexBucketName = []byte("blockheaderidx")

	// hashIndexBucketName is the name of the db bucket used to house to the
	// block hash -> block height index.
	hashIndexBucketName = []byte("hashidx")

	// heightIndexBucketName is the name of the db bucket used to house to
	// the block height -> block hash index.
	heightIndexBucketName = []byte("heightidx")

	// chainStateKeyName is the name of the db key used to store the best
	// chain state.
	chainStateKeyName = []byte("chainstate")

	// spendJournalVersionKeyName is the name of the db key used to store
	// the version of the spend journal currently in the database.
	spendJournalVersionKeyName = []byte("spendjournalversion")

	// spendJournalBucketName is the name of the db bucket used to house
	// transactions outputs that are spent in each block.
	spendJournalBucketName = []byte("spendjournal")

	// utxoSetVersionKeyName is the name of the db key used to store the
	// version of the utxo set currently in the database.
	utxoSetVersionKeyName = []byte("utxosetversion")

	// utxoSetBucketName is the name of the db bucket used to house the
	// unspent transaction output set.
	utxoSetBucketName = []byte("utxosetv2")

	// vertexSetBucketName is the name of the db bucket used to house the
	// vertex definition set.
	vertexSetBucketName = []byte("vertices")

	// borderSetBucketName is the name of the db bucket used to house the
	// border definition set.
	borderSetBucketName = []byte("borders")

	// borderChildrenSetBucketName is the name of the db bucket used to house the
	// border's children set.
//	borderChildrenSetBucketName = []byte("borderChildren")

	// morderModificationSetBucketName is the name of the db bucket from leaf border to
	// outpoint indicating consent is required when the edge is modified.
//	borderModificationSetBucketName = []byte("borderModificationRight")

	// polygonSetBucketName is the name of the db bucket used to house the
	// polygon definition set.
	polygonSetBucketName = []byte("polygons")

	// rightSetBucketName is the name of the db bucket used to house the
	// right definition set.
	rightSetBucketName = []byte("rights")

	// byteOrder is the preferred byte order used for serializing numeric
	// fields for storage in the database.
	byteOrder = binary.LittleEndian
)

// IsNotInMainChainErr returns whether or not the passed error is an
// errNotInMainChain error.
func IsNotInMainChainErr(err error) bool {
	_, ok := err.(bccompress.ErrNotInMainChain)
	return ok
}

// isDbBucketNotFoundErr returns whether or not the passed error is a
// database.Error with an error code of database.ErrBucketNotFound.
func IsDbBucketNotFoundErr(err error) bool {
	dbErr, ok := err.(database.Error)
	return ok && dbErr.ErrorCode == database.ErrBucketNotFound
}

// DbFetchVersion fetches an individual version with the given key from the
// metadata bucket.  It is primarily used to track versions on entities such as
// buckets.  It returns zero if the provided key does not exist.
func DbFetchVersion(dbTx database.Tx, key []byte) uint32 {
	serialized := dbTx.Metadata().Get(key)
	if serialized == nil {
		return 0
	}

	return byteOrder.Uint32(serialized[:])
}

func BbFetchVersion(dbTx database.Tx, key []byte) uint32 {
	return DbFetchVersion(dbTx, key)
}

// DbPutVersion uses an existing database transaction to update the provided
// key in the metadata bucket to the given version.  It is primarily used to
// track versions on entities such as buckets.
func DbPutVersion(dbTx database.Tx, key []byte, version uint32) error {
	var serialized [4]byte
	byteOrder.PutUint32(serialized[:], version)
	return dbTx.Metadata().Put(key, serialized[:])
}

// dbFetchOrCreateVersion uses an existing database transaction to attempt to
// fetch the provided key from the metadata bucket as a version and in the case
// it doesn't exist, it adds the entry with the provided default version and
// returns that.  This is useful during upgrades to automatically handle loading
// and adding version keys as necessary.
func DbFetchOrCreateVersion(dbTx database.Tx, key []byte, defaultVersion uint32) (uint32, error) {
	version := DbFetchVersion(dbTx, key)
	if version == 0 {
		version = defaultVersion
		err := DbPutVersion(dbTx, key, version)
		if err != nil {
			return 0, err
		}
	}

	return version, nil
}


// FetchUtxoEntry loads and returns the requested unspent transaction output
// from the point of view of the end of the main chain.
//
// NOTE: Requesting an output for which there is no data will NOT return an
// error.  Instead both the entry and the error will be nil.  This is done to
// allow pruning of spent transaction outputs.  In practice this means the
// caller must check if the returned entry is nil before invoking methods on it.
//
// This function is safe for concurrent access however the returned entry (if
// any) is NOT.
func (b *BlockChain) FetchUtxoEntry(outpoint wire.OutPoint) (*viewpoint.UtxoEntry, error) {
	b.ChainLock.RLock()
	defer b.ChainLock.RUnlock()

	var entry *viewpoint.UtxoEntry
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		entry, err = viewpoint.DbFetchUtxoEntry(dbTx, outpoint)
		return err
	})
	if err != nil {
		return nil, err
	}

	return entry, nil
}


func (b *BlockChain) NewViewPointSet() * viewpoint.ViewPointSet {
	return viewpoint.NewViewPointSet(b.db)
}

// -----------------------------------------------------------------------------
// The transaction spend journal consists of an entry for each block connected
// to the main chain which contains the transaction outputs the block spends
// serialized such that the order is the reverse of the order they were spent.
//
// This is required because reorganizing the chain necessarily entails
// disconnecting blocks to get back to the point of the fork which implies
// unspending all of the transaction outputs that each block previously spent.
// Since the utxo set, by definition, only contains unspent transaction outputs,
// the spent transaction outputs must be resurrected from somewhere.  There is
// more than one way this could be done, however this is the most straight
// forward method that does not require having a transaction index and unpruned
// blockchain.
//
// NOTE: This format is NOT self describing.  The additional details such as
// the number of entries (transaction inputs) are expected to come from the
// block itself and the utxo set (for legacy entries).  The rationale in doing
// this is to save space.  This is also the reason the spent outputs are
// serialized in the reverse order they are spent because later transactions are
// allowed to spend outputs from earlier ones in the same block.
//
// The reserved field below used to keep track of the version of the containing
// transaction when the height in the header code was non-zero, however the
// height is always non-zero now, but keeping the extra reserved field allows
// backwards compatibility.
//
// The serialized format is:
//
//   [<header code><reserved><compressed txout>],...
//
//   Field                Type     Size
//   header code          VLQ      variable
//   reserved             byte     1
//   compressed txout
//     compressed amount  VLQ      variable
//     compressed script  []byte   variable
//
// The serialized header code format is:
//   bit 0 - containing transaction is a coinbase
//   bits 1-x - height of the block that contains the spent txout
//
// Example 1:
// From block 170 in main blockchain.
//
//    1300320511db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c
//    <><><------------------------------------------------------------------>
//     | |                                  |
//     | reserved                  compressed txout
//    header code
//
//  - header code: 0x13 (coinbase, height 9)
//  - reserved: 0x00
//  - compressed txout 0:
//    - 0x32: VLQ-encoded compressed amount for 5000000000 (50 BTC)
//    - 0x05: special script type pay-to-pubkey
//    - 0x11...5c: x-coordinate of the pubkey
//
// Example 2:
// Adapted from block 100025 in main blockchain.
//
//    8b99700091f20f006edbc6c4d31bae9f1ccc38538a114bf42de65e868b99700086c64700b2fb57eadf61e106a100a7445a8c3f67898841ec
//    <----><><----------------------------------------------><----><><---------------------------------------------->
//     |    |                         |                        |    |                         |
//     |    reserved         compressed txout                  |    reserved         compressed txout
//    header code                                          header code
//
//  - Last spent output:
//    - header code: 0x8b9970 (not coinbase, height 100024)
//    - reserved: 0x00
//    - compressed txout:
//      - 0x91f20f: VLQ-encoded compressed amount for 34405000000 (344.05 BTC)
//      - 0x00: special script type pay-to-pubkey-hash
//      - 0x6e...86: pubkey hash
//  - Second to last spent output:
//    - header code: 0x8b9970 (not coinbase, height 100024)
//    - reserved: 0x00
//    - compressed txout:
//      - 0x86c647: VLQ-encoded compressed amount for 13761000000 (137.61 BTC)
//      - 0x00: special script type pay-to-pubkey-hash
//      - 0xb2...ec: pubkey hash
// -----------------------------------------------------------------------------

// FetchSpendJournal attempts to retrieve the spend journal, or the set of
// outputs spent for the target block. This provides a view of all the outputs
// that will be consumed once the target block is connected to the end of the
// main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) FetchSpendJournal(targetBlock *btcutil.Block) ([]viewpoint.SpentTxOut, error) {
	b.ChainLock.RLock()
	defer b.ChainLock.RUnlock()

	var spendEntries []viewpoint.SpentTxOut
	err := b.db.View(func(dbTx database.Tx) error {
		var err error

		spendEntries, err = dbFetchSpendJournalEntry(dbTx, targetBlock)
		return err
	})
	if err != nil {
		return nil, err
	}

	return spendEntries, nil
}

// spentTxOutHeaderCode returns the calculated header code to be used when
// serializing the provided stxo entry.
func spentTxOutHeaderCode(stxo *viewpoint.SpentTxOut) uint64 {
	// As described in the serialization format comments, the header code
	// encodes the height shifted over one bit and the coinbase flag in the
	// lowest bit.
	headerCode := uint64(stxo.Height) << 1
	if stxo.IsCoinBase {
		headerCode |= 0x01
	}

	return headerCode
}

// spentTxOutSerializeSize returns the number of bytes it would take to
// serialize the passed stxo according to the format described above.
func spentTxOutSerializeSize(stxo *viewpoint.SpentTxOut) int {
	size := bccompress.SerializeSizeVLQ(spentTxOutHeaderCode(stxo))
	size += bccompress.SerializeSizeVLQ(stxo.TokenType)

	if (stxo.TokenType & 1) == 0 {
		// regular token
		size += bccompress.SerializeSizeVLQ(bccompress.CompressTxOutAmount(uint64(stxo.Amount.(*token.NumToken).Val)))
	} else {
		size += chainhash.HashSize
	}

	if (stxo.TokenType & 2) == 2 {
		// with right
		size += chainhash.HashSize
	}
	size += len(stxo.PkScript)

	return size
}

// putSpentTxOut serializes the passed stxo according to the format described
// above directly into the passed target byte slice.  The target byte slice must
// be at least large enough to handle the number of bytes returned by the
// SpentTxOutSerializeSize function or it will panic.
func putSpentTxOut(target []byte, stxo *viewpoint.SpentTxOut) int {
	headerCode := spentTxOutHeaderCode(stxo)
	offset := bccompress.PutVLQ(target, headerCode)
	offset += bccompress.PutVLQ(target, stxo.TokenType)

	if (stxo.TokenType & 1) == 0 {
		// regular token
		offset += bccompress.PutVLQ(target, bccompress.CompressTxOutAmount(uint64(stxo.Amount.(*token.NumToken).Val)))
	} else {
		copy(target[offset:], stxo.Amount.(*token.HashToken).Hash[:])
		offset += chainhash.HashSize
	}

	if (stxo.TokenType & 2) == 2 {
		// with right
		copy(target[offset:], (*stxo.Rights)[:])
		offset += chainhash.HashSize
	}
	copy(target[offset:], stxo.PkScript)
	return offset + len(stxo.PkScript)
}

// decodeSpentTxOut decodes the passed serialized stxo entry, possibly followed
// by other data, into the passed stxo struct.  It returns the number of bytes
// read.
func decodeSpentTxOut(serialized []byte, stxo *viewpoint.SpentTxOut) (int, error) {
	// Ensure there are bytes to decode.
	if len(serialized) == 0 {
		return 0, bccompress.ErrDeserialize("no serialized bytes")
	}

	// Deserialize the header code.
	code, offset := bccompress.DeserializeVLQ(serialized)
	if offset >= len(serialized) {
		return offset, bccompress.ErrDeserialize("unexpected end of data after " +
			"header code")
	}

	// Decode the header code.
	//
	// Bit 0 indicates containing transaction is a coinbase.
	// Bits 1-x encode height of containing transaction.

	stxo.IsCoinBase = code&0x01 != 0
	stxo.Height = int32(code >> 1)

	code, bytesRead := bccompress.DeserializeVLQ(serialized[offset:])
	stxo.TokenType = code
	offset += bytesRead

	if (stxo.TokenType & 1) == 0 {
		// regular token
		compressedAmount, bytesRead := bccompress.DeserializeVLQ(serialized[offset:])
		amount := bccompress.DecompressTxOutAmount(compressedAmount)
		stxo.Amount = &token.NumToken {
			Val: int64(amount),
		}
		offset += bytesRead
	} else {
		stxo.Amount = &token.HashToken{}
		copy(stxo.Amount.(*token.HashToken).Hash[:], serialized[offset:offset + chainhash.HashSize])
		offset += chainhash.HashSize
	}

	if (stxo.TokenType & 2) == 2 && len(serialized) > offset {
		stxo.Rights = &chainhash.Hash{}
		copy(stxo.Rights[:], serialized[offset:offset + chainhash.HashSize])
		offset += chainhash.HashSize
	} else {
		stxo.Rights = nil
	}

	stxo.PkScript = serialized[offset:]
	return offset, nil
}

// deserializeSpendJournalEntry decodes the passed serialized byte slice into a
// slice of spent txouts according to the format described in detail above.
//
// Since the serialization format is not self describing, as noted in the
// format comments, this function also requires the transactions that spend the
// txouts.
func deserializeSpendJournalEntry(serialized []byte, txns []*wire.MsgTx) ([]viewpoint.SpentTxOut, error) {
	// Calculate the total number of stxos.
	var numStxos int
	for _, tx := range txns {
		numStxos += len(tx.TxIn)
	}

	// When a block has no spent txouts there is nothing to serialize.
	if len(serialized) == 0 {
		// Ensure the block actually has no stxos.  This should never
		// happen unless there is database corruption or an empty entry
		// erroneously made its way into the database.
		if numStxos != 0 {
			return nil, AssertError(fmt.Sprintf("mismatched spend "+
				"journal serialization - no serialization for "+
				"expected %d stxos", numStxos))
		}

		return nil, nil
	}

	// Loop backwards through all transactions so everything is read in
	// reverse order to match the serialization order.
	stxoIdx := numStxos - 1
	offset := 0
	stxos := make([]viewpoint.SpentTxOut, numStxos)
	for txIdx := len(txns) - 1; txIdx > -1; txIdx-- {
		tx := txns[txIdx]

		// Loop backwards through all of the transaction inputs and read
		// the associated stxo.
		for txInIdx := len(tx.TxIn) - 1; txInIdx > -1; txInIdx-- {
			txIn := tx.TxIn[txInIdx]
			stxo := &stxos[stxoIdx]
			stxoIdx--

			n, err := decodeSpentTxOut(serialized[offset:], stxo)
			offset += n
			if err != nil {
				return nil, bccompress.ErrDeserialize(fmt.Sprintf("unable "+
					"to decode stxo for %v: %v",
					txIn.PreviousOutPoint, err))
			}
		}
	}

	return stxos, nil
}

// serializeSpendJournalEntry serializes all of the passed spent txouts into a
// single byte slice according to the format described in detail above.
func serializeSpendJournalEntry(stxos []viewpoint.SpentTxOut) []byte {
	if len(stxos) == 0 {
		return nil
	}

	// Calculate the size needed to serialize the entire journal entry.
	var size int
	for i := range stxos {
		size += spentTxOutSerializeSize(&stxos[i])
	}
	serialized := make([]byte, size)

	// Serialize each individual stxo directly into the slice in reverse
	// order one after the other.
	var offset int
	for i := len(stxos) - 1; i > -1; i-- {
		offset += putSpentTxOut(serialized[offset:], &stxos[i])
	}

	return serialized
}

// dbFetchSpendJournalEntry fetches the spend journal entry for the passed block
// and deserializes it into a slice of spent txout entries.
//
// NOTE: Legacy entries will not have the coinbase flag or height set unless it
// was the final output spend in the containing transaction.  It is up to the
// caller to handle this properly by looking the information up in the utxo set.
func dbFetchSpendJournalEntry(dbTx database.Tx, block *btcutil.Block) ([]viewpoint.SpentTxOut, error) {
	// Exclude the coinbase transaction since it can't spend anything.
	spendBucket := dbTx.Metadata().Bucket(spendJournalBucketName)
	serialized := spendBucket.Get(block.Hash()[:])
	blockTxns := block.MsgBlock().Transactions[1:]
	stxos, err := deserializeSpendJournalEntry(serialized, blockTxns)
	if err != nil {
		// Ensure any deserialization errors are returned as database
		// corruption errors.
		if bccompress.IsDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt spend "+
					"information for %v: %v", block.Hash(),
					err),
			}
		}

		return nil, err
	}

	return stxos, nil
}

// dbPutSpendJournalEntry uses an existing database transaction to update the
// spend journal entry for the given block hash using the provided slice of
// spent txouts.   The spent txouts slice must contain an entry for every txout
// the transactions in the block spend in the order they are spent.
func dbPutSpendJournalEntry(dbTx database.Tx, blockHash *chainhash.Hash, stxos []viewpoint.SpentTxOut) error {
	spendBucket := dbTx.Metadata().Bucket(spendJournalBucketName)
	serialized := serializeSpendJournalEntry(stxos)
	return spendBucket.Put(blockHash[:], serialized)
}

// dbRemoveSpendJournalEntry uses an existing database transaction to remove the
// spend journal entry for the passed block hash.
func dbRemoveSpendJournalEntry(dbTx database.Tx, blockHash *chainhash.Hash) error {
	spendBucket := dbTx.Metadata().Bucket(spendJournalBucketName)
	return spendBucket.Delete(blockHash[:])
}

// -----------------------------------------------------------------------------
// The block index consists of two buckets with an entry for every block in the
// main chain.  One bucket is for the hash to height mapping and the other is
// for the height to hash mapping.
//
// The serialized format for values in the hash to height bucket is:
//   <height>
//
//   Field      Type     Size
//   height     uint32   4 bytes
//
// The serialized format for values in the height to hash bucket is:
//   <hash>
//
//   Field      Type             Size
//   hash       chainhash.Hash   chainhash.HashSize
// -----------------------------------------------------------------------------

// DbPutBlockIndex uses an existing database transaction to update or add the
// block index entries for the hash to height and height to hash mappings for
// the provided values.
func DbPutBlockIndex(dbTx database.Tx, hash *chainhash.Hash, height int32) error {
	// Serialize the height for use in the index entries.
	var serializedHeight [4]byte
	byteOrder.PutUint32(serializedHeight[:], uint32(height))

	// Add the block hash to height mapping to the index.
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(hashIndexBucketName)
	if err := hashIndex.Put(hash[:], serializedHeight[:]); err != nil {
		return err
	}

	// Add the block height to hash mapping to the index.
	heightIndex := meta.Bucket(heightIndexBucketName)
	return heightIndex.Put(serializedHeight[:], hash[:])
}

// DbRemoveBlockIndex uses an existing database transaction remove block index
// entries from the hash to height and height to hash mappings for the provided
// values.
func DbRemoveBlockIndex(dbTx database.Tx, hash *chainhash.Hash, height int32) error {
	// Remove the block hash to height mapping.
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(hashIndexBucketName)
	if err := hashIndex.Delete(hash[:]); err != nil {
		return err
	}

	// Remove the block height to hash mapping.
	var serializedHeight [4]byte
	byteOrder.PutUint32(serializedHeight[:], uint32(height))
	heightIndex := meta.Bucket(heightIndexBucketName)
	return heightIndex.Delete(serializedHeight[:])
}

// DbFetchHeightByHash uses an existing database transaction to retrieve the
// height for the provided hash from the index.
func DbFetchHeightByHash(dbTx database.Tx, hash *chainhash.Hash) (int32, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(hashIndexBucketName)
	serializedHeight := hashIndex.Get(hash[:])
	if serializedHeight == nil {
		str := fmt.Sprintf("block %s is not in the main chain", hash)
		return 0, bccompress.ErrNotInMainChain(str)
	}

	return int32(byteOrder.Uint32(serializedHeight)), nil
}

// DbFetchHashByHeight uses an existing database transaction to retrieve the
// hash for the provided height from the index.
func DbFetchHashByHeight(dbTx database.Tx, height int32) (*chainhash.Hash, error) {
	var serializedHeight [4]byte
	byteOrder.PutUint32(serializedHeight[:], uint32(height))

	meta := dbTx.Metadata()
	heightIndex := meta.Bucket(heightIndexBucketName)
	hashBytes := heightIndex.Get(serializedHeight[:])
	if hashBytes == nil {
		str := fmt.Sprintf("no block at height %d exists", height)
		return nil, bccompress.ErrNotInMainChain(str)
	}

	var hash chainhash.Hash
	copy(hash[:], hashBytes)
	return &hash, nil
}

// -----------------------------------------------------------------------------
// The best chain state consists of the best block hash and height, the total
// number of transactions up to and including those in the best block, and the
// accumulated work sum up to and including the best block.
//
// The serialized format is:
//
//   <block hash><block height><total txns><work sum length><work sum>
//
//   Field             Type             Size
//   block hash        chainhash.Hash   chainhash.HashSize
//   block height      uint32           4 bytes
//   total txns        uint64           8 bytes
//   work sum length   uint32           4 bytes
//   work sum          big.Int          work sum length
// -----------------------------------------------------------------------------

// bestChainState represents the data to be stored the database for the current
// best chain state.
type bestChainState struct {
	hash      chainhash.Hash
	bits      uint32
	height    uint32
	totalTxns uint64
	rotation  uint32
}

// serializeBestChainState returns the serialization of the passed block best
// chain state.  This is data to be stored in the chain state bucket.
func serializeBestChainState(state bestChainState) []byte {
	// Calculate the full size needed to serialize the chain state.
//	workSumBytes := state.workSum.Bytes()
//	workSumBytesLen := uint32(len(workSumBytes))
	serializedLen := chainhash.HashSize + 4 + 8 + 4 + 4 + 4	// + workSumBytesLen

	// Serialize the chain state.
	serializedData := make([]byte, serializedLen)
	copy(serializedData[0:chainhash.HashSize], state.hash[:])
	offset := uint32(chainhash.HashSize)
	byteOrder.PutUint32(serializedData[offset:], state.bits)
	offset += 4
	byteOrder.PutUint32(serializedData[offset:], state.height)
	offset += 4
	byteOrder.PutUint32(serializedData[offset:], state.rotation)
	offset += 4
	byteOrder.PutUint64(serializedData[offset:], state.totalTxns)
/*
	offset += 8
	byteOrder.PutUint32(serializedData[offset:], workSumBytesLen)
	offset += 4
	copy(serializedData[offset:], workSumBytes)
 */
	return serializedData[:]
}

// deserializeBestChainState deserializes the passed serialized best chain
// state.  This is data stored in the chain state bucket and is updated after
// every block is connected or disconnected form the main chain.
// block.
func deserializeBestChainState(serializedData []byte) (bestChainState, error) {
	// Ensure the serialized data has enough bytes to properly deserialize
	// the hash, height, total transactions, and work sum length.
	if len(serializedData) < chainhash.HashSize+24 {
		return bestChainState{}, database.Error{
			ErrorCode:   database.ErrCorruption,
			Description: "corrupt best chain state",
		}
	}

	state := bestChainState{}
	copy(state.hash[:], serializedData[0:chainhash.HashSize])
	offset := uint32(chainhash.HashSize)
	state.bits = byteOrder.Uint32(serializedData[offset : offset+4])
	offset += 4
	state.height = byteOrder.Uint32(serializedData[offset : offset+4])
	offset += 4
	state.rotation = byteOrder.Uint32(serializedData[offset : offset+4])
	offset += 4
	state.totalTxns = byteOrder.Uint64(serializedData[offset : offset+8])
/*
	offset += 8
	workSumBytesLen := byteOrder.Uint32(serializedData[offset : offset+4])
	offset += 4

	// Ensure the serialized data has enough bytes to deserialize the work
	// sum.
	if uint32(len(serializedData[offset:])) < workSumBytesLen {
		return bestChainState{}, database.Error{
			ErrorCode:   database.ErrCorruption,
			Description: "corrupt best chain state",
		}
	}
	workSumBytes := serializedData[offset : offset+workSumBytesLen]
	state.workSum = new(big.Int).SetBytes(workSumBytes)
*/

	return state, nil
}

// dbPutBestState uses an existing database transaction to update the best chain
// state with the given parameters.
func dbPutBestState(dbTx database.Tx, snapshot *BestState) error {
	// Serialize the current best chain state.
	serializedData := serializeBestChainState(bestChainState{
		hash:      snapshot.Hash,
		bits:	   snapshot.Bits,
		rotation:  snapshot.LastRotation,
		height:    uint32(snapshot.Height),
		totalTxns: snapshot.TotalTxns,
	})

	// Store the current best chain state into the database.
	return dbTx.Metadata().Put(chainStateKeyName, serializedData)
}

// createChainState initializes both the database and the chain state to the
// genesis block.  This includes creating the necessary buckets and inserting
// the genesis block, so it must only be called on an uninitialized database.
func (b *BlockChain) createChainState() error {
	// Create a new node from the genesis block and set it as the best node.
	genesisBlock := btcutil.NewBlock(b.chainParams.GenesisBlock)
	genesisBlock.SetHeight(0)
	header := &genesisBlock.MsgBlock().Header
	node := NewBlockNode(header, nil)
	node.Data.SetBits(b.chainParams.PowLimitBits)
	node.Status = chainutil.StatusDataStored | chainutil.StatusValid
	b.BestChain.SetTip(node)

	// Add the new node to the index which is used for faster lookups.
	b.index.AddNodeUL(node)

	// Initialize the state related to the best block.  Since it is the
	// genesis block, use its timestamp for the median time.
	numTxns := uint64(len(genesisBlock.MsgBlock().Transactions))
	blockSize := uint64(genesisBlock.MsgBlock().SerializeSize())
	blockWeight := uint64(GetBlockWeight(genesisBlock))

	// set rotation to 0 or committee size?
	b.stateSnapshot = newBestState(node, blockSize, blockWeight, numTxns,
		numTxns, time.Unix(node.Data.TimeStamp(), 0), b.chainParams.PowLimitBits, 0)

	// Create the initial the database chain state including creating the
	// necessary index buckets and inserting the genesis block.
	err := b.db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()

		var err error

		// Create the bucket that houses the block index data.
		if _, err = meta.CreateBucket(blockIndexBucketName); err != nil {
			return err
		}

		// Create the bucket that houses the chain block hash to height
		// index.
		if _, err = meta.CreateBucket(hashIndexBucketName);  err != nil {
			return err
		}

		// Create the bucket that houses the chain block height to hash
		// index.
		if _, err = meta.CreateBucket(heightIndexBucketName); err != nil {
			return err
		}

		// Create the bucket that houses the spend journal data and
		// store its version.
		if _, err = meta.CreateBucket(spendJournalBucketName); err != nil {
			return err
		}
		if err = DbPutVersion(dbTx, utxoSetVersionKeyName, latestUtxoSetBucketVersion); err != nil {
			return err
		}

		// Create the bucket that houses the utxo set and store its
		// version.  Note that the genesis block coinbase transaction is
		// intentionally not inserted here since it is not spendable by
		// consensus rules.
		if _, err = meta.CreateBucket(utxoSetBucketName); err != nil {
			return err
		}
		if err = DbPutVersion(dbTx, spendJournalVersionKeyName,	latestSpendJournalBucketVersion); err != nil {
			return err
		}

		// Create the bucket that houses the vertex hash to definition
		if _, err = meta.CreateBucket(vertexSetBucketName); err != nil {
			return err
		}

		// Create the bucket that houses the border hash to definition
		if _, err = meta.CreateBucket(borderSetBucketName); err != nil {
			return err
		}

		// Create the bucket that houses the polygon hash to definition
		_, err = meta.CreateBucket(polygonSetBucketName)
		if err != nil {
			return err
		}

		// Create the bucket that houses the right hash to definition
		if _, err = meta.CreateBucket(rightSetBucketName); err != nil {
			return err
		}

		// Save the genesis block to the block index database.
		if err = dbStoreBlockNode(dbTx, node); err != nil {
			return err
		}

		// Add the genesis block hash to height and height to hash
		// mappings to the index.
		err = DbPutBlockIndex(dbTx, &node.Hash, node.Height)
		if err != nil {
			return err
		}

		// Store the current best chain state into the database.
		if err = dbPutBestState(dbTx, b.stateSnapshot); err != nil {
			return err
		}

		// Store the initial Tx, bur not the coin base Tx.
		txs := genesisBlock.Transactions()
		views := b.NewViewPointSet()
//		views.db = &b.db
		views.SetBestHash(genesisBlock.Hash())
		if err = viewpoint.DbPutGensisTransaction(dbTx, txs[0], views); err != nil {
			return err
		}

		if err = viewpoint.DbPutGensisTransaction(dbTx, txs[1], views); err != nil {
			return err
		}

		// Store the genesis block into the database.
		return dbStoreBlock(dbTx, genesisBlock)
	})

	// Create system wallet
	ovm.CreateSysWallet(b.chainParams, b.db)

	return err
}

// initChainState attempts to load and initialize the chain state from the
// database.  When the db does not yet contain any chain state, both it and the
// chain state are initialized to the genesis block.
func (b *BlockChain) initChainState() error {
	// Determine the state of the chain database. We may need to initialize
	// everything from scratch or upgrade certain buckets.
	var initialized, hasBlockIndex bool
	err := b.db.View(func(dbTx database.Tx) error {
		initialized = dbTx.Metadata().Get(chainStateKeyName) != nil
		hasBlockIndex = dbTx.Metadata().Bucket(blockIndexBucketName) != nil
		return nil
	})
	if err != nil {
		return err
	}

	if !initialized {
		// At this point the database has not already been initialized, so
		// initialize both it and the chain state to the genesis block.
		return b.createChainState()
	}

	if !hasBlockIndex {
		panic("block index mssing")
	}

	// Attempt to load the chain state from the database.
	err = b.db.View(func(dbTx database.Tx) error {
		// Fetch the stored chain state from the database metadata.
		// When it doesn't exist, it means the database hasn't been
		// initialized for use with chain yet, so break out now to allow
		// that to happen under a writable database transaction.
		serializedData := dbTx.Metadata().Get(chainStateKeyName)
		log.Tracef("Serialized chain state: %x", serializedData)
		state, err := deserializeBestChainState(serializedData)
		if err != nil {
			return err
		}

		// Load all of the headers from the data for the known best
		// chain and construct the block index accordingly.  Since the
		// number of nodes are already known, perform a single alloc
		// for them versus a whole bunch of little ones to reduce
		// pressure on the GC.
		log.Infof("Loading block index...")

		blockIndexBucket := dbTx.Metadata().Bucket(blockIndexBucketName)

		// Determine how many blocks will be loaded into the index so we can
		// allocate the right amount.
		var blockCount int32
		cursor := blockIndexBucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			blockCount++
		}
		blockNodes := make([]chainutil.BlockNode, blockCount)

		var i int32
		var lastNode *chainutil.BlockNode
		cursor = blockIndexBucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			header, status, err := deserializeBlockRow(cursor.Value())
			if err != nil {
				return err
			}

			// Determine the parent block node. Since we iterate block headers
			// in order of height, if the blocks are mostly linear there is a
			// very good chance the previous header processed is the parent.
			var parent *chainutil.BlockNode
			if lastNode == nil {
				blockHash := header.BlockHash()
				if !blockHash.IsEqual(b.chainParams.GenesisHash) {
					return AssertError(fmt.Sprintf("initChainState: Expected "+
						"first entry in block index to be genesis block, "+
						"found %s", blockHash))
				}
			} else if header.PrevBlock == lastNode.Hash {
				// Since we iterate block headers in order of height, if the
				// blocks are mostly linear there is a very good chance the
				// previous header processed is the parent.
				parent = lastNode
			} else {
				parent = b.index.LookupNode(&header.PrevBlock)
				if parent == nil {
					return AssertError(fmt.Sprintf("initChainState: Could "+
						"not find parent for block %s", header.BlockHash()))
				}
			}

			// Initialize the block node for the block, connect it,
			// and add it to the block index.
			node := &blockNodes[i]
			InitBlockNode(node, header, parent)
			node.Status = status
			b.index.AddNodeUL(node)

			lastNode = node
			i++
		}

		// Set the best chain view to the stored best state.
		tip := b.index.LookupNode(&state.hash)
		if tip == nil {
			return AssertError(fmt.Sprintf("initChainState: cannot find "+
				"chain tip %s in block index", state.hash))
		}

		if tip.Parent == nil {
			tip.Data.SetBits(b.chainParams.PowLimitBits)
			state.bits = tip.Data.GetBits()
		}

		b.BestChain.SetTip(tip)

		// Load the raw block bytes for the best block.
		blockBytes, err := dbTx.FetchBlock(&state.hash)
		if err != nil {
			return err
		}
		var block wire.MsgBlock
		err = block.Deserialize(bytes.NewReader(blockBytes))
		if err != nil {
			return err
		}

		// As a final consistency check, we'll run through all the
		// nodes which are ancestors of the current chain tip, and mark
		// them as valid if they aren't already marked as such.  This
		// is a safe assumption as all the block before the current tip
		// are valid by definition.
		for iterNode := tip; iterNode != nil; iterNode = iterNode.Parent {
			// If this isn't already marked as valid in the index, then
			// we'll mark it as valid now to ensure consistency once
			// we're up and running.
			if !iterNode.Status.KnownValid() {
				log.Infof("Block %v (height=%v) ancestor of "+
					"chain tip not marked as valid, "+
					"upgrading to valid for consistency",
					iterNode.Hash, iterNode.Height)

				b.index.SetStatusFlags(iterNode, chainutil.StatusValid)
			}
		}

		// Initialize the state related to the best block.
		blockSize := uint64(len(blockBytes))
		blockWeight := uint64(GetBlockWeight(btcutil.NewBlock(&block)))
		numTxns := uint64(len(block.Transactions))

		tip.Data.SetBits(state.bits)
		b.stateSnapshot = newBestState(tip, blockSize, blockWeight,
			numTxns, state.totalTxns, tip.CalcPastMedianTime(), state.bits, state.rotation)

		return nil
	})
	if err != nil {
		return err
	}

	// As we might have updated the index after it was loaded, we'll
	// attempt to flush the index to the DB. This will only result in a
	// write if the elements are dirty, so it'll usually be a noop.
	return b.index.FlushToDB(dbStoreBlockNode)
}

type blockchainNodeData struct {
	// Some fields from block headers to aid in best chain selection and
	// reconstructing headers from memory.  These must be treated as
	// immutable and are intentionally ordered to avoid padding on 64-bit
	// platforms.
	Version   int32
	Bits      uint32
	Nonce     int32
	Timestamp int64
}

func (d * blockchainNodeData) GetData(s interface{}) {
	t := s.(*blockchainNodeData)
	*t = *d
}

func (d * blockchainNodeData) TimeStamp() int64 {
	return d.Timestamp
}

func (d * blockchainNodeData) GetNonce() int32 {
	return d.Nonce
}

func (d * blockchainNodeData) SetData(s interface{}) {
	t := s.(*blockchainNodeData)
	*d = *t
}

func (d * blockchainNodeData) SetBits(s uint32) {
	d.Bits = s
}

func (d * blockchainNodeData) GetBits() uint32 {
	return d.Bits
}

func (d * blockchainNodeData) GetVersion() int32 {
	return d.Version
}

// Header constructs a block header from the node and returns it.
//
// This function is safe for concurrent access.
func NodetoHeader(node *chainutil.BlockNode) wire.BlockHeader {
	// No lock is needed because all accessed fields are immutable.
	prevHash := &zeroHash
	if node.Parent != nil {
		prevHash = &node.Parent.Hash
	}
	d := node.Data.(*blockchainNodeData)
	return wire.BlockHeader{
		Version:    d.Version,
		PrevBlock:  *prevHash,
		Timestamp:  time.Unix(d.Timestamp, 0),
		Nonce:      d.Nonce,
	}
}

// InitBlockNode initializes a block node from the given header and parent node,
// calculating the Height and workSum from the respective fields on the parent.
// This function is NOT safe for concurrent access.  It must only be called when
// initially creating a node.
func InitBlockNode(node *chainutil.BlockNode, blockHeader *wire.BlockHeader, parent *chainutil.BlockNode) {
	d := blockchainNodeData {
		Version:    blockHeader.Version,
		Nonce:      blockHeader.Nonce,
		Timestamp:  blockHeader.Timestamp.Unix(),
	}
	*node = chainutil.BlockNode{
		Hash:       blockHeader.BlockHash(),
	}
	if parent != nil {
		if d.Bits == 0 {
			d.Bits = parent.Data.(*blockchainNodeData).Bits // default is same as parent
		}
		node.Parent = parent
		node.Height = parent.Height + 1
	}
	node.Data = &d
}

// newBlockNode returns a new block node for the given block header and parent
// node, calculating the Height and workSum from the respective fields on the
// parent. This function is NOT safe for concurrent access.
func NewBlockNode(blockHeader *wire.BlockHeader, parent *chainutil.BlockNode) *chainutil.BlockNode {
	var node chainutil.BlockNode
	InitBlockNode(&node, blockHeader, parent)
	return &node
}

// deserializeBlockRow parses a value in the block index bucket into a block
// header and block status bitfield.
func deserializeBlockRow(blockRow []byte) (*wire.BlockHeader, chainutil.BlockStatus, error) {
	buffer := bytes.NewReader(blockRow)

	var header wire.BlockHeader
	err := header.Deserialize(buffer)
	if err != nil {
		return nil, chainutil.StatusNone, err
	}

	statusByte, err := buffer.ReadByte()
	if err != nil {
		return nil, chainutil.StatusNone, err
	}

	return &header, chainutil.BlockStatus(statusByte), nil
}

// dbFetchHeaderByHash uses an existing database transaction to retrieve the
// block header for the provided hash.
func dbFetchHeaderByHash(dbTx database.Tx, hash *chainhash.Hash) (*wire.BlockHeader, error) {
	headerBytes, err := dbTx.FetchBlockHeader(hash)
	if err != nil {
		return nil, err
	}

	var header wire.BlockHeader
	err = header.Deserialize(bytes.NewReader(headerBytes))
	if err != nil {
		return nil, err
	}

	return &header, nil
}

// dbFetchHeaderByHeight uses an existing database transaction to retrieve the
// block header for the provided height.
func dbFetchHeaderByHeight(dbTx database.Tx, height int32) (*wire.BlockHeader, error) {
	hash, err := DbFetchHashByHeight(dbTx, height)
	if err != nil {
		return nil, err
	}

	return dbFetchHeaderByHash(dbTx, hash)
}

// dbFetchBlockByNode uses an existing database transaction to retrieve the
// raw block for the provided node, deserialize it, and return a btcutil.Block
// with the height set.
func dbFetchBlockByNode(dbTx database.Tx, node *chainutil.BlockNode) (*btcutil.Block, error) {
	// Load the raw block bytes from the database.
	blockBytes, err := dbTx.FetchBlock(&node.Hash)
	if err != nil {
		return nil, err
	}

	// Create the encapsulated block and set the height appropriately.
	block, err := btcutil.NewBlockFromBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	block.SetHeight(node.Height)

	return block, nil
}

// dbStoreBlockNode stores the block header and validation status to the block
// index bucket. This overwrites the current entry if there exists one.
func dbStoreBlockNode(dbTx database.Tx, node *chainutil.BlockNode) error {
	// Serialize block data to be stored.
	w := bytes.NewBuffer(make([]byte, 0, blockHdrSize+1))
	header := NodetoHeader(node)
	err := header.Serialize(w)
	if err != nil {
		return err
	}
	err = w.WriteByte(byte(node.Status))
	if err != nil {
		return err
	}
	value := w.Bytes()

	// Write block header data to block index bucket.
	blockIndexBucket := dbTx.Metadata().Bucket(blockIndexBucketName)
	key := BlockIndexKey(&node.Hash, uint32(node.Height))
	return blockIndexBucket.Put(key, value)
}

// dbStoreBlock stores the provided block in the database if it is not already
// there. The full block data is written to ffldb.
func dbStoreBlock(dbTx database.Tx, block *btcutil.Block) error {
	hasBlock, err := dbTx.HasBlock(block.Hash())
	if err != nil {
		return err
	}
	if hasBlock {
		return nil
	}
	return dbTx.StoreBlock(block)
}

// BlockIndexKey generates the binary key for an entry in the block index
// bucket. The key is composed of the block height encoded as a big-endian
// 32-bit unsigned int followed by the 32 byte block hash.
func BlockIndexKey(blockHash *chainhash.Hash, blockHeight uint32) []byte {
	indexKey := make([]byte, chainhash.HashSize+4)
	binary.BigEndian.PutUint32(indexKey[0:4], blockHeight)
	copy(indexKey[4:chainhash.HashSize+4], blockHash[:])
	return indexKey
}

// BlockByHeight returns the block at the given height in the main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockByHeight(blockHeight int32) (*btcutil.Block, error) {
	// Lookup the block height in the best chain.
	node := b.BestChain.NodeByHeight(blockHeight)
	if node == nil {
		str := fmt.Sprintf("no block at height %d exists", blockHeight)
		return nil, bccompress.ErrNotInMainChain(str)
	}

	// Load the block from the database and return it.
	var block *btcutil.Block
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNode(dbTx, node)
		return err
	})
	return block, err
}

// BlockByHash returns the block from the main chain with the given hash with
// the appropriate chain height set.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockByHash(hash *chainhash.Hash) (*btcutil.Block, error) {
	// Lookup the block hash in block index and ensure it is in the best
	// chain.
	node := b.index.LookupNode(hash)
	if node == nil || !b.BestChain.Contains(node) {
		str := fmt.Sprintf("block %s is not in the main chain", hash)
		return nil, bccompress.ErrNotInMainChain(str)
	}

	// Load the block from the database and return it.
	var block *btcutil.Block
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNode(dbTx, node)
		return err
	})
	return block, err
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
func (b *BlockChain) FetchBorderEntry(hash chainhash.Hash) (*viewpoint.BorderEntry, error) {
	b.ChainLock.RLock()
	defer b.ChainLock.RUnlock()

	var entry *viewpoint.BorderEntry
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		e, err := viewpoint.DbFetchBorderEntry(dbTx, &hash)
		entry = e
		return err
	})
	if err != nil {
		return nil, err
	}

	return entry, nil
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
func (b *BlockChain) FetchPolygonEntry(hash chainhash.Hash) (*viewpoint.PolygonEntry, error) {
	b.ChainLock.RLock()
	defer b.ChainLock.RUnlock()

	var entry *viewpoint.PolygonEntry
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		e, err := viewpoint.DbFetchPolygon(dbTx, &hash)
		if err != nil {
			return err
		}
		entry = &viewpoint.PolygonEntry{
			Loops: e.Loops,
//			RefCnt: e.RefCnt,
			PackedFlags: 0,
		}
		return err
	})
	if err != nil {
		return nil, err
	}

	return entry, nil
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
func (b *BlockChain) FetchRightEntry(hash chainhash.Hash) (*viewpoint.RightEntry, error) {
	b.ChainLock.RLock()
	defer b.ChainLock.RUnlock()

	var entry *viewpoint.RightEntry
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		e, err := viewpoint.DbFetchRight(dbTx, &hash)
		entry = &viewpoint.RightEntry{
			Father: e.(*viewpoint.RightEntry).Father,
			Desc:e.(*viewpoint.RightEntry).Desc,
			Attrib: e.(*viewpoint.RightEntry).Attrib,
			PackedFlags: 0,
		}
		return err
	})
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func (b *BlockChain) dbFetchVertex(blockHeight int32, tx int32, ind uint32) (*token.VertexDef, error) {
	blk,err := b.BlockByHeight(blockHeight)
	if err != nil {
		return nil, err
	}

	return blk.Transactions()[tx].MsgTx().TxDef[ind].(*token.VertexDef), nil
}


// FetchUtxoView loads unspent transaction outputs for the inputs referenced by
// the passed transaction from the point of view of the end of the main chain.
// It also attempts to fetch the utxos for the outputs of the transaction itself
// so the returned view can be examined for duplicate transactions.
//
// This function is safe for concurrent access however the returned view is NOT.
func (b *BlockChain) FetchUtxoView(tx *btcutil.Tx) (*viewpoint.UtxoViewpoint, error) {
	// Create a set of needed outputs based on those referenced by the
	// inputs of the passed transaction and the outputs of the transaction
	// itself.
	neededSet := make(map[wire.OutPoint]struct{})
	prevOut := wire.OutPoint{Hash: *tx.Hash()}
	for txOutIdx, txOut := range tx.MsgTx().TxOut {
		if txOut.TokenType == 0xFFFFFFFFFFFFFFFF {
			continue
		}
		prevOut.Index = uint32(txOutIdx)
		neededSet[prevOut] = struct{}{}
	}
	if !IsCoinBase(tx) {
		for _, txIn := range tx.MsgTx().TxIn {
			neededSet[txIn.PreviousOutPoint] = struct{}{}
		}
	}

	// Request the utxos from the point of view of the end of the main
	// chain.
	view := viewpoint.NewUtxoViewpoint()
	b.ChainLock.RLock()
	err := view.FetchUtxosMain(b.db, neededSet)
	b.ChainLock.RUnlock()
	return view, err
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
func (b *BlockChain) FetchVtxEntry(hash chainhash.Hash) (*viewpoint.VtxEntry, error) {
	b.ChainLock.RLock()
	defer b.ChainLock.RUnlock()

	var entry *viewpoint.VtxEntry
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		e, err := viewpoint.DbFetchVertexEntry(dbTx, &hash)
		if err != nil {
			return err
		}
		entry = e
		return nil
	})
	if err != nil {
		return nil, err
	}

	return entry, nil
}
