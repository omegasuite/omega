// Copyright (c) 2015-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package minerchain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/blockchain/bccompress"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
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

	// BlacklistKeyName is the name of the db key used to store the blacklist.
	BlacklistKeyName = []byte("blacklist")

	// byteOrder is the preferred byte order used for serializing numeric
	// fields for storage in the database.
	byteOrder = binary.LittleEndian
)

// isNotInMainChainErr returns whether or not the passed error is an
// errNotInMainChain error.
func isNotInMainChainErr(err error) bool {
	_, ok := err.(bccompress.ErrNotInMainChain)
	return ok
}

// isDbBucketNotFoundErr returns whether or not the passed error is a
// database.Error with an error code of database.ErrBucketNotFound.
func isDbBucketNotFoundErr(err error) bool {
	dbErr, ok := err.(database.Error)
	return ok && dbErr.ErrorCode == database.ErrBucketNotFound
}

// dbFetchVersion fetches an individual version with the given key from the
// metadata bucket.  It is primarily used to track versions on entities such as
// buckets.  It returns zero if the provided key does not exist.
func dbFetchVersion(dbTx database.Tx, key []byte) uint32 {
	serialized := dbTx.Metadata().Get(key)
	if serialized == nil {
		return 0
	}

	return byteOrder.Uint32(serialized[:])
}

func BbFetchVersion(dbTx database.Tx, key []byte) uint32 {
	return dbFetchVersion(dbTx, key)
}

// dbPutVersion uses an existing database transaction to update the provided
// key in the metadata bucket to the given version.  It is primarily used to
// track versions on entities such as buckets.
func dbPutVersion(dbTx database.Tx, key []byte, version uint32) error {
	var serialized [4]byte
	byteOrder.PutUint32(serialized[:], version)
	return dbTx.Metadata().Put(key, serialized[:])
}

// dbFetchOrCreateVersion uses an existing database transaction to attempt to
// fetch the provided key from the metadata bucket as a version and in the case
// it doesn't exist, it adds the entry with the provided default version and
// returns that.  This is useful during upgrades to automatically handle loading
// and adding version keys as necessary.
func dbFetchOrCreateVersion(dbTx database.Tx, key []byte, defaultVersion uint32) (uint32, error) {
	version := dbFetchVersion(dbTx, key)
	if version == 0 {
		version = defaultVersion
		err := dbPutVersion(dbTx, key, version)
		if err != nil {
			return 0, err
		}
	}

	return version, nil
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

// dbPutBlockIndex uses an existing database transaction to update or add the
// block index entries for the hash to height and height to hash mappings for
// the provided values.
func dbPutBlockIndex(dbTx database.Tx, hash *chainhash.Hash, height int32) error {
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

// dbRemoveBlockIndex uses an existing database transaction remove block index
// entries from the hash to height and height to hash mappings for the provided
// values.
func dbRemoveBlockIndex(dbTx database.Tx, hash *chainhash.Hash, height int32) error {
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

// dbFetchHeightByHash uses an existing database transaction to retrieve the
// height for the provided hash from the index.
func dbFetchHeightByHash(dbTx database.Tx, hash *chainhash.Hash) (int32, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(hashIndexBucketName)
	serializedHeight := hashIndex.Get(hash[:])
	if serializedHeight == nil {
		str := fmt.Sprintf("block %s is not in the main chain", hash)
		return 0, bccompress.ErrNotInMainChain(str)
	}

	return int32(byteOrder.Uint32(serializedHeight)), nil
}

// dbFetchHashByHeight uses an existing database transaction to retrieve the
// hash for the provided height from the index.
func dbFetchHashByHeight(dbTx database.Tx, height int32) (*chainhash.Hash, error) {
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
	height    uint32
	workSum   *big.Int
}

// serializeBestChainState returns the serialization of the passed block best
// chain state.  This is data to be stored in the chain state bucket.
func serializeBestChainState(state bestChainState) []byte {
	// Calculate the full size needed to serialize the chain state.
	workSumBytes := state.workSum.Bytes()
	workSumBytesLen := uint32(len(workSumBytes))
	serializedLen := chainhash.HashSize + 4 + 4 + workSumBytesLen

	// Serialize the chain state.
	serializedData := make([]byte, serializedLen)
	copy(serializedData[0:chainhash.HashSize], state.hash[:])
	offset := uint32(chainhash.HashSize)
	byteOrder.PutUint32(serializedData[offset:], state.height)
	offset += 4
	byteOrder.PutUint32(serializedData[offset:], workSumBytesLen)
	offset += 4
	copy(serializedData[offset:], workSumBytes)
	return serializedData[:]
}

// deserializeBestChainState deserializes the passed serialized best chain
// state.  This is data stored in the chain state bucket and is updated after
// every block is connected or disconnected form the main chain.
// block.
func deserializeBestChainState(serializedData []byte) (bestChainState, error) {
	// Ensure the serialized data has enough bytes to properly deserialize
	// the hash, height, total transactions, and work sum length.
	if len(serializedData) < chainhash.HashSize+8 {
		return bestChainState{}, database.Error{
			ErrorCode:   database.ErrCorruption,
			Description: "corrupt best chain state",
		}
	}

	state := bestChainState{}
	copy(state.hash[:], serializedData[0:chainhash.HashSize])
	offset := uint32(chainhash.HashSize)
	state.height = byteOrder.Uint32(serializedData[offset : offset+4])
	offset += 4
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

	return state, nil
}

// dbPutBestState uses an existing database transaction to update the best chain
// state with the given parameters.
func dbPutBestState(dbTx database.Tx, snapshot *blockchain.BestState, workSum *big.Int) error {
	// Serialize the current best chain state.
	serializedData := serializeBestChainState(bestChainState{
		hash:      snapshot.Hash,
		height:    uint32(snapshot.Height),
		workSum:   workSum,
	})

	// Store the current best chain state into the database.
	return dbTx.Metadata().Put(chainStateKeyName, serializedData)
}

// createChainState initializes both the database and the chain state to the
// genesis block.  This includes creating the necessary buckets and inserting
// the genesis block, so it must only be called on an uninitialized database.
func (b *MinerChain) createChainState() error {
	// Create a new node from the genesis block and set it as the best node.
	genesisBlock := wire.NewMinerBlock(b.chainParams.GenesisMinerBlock)
	genesisBlock.SetHeight(0)
	header := genesisBlock.MsgBlock()
	node := newBlockNode(header, nil)
	node.status = statusDataStored | statusValid
	b.BestChain.SetTip(node)

	// Add the new node to the index which is used for faster lookups.
	b.index.addNode(node)

	// Initialize the state related to the best block.  Since it is the
	// genesis block, use its timestamp for the median time.
	b.stateSnapshot = newBestState(node, time.Unix(node.block.Timestamp.Unix(), 0))

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

		// Create the bucket that houses the blacklist.
		if _, err = meta.CreateBucket(BlacklistKeyName); err != nil {
			return err
		}

		// Save the genesis block to the block index database.
		if err = dbStoreBlockNode(dbTx, node); err != nil {
			return err
		}

		// Add the genesis block hash to height and height to hash
		// mappings to the index.
		err = dbPutBlockIndex(dbTx, &node.hash, node.height)
		if err != nil {
			return err
		}

		// Store the current best chain state into the database.
		if err = dbPutBestState(dbTx, b.stateSnapshot, node.workSum); err != nil {
			return err
		}

		// Store the genesis block into the database.
		return dbStoreBlock(dbTx, genesisBlock)
	})

	return err
}

// initChainState attempts to load and initialize the chain state from the
// database.  When the db does not yet contain any chain state, both it and the
// chain state are initialized to the genesis block.
func (b *MinerChain) initChainState() error {
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
//		log.Tracef("Serialized chain state: %x", serializedData)
		state, err := deserializeBestChainState(serializedData)
		if err != nil {
			return err
		}

		// Load all of the headers from the data for the known best
		// chain and construct the block index accordingly.  Since the
		// number of nodes are already known, perform a single alloc
		// for them versus a whole bunch of little ones to reduce
		// pressure on the GC.
//		log.Infof("Loading block index...")

		blockIndexBucket := dbTx.Metadata().Bucket(blockIndexBucketName)

		// Determine how many blocks will be loaded into the index so we can
		// allocate the right amount.
		var blockCount int32
		cursor := blockIndexBucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			blockCount++
		}
		blockNodes := make([]blockNode, blockCount)

		var i int32
		var lastNode *blockNode
		cursor = blockIndexBucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			header, status, err := deserializeBlockRow(cursor.Value())
			if err != nil {
				return err
			}

			// Determine the parent block node. Since we iterate block headers
			// in order of height, if the blocks are mostly linear there is a
			// very good chance the previous header processed is the parent.
			var parent *blockNode
			if lastNode == nil {
				blockHash := header.Hash()
				if !blockHash.IsEqual(b.chainParams.GenesisMinerHash) {
					return AssertError(fmt.Sprintf("initChainState: Expected "+
						"first entry in block index to be genesis block, "+
						"found %s", blockHash))
				}
			} else if header.MsgBlock().PrevBlock == lastNode.hash {
				// Since we iterate block headers in order of height, if the
				// blocks are mostly linear there is a very good chance the
				// previous header processed is the parent.
				parent = lastNode
			} else {
				parent = b.index.LookupNode(&header.MsgBlock().PrevBlock)
				if parent == nil {
					return AssertError(fmt.Sprintf("initChainState: Could "+
						"not find parent for block %s", header.MsgBlock().BlockHash()))
				}
			}

			// Initialize the block node for the block, connect it,
			// and add it to the block index.
			node := &blockNodes[i]
			initBlockNode(node, header.MsgBlock(), parent)
			node.status = status
			b.index.addNode(node)

			lastNode = node
			i++
		}

		// Set the best chain view to the stored best state.
		tip := b.index.LookupNode(&state.hash)
		if tip == nil {
			return AssertError(fmt.Sprintf("initChainState: cannot find "+
				"chain tip %s in block index", state.hash))
		}
		b.BestChain.SetTip(tip)

		// Load the raw block bytes for the best block.
		blockBytes, err := dbTx.FetchBlock(&state.hash)
		if err != nil {
			return err
		}
		var block wire.MingingRightBlock
		err = block.Deserialize(bytes.NewReader(blockBytes))
		if err != nil {
			return err
		}

		// As a final consistency check, we'll run through all the
		// nodes which are ancestors of the current chain tip, and mark
		// them as valid if they aren't already marked as such.  This
		// is a safe assumption as all the block before the current tip
		// are valid by definition.
		for iterNode := tip; iterNode != nil; iterNode = iterNode.parent {
			// If this isn't already marked as valid in the index, then
			// we'll mark it as valid now to ensure consistency once
			// we're up and running.
			if !iterNode.status.KnownValid() {
/*
				log.Infof("Block %v (height=%v) ancestor of "+
					"chain tip not marked as valid, "+
					"upgrading to valid for consistency",
					iterNode.hash, iterNode.height)
*/
				b.index.SetStatusFlags(iterNode, statusValid)
			}
		}

		// Initialize the state related to the best block.
		b.stateSnapshot = newBestState(tip, tip.CalcPastMedianTime())

		return nil
	})
	if err != nil {
		return err
	}

	// As we might have updated the index after it was loaded, we'll
	// attempt to flush the index to the DB. This will only result in a
	// write if the elements are dirty, so it'll usually be a noop.
	return b.index.flushToDB()
}

// deserializeBlockRow parses a value in the block index bucket into a block
// header and block status bitfield.
func deserializeBlockRow(blockRow []byte) (*wire.MinerBlock, blockStatus, error) {
	buffer := bytes.NewReader(blockRow)

	var header wire.MingingRightBlock
	err := header.Deserialize(buffer)
	if err != nil {
		return nil, statusNone, err
	}

	statusByte, err := buffer.ReadByte()
	if err != nil {
		return nil, statusNone, err
	}

	return wire.NewMinerBlock(&header), blockStatus(statusByte), nil
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
	hash, err := dbFetchHashByHeight(dbTx, height)
	if err != nil {
		return nil, err
	}

	return dbFetchHeaderByHash(dbTx, hash)
}

// dbFetchBlockByNode uses an existing database transaction to retrieve the
// raw block for the provided node, deserialize it, and return a btcutil.Block
// with the height set.
func dbFetchBlockByNode(dbTx database.Tx, node *blockNode) (*wire.MinerBlock, error) {
	// Load the raw block bytes from the database.
	blockBytes, err := dbTx.FetchBlock(&node.hash)
	if err != nil {
		return nil, err
	}

	// Create the encapsulated block and set the height appropriately.
	nd := wire.MingingRightBlock{}
	buffer := bytes.NewReader(blockBytes)
	nd.Deserialize(buffer)
	block := wire.NewMinerBlock(&nd)

	if err != nil {
		return nil, err
	}
	block.SetHeight(node.height)

	return block, nil
}

// dbStoreBlockNode stores the block header and validation status to the block
// index bucket. This overwrites the current entry if there exists one.
func dbStoreBlockNode(dbTx database.Tx, node *blockNode) error {
	// Serialize block data to be stored.
	w := bytes.NewBuffer(make([]byte, 0, blockHdrSize+1))
	header := node.Header()
	err := header.Serialize(w)
	if err != nil {
		return err
	}
	err = w.WriteByte(byte(node.status))
	if err != nil {
		return err
	}
	value := w.Bytes()

	// Write block header data to block index bucket.
	blockIndexBucket := dbTx.Metadata().Bucket(blockIndexBucketName)
	key := blockIndexKey(&node.hash, uint32(node.height))
	return blockIndexBucket.Put(key, value)
}

// dbStoreBlock stores the provided block in the database if it is not already
// there. The full block data is written to ffldb.
func dbStoreBlock(dbTx database.Tx, block *wire.MinerBlock) error {
	h := block.MsgBlock().BlockHash()
	hasBlock, err := dbTx.HasBlock(&h)
	if err != nil {
		return err
	}
	if hasBlock {
		return nil
	}
	return dbTx.StoreMinerBlock(block)
}

// blockIndexKey generates the binary key for an entry in the block index
// bucket. The key is composed of the block height encoded as a big-endian
// 32-bit unsigned int followed by the 32 byte block hash.
func blockIndexKey(blockHash *chainhash.Hash, blockHeight uint32) []byte {
	indexKey := make([]byte, chainhash.HashSize+4)
	binary.BigEndian.PutUint32(indexKey[0:4], blockHeight)
	copy(indexKey[4:chainhash.HashSize+4], blockHash[:])
	return indexKey
}

// BlockByHeight returns the block at the given height in the main chain.
//
// This function is safe for concurrent access.
func (b *MinerChain) BlockByHeight(blockHeight int32) (*wire.MinerBlock, error) {
	// Lookup the block height in the best chain.
	node := b.BestChain.NodeByHeight(blockHeight)
	if node == nil {
		str := fmt.Sprintf("no block at height %d exists", blockHeight)
		return nil, bccompress.ErrNotInMainChain(str)
	}

	// Load the block from the database and return it.
	var block *wire.MinerBlock
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
func (b *MinerChain) BlockByHash(hash *chainhash.Hash) (*wire.MinerBlock, error) {
	// Lookup the block hash in block index and ensure it is in the best
	// chain.
	node := b.index.LookupNode(hash)
	if node == nil || !b.BestChain.Contains(node) {
		str := fmt.Sprintf("block %s is not in the main chain", hash)
		return nil, bccompress.ErrNotInMainChain(str)
	}

	// Load the block from the database and return it.
	var block *wire.MinerBlock
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNode(dbTx, node)
		return err
	})
	return block, err
}
