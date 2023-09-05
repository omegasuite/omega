/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package minerchain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/blockchain/bccompress"
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
)

const (
	// blockHdrSize is the size of a block header.  This is simply the
	// constant from wire and is only provided here for convenience since
	// wire.MaxBlockHeaderPayload is quite long.
	blockHdrSize = wire.MaxMinerBlockHeaderPayload
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

	// TphReportsName is the name of the db key used to reports of tph.
	TphReportsName = []byte("tphreports")

	// byteOrder is the preferred byte order used for serializing numeric
	// fields for storage in the database.
	byteOrder = binary.LittleEndian
)

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
	hash   chainhash.Hash
	height uint32
}

// serializeBestChainState returns the serialization of the passed block best
// chain state.  This is data to be stored in the chain state bucket.
func serializeBestChainState(state bestChainState) []byte {
	// Calculate the full size needed to serialize the chain state.
	serializedLen := chainhash.HashSize + 4

	// Serialize the chain state.
	serializedData := make([]byte, serializedLen)
	copy(serializedData[0:chainhash.HashSize], state.hash[:])
	offset := uint32(chainhash.HashSize)
	byteOrder.PutUint32(serializedData[offset:], state.height)

	return serializedData[:]
}

// deserializeBestChainState deserializes the passed serialized best chain
// state.  This is data stored in the chain state bucket and is updated after
// every block is connected or disconnected form the main chain.
// block.
func deserializeBestChainState(serializedData []byte) (bestChainState, error) {
	// Ensure the serialized data has enough bytes to properly deserialize
	// the hash, height, total transactions, and work sum length.
	if len(serializedData) < chainhash.HashSize+4 {
		return bestChainState{}, database.Error{
			ErrorCode:   database.ErrCorruption,
			Description: "corrupt best chain state",
		}
	}

	state := bestChainState{}
	copy(state.hash[:], serializedData[0:chainhash.HashSize])
	offset := uint32(chainhash.HashSize)
	state.height = byteOrder.Uint32(serializedData[offset : offset+4])

	return state, nil
}

// dbPutBestState uses an existing database transaction to update the best chain
// state with the given parameters.
func dbPutBestState(dbTx database.Tx, snapshot *blockchain.BestState) error {
	// Serialize the current best chain state.
	serializedData := serializeBestChainState(bestChainState{
		hash:   snapshot.Hash,
		height: uint32(snapshot.Height),
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
	node := NewBlockNode(header, nil)
	node.Status = chainutil.StatusDataStored | chainutil.StatusValid
	b.BestChain.SetTip(node)

	// Add the new node to the index which is used for faster lookups.
	b.index.AddNodeUL(node)

	// Initialize the state related to the best block.  Since it is the
	// genesis block, use its timestamp for the median time.
	b.stateSnapshot = newBestState(node, time.Unix(node.Data.TimeStamp(), 0))

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
		if _, err = meta.CreateBucket(hashIndexBucketName); err != nil {
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

		// Create the bucket that houses the tph reports.
		if _, err = meta.CreateBucket(TphReportsName); err != nil {
			return err
		}

		// Save the genesis block to the block index database.
		if err = dbStoreBlockNode(dbTx, node); err != nil {
			return err
		}

		// Add the genesis block hash to height and height to hash
		// mappings to the index.
		err = blockchain.DbPutBlockIndex(dbTx, &node.Hash, node.Height)
		if err != nil {
			return err
		}

		// Store the current best chain state into the database.
		if err = dbPutBestState(dbTx, b.stateSnapshot); err != nil {
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
	var initialized, hasBlockIndex, hasTphReports bool
	err := b.db.View(func(dbTx database.Tx) error {
		initialized = dbTx.Metadata().Get(chainStateKeyName) != nil
		hasBlockIndex = dbTx.Metadata().Bucket(blockIndexBucketName) != nil
		hasTphReports = dbTx.Metadata().Bucket(TphReportsName) != nil
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
	if !hasTphReports {
		err := b.db.Update(func(dbTx database.Tx) error {
			if _, err = dbTx.Metadata().CreateBucket(TphReportsName); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Attempt to load the chain state from the database.
	exec := func(dbTx database.Tx) error {
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
				blockHash := header.Hash()
				if !blockHash.IsEqual(b.chainParams.GenesisMinerHash) {
					return AssertError(fmt.Sprintf("initChainState: Expected "+
						"first entry in block index to be genesis block, "+
						"found %s", blockHash))
				}
			} else if header.MsgBlock().PrevBlock == lastNode.Hash {
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
			InitBlockNode(node, header.MsgBlock(), parent)

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
		for iterNode := tip; iterNode != nil; iterNode = iterNode.Parent {
			// If this isn't already marked as valid in the index, then
			// we'll mark it as valid now to ensure consistency once
			// we're up and running.
			if !iterNode.Status.KnownValid() {
				/*
					log.Infof("Block %v (height=%v) ancestor of "+
						"chain tip not marked as valid, "+
						"upgrading to valid for consistency",
						iterNode.hash, iterNode.height)
				*/
				b.index.SetStatusFlags(iterNode, chainutil.StatusValid)
			}

		}
		// Initialize the state related to the best block.
		b.stateSnapshot = newBestState(tip, tip.CalcPastMedianTime())

		return nil
	}

	err = b.db.View(exec)

	if err != nil {
		return err
	}

	// As we might have updated the index after it was loaded, we'll
	// attempt to flush the index to the DB. This will only result in a
	// write if the elements are dirty, so it'll usually be a noop.
	return b.index.FlushToDB(dbStoreBlockNode)
}

// deserializeBlockRow parses a value in the block index bucket into a block
// header and block status bitfield.
func deserializeBlockRow(blockRow []byte) (*wire.MinerBlock, chainutil.BlockStatus, error) {
	buffer := bytes.NewReader(blockRow)

	var header wire.MingingRightBlock
	err := header.Deserialize(buffer)
	if err != nil {
		return nil, chainutil.StatusNone, err
	}

	statusByte, err := buffer.ReadByte()
	if err != nil {
		// make sure we get the last byte
		buffer.UnreadByte()
		statusByte, err = buffer.ReadByte()
		if err != nil {
			return nil, chainutil.StatusNone, err
		}
	}

	return wire.NewMinerBlock(&header), chainutil.BlockStatus(statusByte), nil
}

// dbFetchBlockByNode uses an existing database transaction to retrieve the
// raw block for the provided node, deserialize it, and return a btcutil.Block
// with the height set.
func dbFetchBlockByNode(dbTx database.Tx, node *chainutil.BlockNode) (*wire.MinerBlock, error) {
	// Load the raw block bytes from the database.
	blockBytes, err := dbTx.FetchBlock(&node.Hash)
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
	key := blockchain.BlockIndexKey(&node.Hash, uint32(node.Height))
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

// BlockByHeight returns the block at the given height in the main chain.
//
// This function is safe for concurrent access.
func (b *MinerChain) BlockByHeight(blockHeight int32) (*wire.MinerBlock, error) {
	// Lookup the block height in the best chain.
	node := b.BestChain.NodeByHeight(blockHeight)
	if node == nil {
		str := fmt.Sprintf("no miner block at height %d exists", blockHeight)
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

func (b *MinerChain) AnyBlockByHash(hash *chainhash.Hash) (*wire.MinerBlock, error) {
	// Lookup the block hash in block index and ensure it is in the best
	// chain.
	node := b.index.LookupNode(hash)
	if node == nil {
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

func (b *MinerChain) DBBlockByHash(hash *chainhash.Hash) (*wire.MinerBlock, error) {
	// Lookup the block hash in block index and ensure it is in the best
	// chain.
	node := b.index.LookupNode(hash)
	if node == nil {
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

func (b *MinerChain) NodeByHash(hash *chainhash.Hash) *chainutil.BlockNode {
	node := b.index.LookupNode(hash)
	if node == nil || !b.BestChain.Contains(node) {
		return nil
	}
	return node
}

func (b *MinerChain) DeepNodeByHash(hash *chainhash.Hash) *chainutil.BlockNode {
	node := b.index.LookupNode(hash)
	if node != nil {
		return node
	}

	blk, err := b.DBBlockByHash(hash)

	if blk == nil || err != nil {
		return nil
	}

	node = &chainutil.BlockNode{}

	InitBlockNode(node, blk.MsgBlock(), nil)

	return node
}
