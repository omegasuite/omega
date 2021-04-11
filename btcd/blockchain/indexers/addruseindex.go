// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire/common"

	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/viewpoint"
)

const (
	// addrIndexName is the human-readable name for the index.
	addrUseIndexName = "address usage index"
)

var (
	// addrIndexKey is the key of the address index and the db bucket used
	// to house it.
	addrUseIndexKey = []byte("usebyaddridx")
)

// AddrUseIndex implements a transaction by address usage index. It is simply
// acount of address occurances by blocks
type AddrUseIndex struct {
	// The following fields are set when the instance is created and can't
	// be changed afterwards, so there is no need to protect them with a
	// separate mutex.
	db          database.DB
	chainParams *chaincfg.Params
}

// Ensure the AddrIndex type implements the Indexer interface.
var _ Indexer = (*AddrUseIndex)(nil)

// Ensure the AddrIndex type implements the NeedsInputser interface.
var _ NeedsInputser = (*AddrUseIndex)(nil)

// NeedsInputs signals that the index requires the referenced inputs in order
// to properly create the index.
//
// This implements the NeedsInputser interface.
func (idx *AddrUseIndex) NeedsInputs() bool {
	return true
}

// BlockInit is only provided to satisfy the Indexer interface as there is nothing to
// initialize for this index.
//
// This is part of the Indexer interface.
func (idx *AddrUseIndex) Init() error {
	// Nothing to do.
	return nil
}

// Key returns the database key to use for the index as a byte slice.
//
// This is part of the Indexer interface.
func (idx *AddrUseIndex) Key() []byte {
	return addrUseIndexKey
}

// Name returns the human-readable name of the index.
//
// This is part of the Indexer interface.
func (idx *AddrUseIndex) Name() string {
	return addrUseIndexName
}

// Create is invoked when the indexer manager determines the index needs
// to be created for the first time.  It creates the bucket for the address
// index.
//
// This is part of the Indexer interface.
func (idx *AddrUseIndex) Create(dbTx database.Tx) error {
	_, err := dbTx.Metadata().CreateBucket(addrUseIndexKey)
	return err
}
func (idx *AddrUseIndex) keyList(block *btcutil.Block,
	stxos []viewpoint.SpentTxOut) map[[addrKeySize]byte]struct{} {
	if block.MsgBlock().Header.Version < wire.Version2 {
		return nil
	}

	umap := make(map[[addrKeySize]byte]struct{})
	for _, txIdxs := range stxos {
		addrs, _, err := ExtractPkScriptAddrs(txIdxs.PkScript, idx.chainParams)
		if err != nil || len(addrs) == 0 {
			continue
		}

		for _, addr := range addrs {
			addrKey, err := AddrToKey(addr)
			if err != nil {
				continue
			}
			umap[addrKey] = struct{}{}
		}
	}
	return umap
}

// ConnectBlock is invoked by the index manager when a new block has been
// connected to the main chain.  This indexer adds a mapping for each address
// the transactions in the block involve.
//
// This is part of the Indexer interface.
func (idx *AddrUseIndex) ConnectBlock(dbTx database.Tx, block *btcutil.Block,
	stxos []viewpoint.SpentTxOut) error {
	keys := idx.keyList(block, stxos)

	addrIdxBucket := dbTx.Metadata().Bucket(addrUseIndexKey)
	for addrKey, _ := range keys {
		k := addrIdxBucket.Get(addrKey[:])
		kv := uint32(0)
		if k != nil {
			kv = common.LittleEndian.Uint32(k)
		}
		kv++
		var r [4]byte
		common.LittleEndian.PutUint32(r[:], kv)
		addrIdxBucket.Put(addrKey[:], r[:])
	}

	return nil
}

// DisconnectBlock is invoked by the index manager when a block has been
// disconnected from the main chain.  This indexer removes the address mappings
// each transaction in the block involve.
//
// This is part of the Indexer interface.
func (idx *AddrUseIndex) DisconnectBlock(dbTx database.Tx, block *btcutil.Block,
	stxos []viewpoint.SpentTxOut) error {
	keys := idx.keyList(block, stxos)

	addrIdxBucket := dbTx.Metadata().Bucket(addrUseIndexKey)
	for addrKey, _ := range keys {
		k := addrIdxBucket.Get(addrKey[:])
		if k == nil {
			// error. ignored.
			continue
		}
		kv := common.LittleEndian.Uint32(k) - 1
		common.LittleEndian.PutUint32(k, kv)
		addrIdxBucket.Put(addrKey[:], k)
	}

	return nil
}

func (idx *AddrUseIndex) Usage(address btcutil.Address) uint32 {
	addrKey, err := AddrToKey(address)
	if err != nil {
		return 0
	}

	var r uint32

	idx.db.View(func (tx database.Tx) error {
		addrIdxBucket := tx.Metadata().Bucket(addrUseIndexKey)
		k := addrIdxBucket.Get(addrKey[:])
		if k == nil {
			return nil
		}
		r = common.LittleEndian.Uint32(k)
		return nil
	})
	return r
}

func (idx *AddrUseIndex) Snap2V2() {
	// this index is effective only for version 2
	idx.db.Update(func(dbTx database.Tx) error {
		// ad hoc getting best state to avoid circular importation
		chainStateKeyName := []byte("chainstate")
		serializedData := dbTx.Metadata().Get(chainStateKeyName)
		if serializedData == nil {
			return nil
		}
		var hash chainhash.Hash
		copy(hash[:], serializedData[0:chainhash.HashSize])
		height := int32(common.LittleEndian.Uint32(serializedData[chainhash.HashSize+4:]))

		h,_ := blockchain.DbFetchHeaderByHash(dbTx, &hash)
		if h.Version < wire.Version2 {
			// snap IndexerTip to best state
			dbPutIndexerTip(dbTx, addrUseIndexKey, &hash, height)
		}
		return nil
	})
}

// NewAddrIndex returns a new instance of an indexer that is used to create a
// mapping of all addresses in the blockchain to the respective transactions
// that involve them.
//
// It implements the Indexer interface which plugs into the IndexManager that in
// turn is used by the blockchain package.  This allows the index to be
// seamlessly maintained along with the chain.
func NewAddrUseIndex(db database.DB, chainParams *chaincfg.Params) *AddrUseIndex {
	return &AddrUseIndex{
		db:          db,
		chainParams: chainParams,
	}
}
