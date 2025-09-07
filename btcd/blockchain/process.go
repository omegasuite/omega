// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"btcd/blockchain/chainutil"
	"btcd/wire"
	"btcd/wire/common"
	"fmt"
	"github.com/omegasuite/btcd/btcec"
	"time"

	"btcd/database"
	"btcutil"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
)

// BehaviorFlags is a bitmask defining tweaks to the normal behavior when
// performing chain processing and consensus rules checks.
type BehaviorFlags uint32

const (
	// BFFastAdd may be set to indicate that several checks can be avoided
	// for the block since it is already known to fit into the chain due to
	// already proving it correct links into the chain up to a known
	// checkpoint.  This is primarily used for headers-first mode.
	BFFastAdd BehaviorFlags = 1 << iota

	// BFNoPoWCheck may be set to indicate the proof of work check which
	// ensures a block hashes to a value less than the required target will
	// not be performed.
	BFNoPoWCheck

	BFAddAsOrphan

	BFSubmission

	BFNoConnect

	BFNoReorg

	BFSideChain

	BFWatingFactor

	BFAlreadyInChain

	BFEasyBlocks

	BFNoOrphan

	// BFNone is a convenience value to specifically indicate no flags.
	BFNone BehaviorFlags = 0
)

// blockExists determines whether a block with the given hash exists either in
// the main chain or any side chains.
//
// This function is safe for concurrent access.
func (b *BlockChain) blockExists(hash *chainhash.Hash) (bool, error) {
	// Check block Index first (could be main chain or side chain blocks).
	if b.Index.HaveBlock(hash) { // Index includes only the most recent blocks
		return true, nil
	}

	// Check in the database.
	var exists bool
	err := b.db.View(func(dbTx database.Tx) error {
		// if not in Index, it might still be a valid block
		bucket := dbTx.Metadata().Bucket(hashIndexBucketName)
		if bucket.Get((*hash)[:]) != nil {
			exists = true
			return nil
		}

		// it might be in cache
		var err error
		exists, err = dbTx.HasBlock(hash)
		if err != nil || !exists {
			return err
		}

		// Ignore side chain blocks in the database.  This is necessary
		// because there is not currently any record of the associated
		// block Index data such as its block height, so it's not yet
		// possible to efficiently load the block and do anything useful
		// with it.
		//
		// Ultimately the entire block Index should be serialized
		// instead of only the current main chain so it can be consulted
		// directly.
		/*
			_, err = DbFetchHeightByHash(dbTx, hash)
			if IsNotInMainChainErr(err) {
				exists = false
				return nil
			}
		*/
		return err
	})
	return exists, err
}

func (b *BlockChain) TryConnectOrphan(hash *chainhash.Hash) bool {
	b.ChainLock.Lock()
	defer b.ChainLock.Unlock()

	m := b.Orphans.GetOrphanBlock(hash)
	if m == nil {
		return true
	}

	block := m.(*wire.MsgBlock)

	n := b.NodeByHash(&block.Header.PrevBlock)
	if n == nil {
		return false
	}

	return b.ProcessOrphans(&block.Header.PrevBlock, BFNone) == nil
}

// ProcessOrphans determines if there are any Orphans which depend on the passed
// block hash (they are no longer Orphans if true) and potentially accepts them.
// It repeats the process for the newly accepted blocks (to detect further
// Orphans which may no longer be Orphans) until there are no more.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to maybeAcceptBlock.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) ProcessOrphans(hash *chainhash.Hash, flags BehaviorFlags) error {
	behaviorFlags := BFNone | BFNoOrphan
	if b.ChainParams.Net == uint32(common.TestNet) || b.ChainParams.Net == uint32(common.SimNet) || b.ChainParams.Net == uint32(common.RegNet) {
		behaviorFlags |= BFEasyBlocks
	}

	b.Orphans.ProcessOrphans(hash, func(_ *chainhash.Hash, blk interface{}) (bool, wire.Message) {
		block := (*btcutil.Block)(blk.(*orphanBlock))
		if prevNode := b.NodeByHash(&block.MsgBlock().Header.PrevBlock); prevNode != nil {
			block.SetHeight(prevNode.Height + 1)
			if !b.MatchInpool(block) {
				return false, nil
			}

			// Potentially accept the block into the block chain.
			if prevNode == b.BestChain.Tip() {
				err, mkorphan := b.checkProofOfWork(block, prevNode, b.ChainParams.PowLimit, flags|behaviorFlags)
				if err != nil || mkorphan {
					return true, nil
				}
			}

			_, err, _ := b.maybeAcceptBlock(block, flags)
			return err != nil, nil
		}
		return true, nil
	})

	return nil
}

func (b *BlockChain) OnNewMinerNode() {
	if b.Orphans.OnNewMinerNode(func(f *chainhash.Hash, r *chainhash.Hash, added bool) bool {
		if b.NodeByHash(f) != nil {
			b.ProcessOrphans(f, BFNone)
		}
		if !added && b.NodeByHash(r) != nil {
			added = true
		}
		return added
	}) {
		high := b.Index.Highest()
		b.CheckSideChain(&high.Hash)
	}
}

func (b *BlockChain) CheckSideChain(hash *chainhash.Hash) {
	node := b.NodeByHash(hash)

	if node == nil {
		return
	}

	tip := b.BestChain.Tip()
	if node.Height <= tip.Height {
		return
	}

	detachNodes, attachNodes := b.getReorganizeNodes(node)

	if detachNodes.Len() == 0 && attachNodes.Len() == 0 {
		return
	}

	// Reorganize the chain.
	b.ReorganizeChain(detachNodes, attachNodes)
	log.Infof("CheckSideChain: tx REORGANIZE: Block %v is causing a reorganize. %d detached %d attaches. New chain height = %d", node.Hash, detachNodes.Len(), attachNodes.Len(), b.BestSnapshot().Height)

	b.Index.FlushToDB(dbStoreBlockNode)
}

type orphanBlock btcutil.Block

func (b *orphanBlock) PrevBlock() *chainhash.Hash {
	return &(*btcutil.Block)(b).MsgBlock().Header.PrevBlock
}

func (b *orphanBlock) MsgBlock() wire.Message {
	return (*btcutil.Block)(b).MsgBlock()
}

func (b *orphanBlock) Hash() *chainhash.Hash {
	return (*btcutil.Block)(b).Hash()
}

func (b *orphanBlock) Removable(ob chainutil.Orphaned) bool {
	block := b.MsgBlock().(*wire.MsgBlock)
	oblock := ob.MsgBlock().(*wire.MsgBlock)
	if len(block.Transactions[0].SignatureScripts) > len(oblock.Transactions[0].SignatureScripts) {
		return true
	}
	return !oblock.Transactions[0].TxIn[0].PreviousOutPoint.Hash.IsEqual(&zeroHash)
	// refers a BTC block, we may remove it from orphan because it could be added when the BTC block was not ready
	// for regulay coinbase, this Hash is 0
}

func (b *orphanBlock) NeedUpdate(ob chainutil.Orphaned) bool {
	block := b.MsgBlock().(*wire.MsgBlock)
	if block.Header.Nonce < 0 {
		nl := len(block.Transactions[0].SignatureScripts)
		oblock := ob.MsgBlock().(*wire.MsgBlock)
		ol := len(oblock.Transactions[0].SignatureScripts)
		if nl > ol {
			return true
		} else if nl == ol {
			if len(block.Transactions[0].SignatureScripts[1]) > len(oblock.Transactions[0].SignatureScripts[1]) {
				return true
			}
		}
	}
	return false
}

func BlockToOrphan(block *btcutil.Block) chainutil.Orphaned {
	return (*orphanBlock)(block)
}

func (b *BlockChain) MatchInpool(block *btcutil.Block) bool {
	r := b.db.View(func(dbtx database.Tx) error {
		bucket := dbtx.Metadata().Bucket([]byte(common.INCOMINGPOOL))

		dxchain := make(map[wire.OutPoint]*wire.XchainData)

		for _, tx := range block.MsgBlock().Transactions[1:] {
			if !tx.IsCrossChain() { // len(tx.TxIn) != 1 || tx.TxIn[0].PreviousOutPoint.Index&wire.CrossChainFalg == 0 {
				continue
			}

			xtx := &wire.XchainData{
				ChainID:   tx.TxIn[0].PreviousOutPoint.Index &^ wire.CrossChainFalg,
				Hash:      tx.TxIn[0].PreviousOutPoint.Hash,
				Height:    int32(tx.TxIn[0].SignatureIndex),
				Txs:       []*wire.MsgXrossL2{},
				Finalized: 0,
			}

			if d, ok := dxchain[tx.TxIn[0].PreviousOutPoint]; ok {
				xtx = d
			} else {
				dxchain[tx.TxIn[0].PreviousOutPoint] = xtx
			}
			for _, txo := range tx.TxOut {
				xtx.Txs = append(xtx.Txs, &wire.MsgXrossL2{
					Utxo: wire.OutPoint{},
					Txo:  *txo,
				})
			}
		}

		for key, xchain := range dxchain {
			xtx := &wire.XchainData{}
			tntx := bucket.Get(key.ToBytes())
			if tntx == nil || len(tntx) == 0 {
				return fmt.Errorf("cross chain tx %s from %d does not exist in INCOMINGPOOL", key.Hash.String(), key.Index&^wire.CrossChainFalg)
			}
			if err := xtx.DeSerialize(tntx); err != nil || xtx.Finalized == 0 {
				return fmt.Errorf("INCOMINGPOOL deserialization error or the source block is not finalized")
			}

			for _, to := range xchain.Txs {
				matched := false
				for i, txo := range xtx.Txs {
					if txo.Txo.Match(&to.Txo) {
						matched = true
						xtx.Txs = append(xtx.Txs[:i], xtx.Txs[i+1:]...)
						break
					}
				}
				if !matched {
					return fmt.Errorf("An unknown cross chain tx")
				}
			}
		}

		return nil
	})
	return r == nil
}

// ProcessBlock is the main workhorse for handling insertion of new blocks into
// the block chain.  It includes functionality such as rejecting duplicate
// blocks, ensuring blocks follow all rules, orphan handling, and insertion into
// the block chain along with best chain selection and reorganization.
//
// When no errors occurred during processing, the first return value indicates
// whether or not the block is on the main chain and the second indicates
// whether or not the block is an orphan.
//
// This function is safe for concurrent access.
func (b *BlockChain) ProcessBlock(block *btcutil.Block, flags BehaviorFlags) (bool, bool, error, int32, *chainhash.Hash) {
	//	log.Infof("ProcessBlock: ChainLock.RLock")
	if block == nil {
		return false, false, fmt.Errorf("nil block"), -1, nil
	}
	b.ChainLock.Lock()
	defer b.ChainLock.Unlock()

	blockHash := block.Hash()

	blockHeader := &block.MsgBlock().Header
	prevHash := &blockHeader.PrevBlock
	if prevHash.IsEqual(&zerohash) { // && !blockHash.IsEqual(b.ChainParams.GenesisHash) {
		return true, false, nil, -1, nil
	}
	prevHashExists, err := b.blockExists(prevHash)
	if err != nil {
		return false, false, err, -1, nil
	}
	if !prevHashExists {
		log.Infof("block %s: prevHash block %s does not exist", block.Hash().String(), prevHash.String())
		var orp *chainhash.Hash
		orp = nil
		if flags&BFNoConnect == 0 {
			if block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index > uint32(b.BestChain.Height())+500 {
				err := fmt.Errorf("Skipping future block %s with parent %s height appear %d", block.Hash().String(), prevHash.String(), block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index)
				return false, false, err, -1, nil
			} else {
				log.Infof("Adding orphan block %s with parent %s height appear %d", block.Hash().String(), prevHash.String(), block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index)
				if flags&BFNoOrphan == 0 {
					orp = b.Orphans.AddOrphanBlock((*orphanBlock)(block))
				}
			}
		}
		return false, true, nil, -1, orp
	}

	prevNode := b.NodeByHash(prevHash)

	if prevNode == nil {
		str := fmt.Sprintf("previous block %s is unknown", prevHash)
		return false, false, ruleError(ErrPreviousBlockUnknown, str), -1, nil
	} else if b.Index.NodeStatus(prevNode).KnownInvalid() {
		str := fmt.Sprintf("previous block %s is known to be invalid", prevHash)
		return false, false, ruleError(ErrInvalidAncestorBlock, str), -1, prevHash
	}

	blockHeight := prevNode.Height + 1

	if blockHeight <= int32(b.Index.Cutoff) {
		if prevNode.Height <= 0 {
			return false, false, ruleError(ErrInvalidAncestorBlock, "Block height is in locked area"), -1, prevHash
		}
		return false, false, ruleError(ErrInvalidAncestorBlock, "Block height is in locked area"), -1, nil
	}

	block.SetHeight(blockHeight)

	if blockHeight != int32(block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index) {
		return false, false, ruleError(ErrInvalidAncestorBlock, "Block height inconsistent with ostensible height"), -1, nil
	}

	//	fastAdd := flags&BFFastAdd == BFFastAdd

	// The block must not already exist as valid in the main chain or side chains.
	exists, err := b.blockExists(blockHash)
	if err != nil {
		return false, false, err, -1, nil
	}

	if exists {
		if blockHash.IsEqual(&b.BestChain.Tip().Hash) {
			return false, false, ruleError(ErrDuplicateBlock, errorCodeStrings[ErrDuplicateBlock]), -1, nil
		}
		node := b.NodeByHash(blockHash)
		if !b.Index.NodeStatus(node).KnownInvalid() && node.Height == block.Height() {
			if block.Height() > b.BestChain.Height() {
				// do we need to reorg?
				detachNodes, attachNodes := b.getReorganizeNodes(node)

				if detachNodes.Len() == 0 && attachNodes.Len() == 1 {
					exists = false
				} else if attachNodes.Len() != 0 {
					// Reorganize the chain.
					if err = b.ReorganizeChain(detachNodes, attachNodes); err != nil {
						return false, true, err, -1, nil
					}
					if writeErr := b.Index.FlushToDB(dbStoreBlockNode); writeErr != nil {
						log.Warnf("Error flushing block Index changes to disk: %v", writeErr)
					}
				}
			}
			if exists {
				return false, false, ruleError(ErrDuplicateBlock, errorCodeStrings[ErrDuplicateBlock]), -1, nil
			}
		} // re-examine it otherwise
	}

	// The block must not already exist as an orphan.
	if !b.Orphans.CheckOrphan(blockHash, (*orphanBlock)(block)) {
		str := fmt.Sprintf("already have block (orphan) %v", blockHash)
		return false, true, ruleError(ErrDuplicateBlock, str), -1, nil
	}

	// Perform preliminary sanity checks on the block and its transactions.
	err = b.checkBlockSanity(block, b.ChainParams.PowLimit, b.timeSource, flags)
	if err != nil {
		return false, false, err, -1, nil
	}

	for _, tx := range block.MsgBlock().Transactions {
		for _, txo := range tx.TxOut {
			if !txo.IsSeparator() && txo.Crossing() {
				if txo.PkScript[0] != b.ChainParams.PubKeyHashAddrID && (txo.PkScript[24]&0x80) != 0 {
					// only PKH xfer is not allowed in layer 2 chain
					str := fmt.Sprintf("Invalid cross chain tx type in tx %s", blockHash.String())
					return false, true, ruleError(ErrDuplicateBlock, str), -1, nil
				}
			}
		}
	}

	if block.Size() > wire.MaxBlockPayload {
		str := fmt.Sprintf("serialized block is too big - got %d, "+
			"max %d", block.Size(), wire.MaxBlockPayload)
		return false, false, ruleError(ErrBlockTooBig, str), -1, nil
	}

	// Find the previous checkpoint and perform some additional checks based
	// on the checkpoint.  This provides a few nice properties such as
	// preventing old side chain blocks before the last checkpoint,
	// rejecting easy to mine, but otherwise bogus, blocks that could be
	// used to eat memory, and ensuring expected (versus claimed) proof of
	// work requirements since the previous checkpoint are met.
	checkpointNode, err := b.findPreviousCheckpoint()
	if err != nil {
		return false, false, err, -1, nil
	}
	if checkpointNode != nil {
		// Ensure the block timestamp is after the checkpoint timestamp.
		checkpointTime := time.Unix(checkpointNode.Data.TimeStamp(), 0)
		if blockHeader.Timestamp.Before(checkpointTime) {
			str := fmt.Sprintf("block %v has timestamp %v before "+
				"last checkpoint timestamp %v", blockHash,
				blockHeader.Timestamp, checkpointTime)
			return false, false, ruleError(ErrCheckpointTimeTooOld, str), -1, nil
		}
	}

	for _, tx := range block.MsgBlock().Transactions[1:] {
		for _, txo := range tx.TxOut {
			if !txo.IsSeparator() && txo.IsCrossChain() {
				if len(txo.PkScript) < 26 || !b.validCrossChainScript(txo.PkScript) {
					return false, false, fmt.Errorf("Cross chain PkScript length is less than 25b in %s", tx.TxHash().String()), -1, nil
				}
			}
		}
	}

	isMainChain := false

	if !b.IsSVP && !b.MatchInpool(block) {
		return false, true, nil, -1, nil
		//		if flags&BFNoOrphan != 0 {
		//			return false, true, nil, -1, nil
		//		}
		//		orp := b.Orphans.AddOrphanBlock((*orphanBlock)(block))
		//		return false, true, nil, -1, orp
	}

	if prevNode == b.BestChain.Tip() && flags&BFNoConnect != BFNoConnect {
		// only check proof of work if it extends the best chain. if the block
		// would cause a reorg, pow check will be done in reorg
		behaviorFlags := BFNone
		if b.ChainParams.Net == uint32(common.TestNet) || b.ChainParams.Net == uint32(common.SimNet) || b.ChainParams.Net == uint32(common.RegNet) {
			behaviorFlags |= BFEasyBlocks
		}
		err, mkorphan := b.checkProofOfWork(block, prevNode, b.ChainParams.PowLimit, flags|behaviorFlags)
		if err != nil {
			return isMainChain, true, err, -1, nil
		}
		if mkorphan {
			log.Infof("checkProofOfWork failed. Make block %s an orphan at %d", block.Hash().String(), block.Height())
			if flags&BFNoOrphan == 0 {
				orp := b.Orphans.AddOrphanBlock((*orphanBlock)(block))
				return isMainChain, true, nil, -1, orp
			}
			return false, true, nil, -1, nil
		}
	} else if prevNode != b.BestChain.Tip() {
		if flags&BFNoConnect == BFNoConnect {
			return false, false, fmt.Errorf("Prev node is not best chain tip in BFNoConnect mode"), -1, nil
		}

		switch {
		case block.MsgBlock().Header.Nonce == -1:
			if prevNode.Data.GetNonce() > -wire.MINER_RORATE_FREQ && prevNode.Data.GetNonce() < 0 {
				return isMainChain, false, fmt.Errorf("Bad nonce sequence"), -1, nil
			}

		case block.MsgBlock().Header.Nonce < -wire.MINER_RORATE_FREQ:
			if 1-wire.MINER_RORATE_FREQ != prevNode.Data.GetNonce() {
				return isMainChain, false, fmt.Errorf("Bad nonce sequence"), -1, nil
			}
		}
	}

	isMainChain, err, missing := b.maybeAcceptBlock(block, flags)

	if missing > 0 || flags&BFNoConnect == BFNoConnect {
		return false, false, err, missing, nil
	}
	if err != nil {
		return false, false, err, -1, nil
	}

	if isMainChain {
		b.Miners.ProcessOrphans(&b.Miners.BestSnapshot().Hash, BFNone)
	} else if block.MsgBlock().Header.Nonce < 0 {
		// CHECK if there is a miner violation
		// block is in side chain
		mblk, _ := b.BlockByHeight(block.Height()) //	main chain block
		if mblk != nil && mblk.MsgBlock().Header.Nonce < 0 {
			// both are signed blocks. find out double singers
			best := b.BestSnapshot()
			rotate := best.LastRotation
			for p := b.BestChain.Tip(); p != nil && p.Height != block.Height(); p = b.ParentNode(p) {
				switch {
				case p.Data.GetNonce() > 0:
					rotate -= wire.POWRotate

				case p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ:
					rotate--
				}
			}
			// examine signatures. must not have double signs
			signers := make(map[[20]byte]struct{})
			var name [20]byte
			for _, sig := range block.MsgBlock().Transactions[0].SignatureScripts[1:] {
				copy(name[:], btcutil.Hash160(sig[:btcec.PubKeyBytesLenCompressed]))
				signers[name] = struct{}{}
			}
			for _, sig := range mblk.MsgBlock().Transactions[0].SignatureScripts[1:] {
				copy(name[:], btcutil.Hash160(sig[:btcec.PubKeyBytesLenCompressed]))
				rt := rotate
				if _, ok := signers[name]; ok {
					// double signer
					mb, _ := b.Miners.BlockByHeight(int32(rt))
					for i := 0; i < wire.CommitteeSize; i++ {
						if mb.MsgBlock().Miner == name {
							b.Miners.DSReport(&wire.Violations{
								Height:  block.Height(), // Height of Tx blocks
								MRBlock: *mb.Hash(),     // the MR block of violator
								Blocks:  []chainhash.Hash{*block.Hash(), *mblk.Hash()},
							})
							break
						}
						rt--
						mb, _ = b.Miners.BlockByHeight(int32(rt))
					}
				}
			}
		}
	}

	// The block has passed all context independent checks and appears sane
	// enough to potentially accept it into the block chain.

	// Accept any orphan blocks that depend on this block (they are
	// no longer Orphans) and repeat for those accepted blocks until
	// there are no more.
	b.ProcessOrphans(blockHash, BFNone) // flags)

	net := "main"
	if b.IsSVP {
		net = "SVP"
	}
	log.Infof("%s: ProcessBlock finished with height = %d Miner height = %d Orphans = %d", net, b.BestSnapshot().Height,
		b.Miners.BestSnapshot().Height, b.Orphans.Count())

	return isMainChain, false, nil, -1, nil
}

func (b *BlockChain) consistent(block *btcutil.Block, parent *chainutil.BlockNode, nocon bool) bool {
	//	state := b.BestSnapshot()
	if block.MsgBlock().Header.Nonce <= -wire.MINER_RORATE_FREQ {
		mstate := b.Miners.BestSnapshot()
		if -block.MsgBlock().Header.Nonce-wire.MINER_RORATE_FREQ > mstate.Height {
			return false
		}
	}

	if wire.CommitteeSize == 1 || block.MsgBlock().Header.Nonce > 0 {
		return true
	}

	best := b.BestSnapshot()
	rotate := best.LastRotation
	if parent.Hash != best.Hash {
		pn := b.NodeByHash(&parent.Hash)
		fork := b.FindFork(pn)

		if fork == nil {
			return false
		}

		// parent is not the tip, go back to find correct rotation
		for p := b.BestChain.Tip(); p != nil && p != fork; p = b.ParentNode(p) {
			switch {
			case p.Data.GetNonce() > 0:
				rotate -= wire.POWRotate

			case p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ:
				rotate--
			}
		}
		for p := pn; p != nil && p != fork; p = b.ParentNode(p) {
			switch {
			case p.Data.GetNonce() > 0:
				rotate += wire.POWRotate

			case p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ:
				rotate++
			}
		}
	}

	// examine signers are in committee
	miners := make(map[[20]byte]struct{})

	for i := int32(0); i < wire.CommitteeSize; i++ {
		blk, _ := b.Miners.BlockByHeight(int32(rotate) - i)
		if blk == nil {
			return false
		}

		miners[blk.MsgBlock().Miner] = struct{}{}
	}

	if nocon {
		return true
	}

	for _, sign := range block.MsgBlock().Transactions[0].SignatureScripts[1:] {
		k, _ := btcec.ParsePubKey(sign[:btcec.PubKeyBytesLenCompressed], btcec.S256())
		pk, _ := btcutil.NewAddressPubKeyPubKey(*k, b.ChainParams)
		pk.SetFormat(btcutil.PKFCompressed)
		ppk := pk.AddressPubKeyHash()
		snr := *(ppk.Hash160())
		// is the signer in committee?
		if _, ok := miners[snr]; !ok {
			//			b.Index.RemoveNode(b.Index.LookupNode(block.Hash()))
			return false
		}
	}

	return true
}
