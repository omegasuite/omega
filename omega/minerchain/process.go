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
	"fmt"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcutil"
	"math/big"
//	"net"
	"time"

	"encoding/hex"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
)

/*
func (b *MinerChain) blockExistsSomewhere(hash *chainhash.Hash) (bool, error) {
	// Check block index first (could be main chain or side chain blocks).
	if b.index.HaveBlock(hash) {
		return true, nil
	}

	// Check in the database.
	var exists bool
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		exists, err = dbTx.HasBlock(hash)
		return err
	})
	return exists, err
}
*/

// blockExists determines whether a block with the given hash exists either in
// the main chain or any side chains.
//
// This function is safe for concurrent access.
func (b *MinerChain) blockExists(hash *chainhash.Hash) (bool, error) {
	// Check block index first (could be main chain or side chain blocks).
	if b.index.HaveBlock(hash) {
		return true, nil
	}

	// Check in the database.
	var exists bool
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		exists, err = dbTx.HasBlock(hash)
		if err != nil || !exists {
			return err
		}

		// Ignore side chain blocks in the database.  This is necessary
		// because there is not currently any record of the associated
		// block index data such as its block height, so it's not yet
		// possible to efficiently load the block and do anything useful
		// with it.
		//
		// Ultimately the entire block index should be serialized
		// instead of only the current main chain so it can be consulted
		// directly.
		_, err = blockchain.DbFetchHeightByHash(dbTx, hash)
		if blockchain.IsNotInMainChainErr(err) {
			exists = false
			return nil
		}
		return err
	})
	return exists, err
}

func (b *MinerChain) TryConnectOrphan(hash *chainhash.Hash) bool {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	block := b.Orphans.GetOrphanBlock(hash).(*wire.MingingRightBlock)
	n := b.index.LookupNode(&block.PrevBlock)

	if n == nil {
		return false
	}

	err,_ := b.ProcessOrphans(&block.PrevBlock, blockchain.BFNone)
	return err == nil
}

// processOrphans determines if there are any orphans which depend on the passed
// block hash (they are no longer orphans if true) and potentially accepts them.
// It repeats the process for the newly accepted blocks (to detect further
// orphans which may no longer be orphans) until there are no more.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to maybeAcceptBlock.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *MinerChain) ProcessOrphans(hash *chainhash.Hash, flags blockchain.BehaviorFlags) (error, wire.Message) {
	_, h := b.Orphans.ProcessOrphans(hash, func(processHash *chainhash.Hash, blk interface{}) (bool, wire.Message) {
		parent := b.index.LookupNode(processHash)
		block := (*wire.MinerBlock)(blk.(*orphanBlock))
		if !b.blockChain.SameChain(block.MsgBlock().BestBlock, NodetoHeader(parent).BestBlock) {
			return true, nil
		}

		if block.MsgBlock().Version&0x7FFF0000 >= chaincfg.Version2 {
			if r, _, hreq := b.checkV2(block, parent, flags); !r {
				return true, hreq
			}
		} else if len(block.MsgBlock().ViolationReport) > 0 {
			return true, nil
		}

		// Potentially accept the block into the block chain.
		_, err := b.maybeAcceptBlock(block, flags)
		return err != nil, nil
	})

	return nil, h
}

func (b *MinerChain) CheckSideChain(hash *chainhash.Hash) {
	node := b.index.LookupNode(hash)

	if node == nil {
		return
	}

	tip := b.BestChain.Tip()
	if node.Height <= tip.Height {
		return
	}

	detachNodes, attachNodes, txdetachNodes, txattachNodes := b.getReorganizeNodes(node)

	if attachNodes.Len() == 0 {
		return
	}

	// Reorganize the chain.
	log.Infof("miner REORGANIZE: Block %v is causing a reorganize. %d detached %d attaches", node.Hash, detachNodes.Len(), attachNodes.Len())
	if err := b.reorganizeChain(detachNodes, attachNodes); err != nil {
		return
	}
	if err := b.blockChain.ReorganizeChain(txdetachNodes, txattachNodes); err != nil {
		b.reorganizeChain(attachNodes, detachNodes)
		return
	}

	b.index.FlushToDB(dbStoreBlockNode)
}

func (b *MinerChain) checkV2(block *wire.MinerBlock, parent *chainutil.BlockNode, flags blockchain.BehaviorFlags) (bool, error, wire.Message) {
	// if it is in side chain, skip these tests below as they depends on chain state
	for p, i := parent, int32(0); i <= b.chainParams.ViolationReportDeadline && p != nil; i++ {
		if p.Data.GetVersion() < chaincfg.Version2 {
			break
		}
		if *block.MsgBlock().Utxos == *p.Data.(*blockchainNodeData).block.Utxos {
			// not allowed same utxo in 100 blks
			return false, fmt.Errorf("Re-use UTXO for collateral within 100 miner blocks"), nil
		}
		p = p.Parent
	}
	// check the coin for collateral exists and have correct amount
	_, err := b.blockChain.CheckCollateral(block, &block.MsgBlock().BestBlock, flags)
	if err != nil {
		return false, err, nil
	}
	/* SameChain includes test of existence
	   if have, _ := b.blockChain.HaveBlock(&block.MsgBlock().BestBlock); !have {
	   	log.Infof("BestBlock %s does not Exists ", block.MsgBlock().BestBlock.String())
	   	return false, true, nil, &block.MsgBlock().BestBlock
	   }
	*/

	for _, p := range block.MsgBlock().ViolationReport {
		for j, tb := range p.Blocks {
			if !b.blockChain.HaveNode(&tb) {
				// if we have node of the hash, it is in main chain or side chain
				// otherwise, it is missing and we need to request it
				return false, ruleError(ErrViolationReport, "Missing block in violation report"), &wire.MsgGetData{InvList: []*wire.InvVect{{common.InvTypeWitnessBlock, p.Blocks[j]}}}
			}
		}
	}
	if err := b.validateVioldationReports(block); err != nil {
		return false, err, nil
	}
	return true, nil, nil
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
func (b *MinerChain) ProcessBlock(block *wire.MinerBlock, flags blockchain.BehaviorFlags) (bool, bool, error, wire.Message) {
//	log.Infof("MinerChain.ProcessBlock: ChainLock.RLock")
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	blockHash := block.Hash()

	log.Infof("miner Block hash %s\nprevhash %s", blockHash.String(), block.MsgBlock().PrevBlock.String())

	// The block must not already exist in the main chain or side chains.
	exists := b.MainChainHasBlock(blockHash)		// index.HaveBlock(blockHash)
//	if err != nil {
//		return false, false, err, nil
//	}
	if exists {
		str := fmt.Sprintf("already have block %v", blockHash)
		return false, false, ruleError(ErrDuplicateBlock, str), nil
	}

	// The block must not already exist as an orphan.
	if !b.Orphans.CheckOrphan(blockHash, (*orphanBlock)(block)) {
		str := fmt.Sprintf("already have block (orphan) %v", blockHash)
		return false, false, ruleError(ErrDuplicateBlock, str), nil
	}

	// Perform preliminary sanity checks on the block.
	if b.chainParams.Net == common.TestNet || b.chainParams.Net == common.SimNet || b.chainParams.Net == common.RegNet {
		flags |= blockchain.BFEasyBlocks
	}

	err := CheckBlockSanity(block, b.chainParams.PowLimit, b.timeSource, flags|blockchain.BFNoPoWCheck)
	if err != nil {
		return false, false, err, nil
	}
	if len(block.MsgBlock().Connection) == 0 {
		return false, false, fmt.Errorf("Empty Connection"), nil
	}

	// Find the previous checkpoint and perform some additional checks based
	// on the checkpoint.  This provides a few nice properties such as
	// preventing old side chain blocks before the last checkpoint,
	// rejecting easy to mine, but otherwise bogus, blocks that could be
	// used to eat memory, and ensuring expected (versus claimed) proof of
	// work requirements since the previous checkpoint are met.
	blockHeader := block.MsgBlock()

	// Handle orphan blocks.
	prevHash := &blockHeader.PrevBlock

	prevHashExists := b.index.HaveBlock(prevHash)

	//	if err != nil {
	//		return false, false, err, nil
	//	}
	if !prevHashExists {
		log.Infof("block prevHash does not Exists Adding orphan block %s with parent %s", blockHash.String(), prevHash.String())
		b.Orphans.AddOrphanBlock((*orphanBlock)(block))

		return false, true, nil, &wire.MsgGetData{InvList: []*wire.InvVect{{common.InvTypeMinerBlock, *prevHash}}}
	}

	bestblk := b.blockChain.NodeByHash(&block.MsgBlock().BestBlock) //.HaveBlock(&block.MsgBlock().BestBlock)
	if bestblk == nil {
		log.Infof("best block %s does not exist", block.MsgBlock().BestBlock.String())
		return false, false, ruleError(ErrMissingBestBlock, "best block does not exist"), &wire.MsgGetData{InvList: []*wire.InvVect{{common.InvTypeWitnessBlock, block.MsgBlock().BestBlock}}}
	}
	if block.MsgBlock().Version&0x7FFF0000 >= chaincfg.Version3 && bestblk.Data.GetNonce() >= 0 && bestblk.Height > 0 {
		log.Infof("best block is not a signed block")
		return false, false, ruleError(ErrMissingBestBlock, "best block is not a signed block"), &wire.MsgGetData{InvList: []*wire.InvVect{{common.InvTypeWitnessBlock, block.MsgBlock().BestBlock}}}
	}

	parent := b.index.LookupNode(prevHash)
	if !b.blockChain.SameChain(block.MsgBlock().BestBlock, NodetoHeader(parent).BestBlock) {
		log.Infof("block and parent tx reference not in the same chain.")
		//		b.Orphans.AddOrphanBlock((*orphanBlock)(block))
		return false, false, fmt.Errorf("block and parent tx reference not in the same chain."), nil
	}

	if block.MsgBlock().Version&0x7FFF0000 >= chaincfg.Version2 {
		if r, err, hreq := b.checkV2(block, parent, flags); !r {
			return false, false, err, hreq
		}
	} else if len(block.MsgBlock().ViolationReport) > 0 {
		return false, false, fmt.Errorf("Unexpected blacklist"), nil
	}

	// the rule is new ContractLimit must not less than prev ContractLimit
	// and max ContractExec between BestBlocks of prev and this MR blocks.
	// it may not be larger than twice of the max ContractExec and prev
	// ContractLimit if that is less than chain param, it could be 0
	// implying the chain param value
	lastBlk := parent.Data.(*blockchainNodeData).block
	if block.MsgBlock().Version&0x7FFF0000 >= chaincfg.Version2 {
		contractlim := block.MsgBlock().ContractLimit
		if contractlim == 0 {
			contractlim = b.chainParams.ContractExecLimit
		}
		limita := b.blockChain.MaxContractExec(lastBlk.BestBlock, block.MsgBlock().BestBlock)
		if contractlim < limita || contractlim < lastBlk.ContractLimit*95/100 {
			return false, false, fmt.Errorf("ContractLimit is too low"), nil
		}
		if contractlim > 2*limita && contractlim > lastBlk.ContractLimit && contractlim > b.chainParams.ContractExecLimit {
			return false, false, fmt.Errorf("ContractLimit is too big"), nil
		}
	}

	// The block has passed all context independent checks and appears sane
	// enough to potentially accept it into the block chain.
	isMainChain, err := b.maybeAcceptBlock(block, flags)
	if err != nil {
		return false, false, err, nil
	}

	if isMainChain {
		b.blockChain.OnNewMinerNode()
	}

	// Accept any orphan blocks that depend on this block (they are
	// no longer orphans) and repeat for those accepted blocks until
	// there are no more.
	err, h := b.ProcessOrphans(blockHash, flags)
	if err != nil {
//		log.Infof("b.ProcessOrphans error %s", err)
		return false, false, err, h
	}

	log.Infof("miner.ProcessBlock finished with height = %d (%d) tx height = %d orphans = %d",
		b.BestSnapshot().Height, block.Height(),
		b.blockChain.BestSnapshot().Height, b.Orphans.Count())

	return isMainChain, false, nil, h
}

// checkBlockSanity performs some preliminary checks on a block to ensure it is
// sane before continuing with block processing.  These checks are context free.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to checkBlockHeaderSanity.
func CheckBlockSanity(header *wire.MinerBlock, powLimit *big.Int, timeSource chainutil.MedianTimeSource, flags blockchain.BehaviorFlags) error {
	// Ensure the proof of work bits in the block header is in min/max range
	// and the block hash is less than the target value described by the
	// bits.
	if (flags & blockchain.BFEasyBlocks) == 0 {
		err := checkProofOfWork(header.MsgBlock(), powLimit, flags)
		if err != nil {
			return err
		}
	}

	// A block timestamp must not have a greater precision than one second.
	// This check is necessary because Go time.Time values support
	// nanosecond precision whereas the consensus rules only apply to
	// seconds and it's much nicer to deal with standard Go time values
	// instead of converting to seconds everywhere.
	if !header.MsgBlock().Timestamp.Equal(time.Unix(header.MsgBlock().Timestamp.Unix(), 0)) {
		str := fmt.Sprintf("block timestamp of %v has a higher "+
			"precision than one second", header.MsgBlock().Timestamp)
		return ruleError(ErrInvalidTime, str)
	}

	// Ensure the block time is not too far in the future.
	maxTimestamp := timeSource.AdjustedTime().Add(time.Second *
		blockchain.MaxTimeOffsetSeconds)
	if header.MsgBlock().Timestamp.After(maxTimestamp) {
		str := fmt.Sprintf("block timestamp of %v is too far in the "+
			"future", header.MsgBlock().Timestamp)
		return ruleError(ErrTimeTooNew, str)
	}

	if len(header.MsgBlock().Connection) > 128 {
		return fmt.Errorf("The connect information is neither a RSA key nor an IP address",
			hex.EncodeToString(header.MsgBlock().Connection))
	}

	if header.MsgBlock().Version&0x7FFF0000 >= 0x20000 {
		k := len(header.MsgBlock().TphReports)
		if k > wire.MaxTPSReports {
			return fmt.Errorf("Reported more than max allowed TPS items")
		}
		if k < wire.MinTPSReports && header.Height() > wire.MinTPSReports {
			return fmt.Errorf("Reported less than min required TPS items")
		}
		for _, v := range header.MsgBlock().TphReports {
			if v == 0 {
				return fmt.Errorf("Reported 0 in TPS value")
			}
		}
	}
	return nil
}

// validate violation reports
// a BR block's violation report includes one or more incident reports. an incident
// is a double signing violation by a miner at one height. The evidence includes MR
// block's hash to identify the violator; a number of hashes of blacks at the height
// signed by the violator. none of the blocks may have height greater than the best
// block's. the report may or may not include blocks in the chain of best block's
// chain. miner may not report side chain blocks duplicated in previous MR block
// reports. yet the reported side chain blocks along with those in previous reports
// must form a chain extending from a fork point in the chain of best block. i.e.,
// no orphan block may be reported.
func (b *MinerChain) validateVioldationReports(block * wire.MinerBlock) error {
	// validate violation reports
	bestnode := b.blockChain.NodeByHash(&block.MsgBlock().BestBlock)

	mynode := &chainutil.BlockNode{}
	InitBlockNode(mynode, block.MsgBlock(), b.NodeByHash(&block.MsgBlock().PrevBlock))

	vb := make(map[chainhash.Hash]map[chainhash.Hash]struct{})

	hoder := int32(-1)
	for _, v := range block.MsgBlock().ViolationReport {
		mb := b.NodeByHash(&v.MRBlock)
		if v.Height < hoder {
			// ensure reports are in ascending order by height
			return fmt.Errorf("reports are not in ascending order")
		}
		hoder = v.Height
		if block.Height()-mb.Height >= b.chainParams.ViolationReportDeadline {
			return fmt.Errorf("violation report exceeds time limit")
		}
		if bestnode.Height < v.Height {
			return ruleError(ErrViolationReport, "Can not report a violation at hight higher than bestblock")
		}
		if len(v.Blocks) < 2 {
			return fmt.Errorf("A incident must include at least two blocks")
		}

		hasmainchain := false

		if _, ok := vb[v.MRBlock]; !ok {
			vb[v.MRBlock] = make(map[chainhash.Hash]struct{})
		}

		for _, h := range v.Blocks {
			if _, ok := vb[v.MRBlock][h]; ok {
				return fmt.Errorf("Duplicated violation report")
			}
			vb[v.MRBlock][h] = struct{}{}
			txb, err := b.blockChain.HashToBlock(&h)
			if err != nil {
				return err
			}
			if b.MainChainHasBlock(&h) {
				delete(vb[v.MRBlock], h)
			}
			if txb.Height() != v.Height {
				return ruleError(ErrViolationReport, "Incorrect violation report height")
			}

			signed := false
			for _, sig := range txb.MsgBlock().Transactions[0].SignatureScripts[1:] {
				signer := btcutil.Hash160(sig[:btcec.PubKeyBytesLenCompressed])
				if bytes.Compare(signer[:], mb.Data.(*blockchainNodeData).block.Miner[:]) == 0 {
					signed = true
					hash := blockchain.MakeMinerSigHash(txb.Height(), *txb.Hash())
					_, err := btcutil.VerifySigScript(sig, hash, b.blockChain.ChainParams)
					if err != nil {
						return fmt.Errorf("report violation block is not signed by the reported miner")
					}
					break
				}
			}

			if !signed {
				return fmt.Errorf("report violation block is not signed by the reported miner")
			}

			p := bestnode
			for ; p.Height > v.Height; p = b.blockChain.ParentNode(p) {
			}
			if p.Hash == h {
				// it is in the bestblock's chain
				hasmainchain = true
				continue
			}
			// it is in a side chain. either its parent is in the bestblock's chain
			// or its parent has been reported
			q := txb.MsgBlock().Header.PrevBlock
			matched := false
			if q == p.Parent.Hash {
				matched = true // keep going to check dup of h
			}
		matching:
			for j, w := int32(0), mynode; j < b.chainParams.ViolationReportDeadline; j++ {
				y := w.Data.(*blockchainNodeData).block
				if j > 0 {
					// check h is a new report
					for _, v2 := range y.ViolationReport {
						for _, h2 := range v2.Blocks {
							if h2 == h {
								return fmt.Errorf("Duplicated report")
							}
						}
					}
				}
				if !matched {
					for _, v2 := range y.ViolationReport {
						for _, h2 := range v2.Blocks {
							if h2 == q {
								matched = true
								break matching
							}
						}
					}
				}
				w = w.Parent
			}

			if !matched {
				return ruleError(ErrViolationReport, "An orphan violation is reported")
			}
			if !hasmainchain {
				return ruleError(ErrViolationReport, "The report does not contain a best chain block")
			}
		}
	}
	return nil
}
