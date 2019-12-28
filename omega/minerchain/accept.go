// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package minerchain

import (
	"fmt"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
	"math"
	"math/big"
)

const powScaleFactor = 1.2		// the pow scale factor when the number of miner candidate is more than DESIRABLE_MINER_CANDIDATES

// maybeAcceptBlock potentially accepts a block into the miner chain and, if
// accepted, returns whether or not it is on the main chain.  It performs
// several validation checks which depend on its position within the miner chain
// before adding it.  The block is expected to have already gone through
// ProcessBlock before calling this function with it.
//
// The flags are also passed to checkBlockContext and connectBestChain.  See
// their documentation for how the flags modify their behavior.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *MinerChain) maybeAcceptBlock(block *wire.MinerBlock, flags blockchain.BehaviorFlags) (bool, error) {
	// The height of this block is one more than the referenced previous
	// block.
	prevHash := &block.MsgBlock().PrevBlock
	prevNode := b.index.LookupNode(prevHash)
	if prevNode == nil {
		str := fmt.Sprintf("previous block %s is unknown", prevHash)
		return false, ruleError(ErrPreviousBlockUnknown, str)
	} else if b.index.NodeStatus(prevNode).KnownInvalid() {
		str := fmt.Sprintf("previous block %s is known to be invalid", prevHash)
		return false, ruleError(ErrInvalidAncestorBlock, str)
	}

	blockHeight := prevNode.height + 1
	block.SetHeight(blockHeight)

	// The block must pass all of the validation rules which depend on the
	// position of the block within the block chain.
	err := b.checkBlockContext(block, prevNode, flags)
	if err != nil {
		return false, err
	}

	// Insert the block into the database if it's not already there.  Even
	// though it is possible the block will ultimately fail to connect, it
	// has already passed all proof-of-work and validity tests which means
	// it would be prohibitively expensive for an attacker to fill up the
	// disk with a bunch of blocks that fail to connect.  This is necessary
	// since it allows block download to be decoupled from the much more
	// expensive connection logic.  It also has some other nice properties
	// such as making blocks that never become part of the main chain or
	// blocks that fail to connect available for further analysis.
	err = b.db.Update(func(dbTx database.Tx) error {
		return dbStoreMinerBlock(dbTx, block)
	})
	if err != nil {
		return false, err
	}

	// Create a new block node for the block and add it to the node index. Even
	// if the block ultimately gets connected to the main chain, it starts out
	// on a side chain.
	blockHeader := block.MsgBlock()
	newNode := newBlockNode(blockHeader, prevNode)
	newNode.status = statusDataStored

	b.index.AddNode(newNode)
	err = b.index.flushToDB()
	if err != nil {
		return false, err
	}

	// Connect the passed block to the chain while respecting proper chain
	// selection according to the chain with the most proof of work.  This
	// also handles validation of the transaction scripts.
	isMainChain, err := b.connectBestChain(newNode, block, flags)
	if err != nil {
		return false, err
	}

	// Notify the caller that the new block was accepted into the block
	// chain.  The caller would typically want to react by relaying the
	// inventory to other peers.
	b.chainLock.Unlock()
	b.sendNotification(blockchain.NTBlockAccepted, block)
	b.chainLock.Lock()

	return isMainChain, nil
}

// dbStoreBlock stores the provided block in the database if it is not already
// there. The full block data is written to ffldb.
func dbStoreMinerBlock(dbTx database.Tx, block *wire.MinerBlock) error {
	h := block.Hash()
	hasBlock, err := dbTx.HasBlock(h)
	if err != nil {
		return err
	}
	if hasBlock {
		return nil
	}
	return dbTx.StoreMinerBlock(block)
}

// checkProofOfWork ensures the block header bits which indicate the target
// difficulty is in min/max range and that the block hash is less than the
// target difficulty as claimed.
//
// The flags modify the behavior of this function as follows:
//  - BFNoPoWCheck: The check to ensure the block hash is less than the target
//    difficulty is not performed.
func (m *MinerChain) checkProofOfWork(header *wire.NewNodeBlock, powLimit *big.Int, flags blockchain.BehaviorFlags) error {
	// The target difficulty must be larger than zero.
	target := CompactToBig(header.Bits)
	if target.Sign() <= 0 {
		str := fmt.Sprintf("block target difficulty of %064x is too low",
			target)
		return ruleError(ErrUnexpectedDifficulty, str)
	}

	// The target difficulty must be less than the maximum allowed.
	if target.Cmp(powLimit) > 0 {
		str := fmt.Sprintf("block target difficulty of %064x is "+
			"higher than max of %064x", target, powLimit)
		return ruleError(ErrUnexpectedDifficulty, str)
	}

	// The block hash must be less than the claimed target unless the flag
	// to avoid proof of work checks is set.
	if flags&blockchain.BFNoPoWCheck != blockchain.BFNoPoWCheck {
		// The block hash must be less than the claimed target.
		hash := header.BlockHash()
		hashNum := HashToBig(&hash)

		factor := m.factorPOW(m.index.LookupNode(&header.PrevBlock))
		if factor != nil {
			hashNum = hashNum.Mul(hashNum, factor)
			hashNum = hashNum.Div(hashNum, big.NewInt(1024))
		}
		if hashNum.Cmp(target) > 0 {
			str := fmt.Sprintf("block hash of %064x is higher than "+
				"expected max of %064x", hashNum, target)
			return ruleError(ErrHighHash, str)
		}
	}

	return nil
}

func (m *MinerChain) factorPOW(firstNode *blockNode) *big.Int {
//	h0 := firstNode.Header().BestBlock
	baseh := uint32(firstNode.height)

	h := m.blockChain.BestSnapshot().LastRotation	// .LastRotation(h0)
	if h == 0 {
		return nil
	}

	d := uint32(baseh) - h
	factor := float64(1024.0)
	if d > wire.DESIRABLE_MINER_CANDIDATES {
		factor *= math.Pow(powScaleFactor, float64(d - wire.DESIRABLE_MINER_CANDIDATES))
	}
	return big.NewInt(int64(factor))
}

// checkBlockContext peforms several validation checks on the block which depend
// on its position within the block chain.
//
// The flags modify the behavior of this function as follows:
//  - BFFastAdd: The transaction are not checked to see if they are finalized
//    and the somewhat expensive BIP0034 validation is not performed.
//
// The flags are also passed to checkBlockHeaderContext.  See its documentation
// for how the flags modify its behavior.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *MinerChain) checkBlockContext(block *wire.MinerBlock, prevNode *blockNode, flags blockchain.BehaviorFlags) error {
	fastAdd := flags&blockchain.BFFastAdd == blockchain.BFFastAdd

	if fastAdd {
		return nil
	}

	header := block.MsgBlock()

	// Ensure the difficulty specified in the block header matches
	// the calculated difficulty based on the previous block and
	// difficulty retarget rules.
	expectedDifficulty, err := b.calcNextRequiredDifficulty(prevNode, header.Timestamp)
	if err != nil {
		return err
	}

	blockDifficulty := header.Bits
	if blockDifficulty != expectedDifficulty {
		str := "block difficulty of %d is not the expected value of %d"
		str = fmt.Sprintf(str, blockDifficulty, expectedDifficulty)
		return ruleError(ErrUnexpectedDifficulty, str)
	}

	// Ensure the timestamp for the block header is after the
	// median time of the last several blocks (medianTimeBlocks).
	medianTime := prevNode.CalcPastMedianTime()
	if !header.Timestamp.After(medianTime) {
		str := "block timestamp of %v is not after expected %v"
		str = fmt.Sprintf(str, header.Timestamp, medianTime)
		return ruleError(ErrTimeTooOld, str)
	}

	// the following condition must be met before NewNodeBlock may be accepted
	// hash of: PrevBlock + ReferredBlock + BestBlock + Newnode + Nonce must be within Bits Difficulty target, which is
	// set periodically according to NewNodeBlock chain data. The target is to set based on the number of miner
	// candidates as decided by the height of NewNodeBlock chain and the height of NewNodeBlock referred by
	// latest committee in main chain upto ReferredBlock. If this is below MINER_RORATE_FREQ, the difficulty
	// is set to generate 2 NewNodeBlock every MINER_RORATE_FREQ block time. Once number of miner candidates reaches
	// MINER_RORATE_FREQ, the difficulty increases 20% for every one more candidate.

	if err := b.checkProofOfWork(header, b.chainParams.PowLimit, flags); err != nil {
		return err
	}

	refh,_ := b.blockChain.BlockHeightByHash(&header.ReferredBlock)
	best,_ := b.blockChain.BlockHeightByHash(&header.BestBlock)
	prev := b.index.LookupNode(&header.PrevBlock)
	phd := prev.Header().ReferredBlock
	prevh,_ := b.blockChain.BlockHeightByHash(&phd)
	phd = prev.Header().BestBlock
	pbh,_ := b.blockChain.BlockHeightByHash(&phd)

	if refh < prevh || 2 * refh > (best + prevh) || best < pbh {
		str := "referred main chain block height of %d is not in proper range [%d, %d]"
		str = fmt.Sprintf(str, refh, prevh, best)
		return ruleError(ErrTimeTooOld, str)
	}

	if best < pbh {
		str := "referred main chain best block height of %d is less that previous"
		str = fmt.Sprintf(str, best)
		return ruleError(ErrTimeTooOld, str)
	}

	return nil
}


// CheckConnectBlockTemplate fully validates that connecting the passed block to
// the main chain does not violate any consensus rules, aside from the proof of
// work requirement. The block must connect to the current tip of the main chain.
//
// This function is safe for concurrent access.
func (b *MinerChain) CheckConnectBlockTemplate(block *wire.MinerBlock) error {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	// Skip the proof of work check as this is just a block template.
	flags := blockchain.BFNoPoWCheck

	// This only checks whether the block can be connected to the tip of the
	// current chain.
	tip := b.BestChain.Tip()
	header := block.MsgBlock()
	if tip.hash != header.PrevBlock {
		str := fmt.Sprintf("previous block must be the current chain tip %v, "+
			"instead got %v", tip.hash, header.PrevBlock)
		return ruleError(ErrPrevBlockNotBest, str)
	}

	err := checkBlockSanity(block, b.chainParams.PowLimit, b.timeSource, flags)
	if err != nil {
		return err
	}

	return b.checkBlockContext(block, tip, flags)
}