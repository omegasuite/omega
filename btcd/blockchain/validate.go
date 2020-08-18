// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/omega/ovm"
	"math"
	"math/big"
	"time"

	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/token"
	//	"sort"
	"github.com/omegasuite/omega/validate"
	"github.com/omegasuite/omega/viewpoint"
)

const (
	// MaxTimeOffsetSeconds is the maximum number of seconds a block time
	// is allowed to be ahead of the current time.  This is currently 2
	// hours.
	MaxTimeOffsetSeconds = 2 * 60 * 60

	// baseSubsidy is the starting subsidy amount for mined blocks.  This
	// value is halved every SubsidyHalvingInterval blocks.
	baseSubsidy = 6 * btcutil.SatoshiPerBitcoin
)

var (
	// zeroHash is the zero value for a chainhash.Hash and is defined as
	// a package level variable to avoid the need to create a new instance
	// every time a check is needed.
	zeroHash chainhash.Hash
)

// isNullOutpoint determines whether or not a previous transaction output point
// is set.
func isNullOutpoint(outpoint *wire.OutPoint) bool {
	if outpoint.Hash == zeroHash {	// outpoint.Index == math.MaxUint32 &&
		return true
	}
	return false
}

// IsCoinBaseTx determines whether or not a transaction is a coinbase.  A coinbase
// is a special transaction created by miners that has no inputs.  This is
// represented in the block chain by a transaction with a single input that has
// a previous output transaction index set to the maximum value along with a
// zero hash.
//
// This function only differs from IsCoinBase in that it works with a raw wire
// transaction as opposed to a higher level util transaction.
func IsCoinBaseTx(msgTx *wire.MsgTx) bool {
	// A coin base must only have one transaction input.
	if len(msgTx.TxIn) != 1 {
		return false
	}

	// The previous output of a coin base must have a max value index and
	// a zero hash.
	prevOut := &msgTx.TxIn[0].PreviousOutPoint
	if prevOut.Hash != zeroHash {		// prevOut.Index != math.MaxUint32 ||
		return false
	}

	if len(msgTx.TxDef) != 0 {
		return false
	}

	for _,to := range msgTx.TxOut {
		if to.TokenType != 0 {
			return false
		}
	}

	return true
}

// IsCoinBase determines whether or not a transaction is a coinbase.  A coinbase
// is a special transaction created by miners that has no inputs.  This is
// represented in the block chain by a transaction with a single input that has
// a previous output transaction index set to the maximum value along with a
// zero hash.
//
// This function only differs from IsCoinBaseTx in that it works with a higher
// level util transaction as opposed to a raw wire transaction.
func IsCoinBase(tx *btcutil.Tx) bool {
	return tx.IsCoinBase()
}

// SequenceLockActive determines if a transaction's sequence locks have been
// met, meaning that all the inputs of a given transaction have reached a
// height or time sufficient for their relative lock-time maturity.
func SequenceLockActive(sequenceLock *SequenceLock, blockHeight int32,
	medianTimePast time.Time) bool {

	// If either the seconds, or height relative-lock time has not yet
	// reached, then the transaction is not yet mature according to its
	// sequence locks.
	if sequenceLock.Seconds >= medianTimePast.Unix() ||
		sequenceLock.BlockHeight >= blockHeight {
		return false
	}

	return true
}

const (
	// LockTimeThreshold is the number below which a lock time is
	// interpreted to be a block number.  Since an average of one block
	// is generated per 10 minutes, this allows blocks for about 9,512
	// years.
	LockTimeThreshold = 5e8 // Tue Nov 5 00:53:20 1985 UTC
)

// IsFinalizedTransaction determines whether or not a transaction is finalized.
func IsFinalizedTransaction(tx *btcutil.Tx, blockHeight int32, blockTime time.Time) bool {
	msgTx := tx.MsgTx()

	// Lock time of zero means the transaction is finalized.
	lockTime := msgTx.LockTime
	if lockTime == 0 {
		return true
	}

	// The lock time field of a transaction is either a block height at
	// which the transaction is finalized or a timestamp depending on if the
	// value is before the txscript.LockTimeThreshold.  When it is under the
	// threshold it is a block height.
	blockTimeOrHeight := int64(0)
	if lockTime < LockTimeThreshold {
		blockTimeOrHeight = int64(blockHeight)
	} else {
		blockTimeOrHeight = blockTime.Unix()
	}
	if int64(lockTime) < blockTimeOrHeight {
		return true
	}

	// At this point, the transaction's lock time hasn't occurred yet, but
	// the transaction might still be finalized if the sequence number
	// for all transaction inputs is maxed out.
	for _, txIn := range msgTx.TxIn {
		if txIn.IsSeparator() {
			continue
		}
		if txIn.Sequence != math.MaxUint32 {
			return false
		}
	}
	return true
}

// CalcBlockSubsidy returns the subsidy amount a block at the provided height
// should have. This is mainly used for determining how much the coinbase for
// newly generated blocks awards as well as validating the coinbase for blocks
// has the expected value.
//
// The subsidy is halved every SubsidyReductionInterval blocks.  Mathematically
// this is: baseSubsidy / 2^(height/SubsidyReductionInterval)
//
// At the target block generation rate for the main network, this is
// approximately every 4 years.
func CalcBlockSubsidy(height int32, chainParams *chaincfg.Params, prevPows uint) int64 {
	if chainParams.SubsidyReductionInterval == 0 {
		return baseSubsidy
	}

	// Equivalent to: baseSubsidy / 2^(height/subsidyHalvingInterval)
	return baseSubsidy >> (prevPows + uint(height/chainParams.SubsidyReductionInterval))
}

// CheckTransactionSanity performs some preliminary checks on a transaction to
// ensure it is sane.  These checks are context free.
func CheckTransactionSanity(tx *btcutil.Tx) error {
	// A transaction must have at least one input.
	msgTx := tx.MsgTx()
	if len(msgTx.TxIn) == 0 {
		// coin base Tx has len = 1
		return ruleError(ErrNoTxInputs, "transaction has no inputs")
	}

	// A transaction must have at least one output.
	if len(msgTx.TxOut) == 0 {
		return ruleError(ErrNoTxOutputs, "transaction has no outputs")
	}

	// Ensure the transaction amounts are in range.  Each transaction
	// output must not be negative or more than the max allowed per
	// transaction.  Also, the total of all outputs must abide by the same
	// restrictions.
	totals := make(map[uint64]int64)
	for _, txOut := range msgTx.TxOut {
		if txOut.IsSeparator() || !txOut.IsNumeric() {
			// ignore those none numeric tokens here
			continue
		}
		v := txOut.Value.(*token.NumToken)
		satoshi := v.Val
		if satoshi < 0 {
			str := fmt.Sprintf("transaction output has negative "+
				"value of %v", satoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
		if satoshi > btcutil.MaxSatoshi {
			str := fmt.Sprintf("transaction output value of %v is "+
				"higher than max allowed value of %v", satoshi,
				btcutil.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}

		// Two's complement int64 overflow guarantees that any overflow
		// is detected and reported.  This is impossible for Bitcoin, but
		// perhaps possible if an alt increases the total money supply.
		if _,ok := totals[txOut.TokenType]; ok {
			totals[txOut.TokenType] += satoshi
		} else {
			totals[txOut.TokenType] = satoshi
		}

		if totals[txOut.TokenType] < 0 {
			str := fmt.Sprintf("total value of all transaction "+
				"outputs exceeds max allowed value of %v",
				btcutil.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
		if totals[txOut.TokenType] > btcutil.MaxSatoshi {
			str := fmt.Sprintf("total value of all transaction "+
				"outputs is %v which is higher than max "+
				"allowed value of %v", totals[txOut.TokenType],
				btcutil.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
	}

	if err := validate.CheckDefinitions(msgTx); err != nil {
		return err
	}

	// Check for duplicate transaction inputs.
	existingTxOut := make(map[wire.OutPoint]struct{})
	for _, txIn := range msgTx.TxIn {
		if txIn.IsSeparator() {
			continue
		}
		if _, exists := existingTxOut[txIn.PreviousOutPoint]; exists {
			return ruleError(ErrDuplicateTxInputs, "transaction "+
				"contains duplicate inputs")
		}
		existingTxOut[txIn.PreviousOutPoint] = struct{}{}
	}

	// Coinbase script length must be between min and max length.
	if !IsCoinBase(tx) {
		// Previous transaction outputs referenced by the inputs to this
		// transaction must not be null.
		for _, txIn := range msgTx.TxIn {
			if txIn.IsSeparator() {
				continue
			}
			if isNullOutpoint(&txIn.PreviousOutPoint) {
				return ruleError(ErrBadTxInput, "transaction "+
					"input refers to previous output that "+
					"is null")
			}
		}
	}

	return nil
}

func (b * BlockChain) Rotation(hash chainhash.Hash) int32 {
	best := b.BestSnapshot()
	rotate := int32(best.LastRotation)
	p := b.NodeByHash(&best.Hash)
	if p.Height > best.Height {
		return -1
	}
	for ; p != nil && !p.Hash.IsEqual(&hash); p = p.Parent {
		switch {
		case p.Data.GetNonce() > 0:
			rotate -= wire.POWRotate

		case p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ:
			rotate = -(p.Data.GetNonce() + wire.MINER_RORATE_FREQ) - 1
		}
	}
	if p == nil {
		return -1
	}
	return int32(rotate)
}

// checkProofOfWork ensures the block header bits which indicate the target
// difficulty is in min/max range and that the block hash is less than the
// target difficulty as claimed.
//
// The flags modify the behavior of this function as follows:
//  - BFNoPoWCheck: The check to ensure the block hash is less than the target
//    difficulty is not performed.

// if return value is nil,false, the block is ok. if nil,true, it may be added as orphan
// but can not be connected. if err,_, it is a bad block and should be discarded
func (b *BlockChain) checkProofOfWork(block *btcutil.Block, parent * chainutil.BlockNode, powLimit *big.Int, flags BehaviorFlags) (error, bool) {
	best := b.BestSnapshot()
	bits := best.Bits
	rotate := best.LastRotation
	header := &block.MsgBlock().Header

	if parent.Hash != best.Hash {
		pn := b.index.LookupNode(&parent.Hash)
		fork := b.BestChain.FindFork(pn)

		if fork == nil {
			return nil, true
		}

		// parent is not the tip, go back to find correct rotation
		for p := b.BestChain.Tip(); p != nil && p != fork; p = p.Parent {
			switch {
			case p.Data.GetNonce() > 0:
				rotate -= wire.POWRotate

			case p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ:
				rotate--
			}
		}
		for p := pn; p != nil && p != fork; p = p.Parent {
			switch {
			case p.Data.GetNonce() > 0:
				rotate += wire.POWRotate

			case p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ:
				rotate++
			}
		}
	}

	if header.Nonce > 0 {
		// The target difficulty must be larger than zero.
		target := CompactToBig(bits)
		if target.Sign() <= 0 {
			str := fmt.Sprintf("block target difficulty of %064x is too low",
				target)
			return ruleError(ErrUnexpectedDifficulty, str), false
		}

		// The target difficulty must be less than the maximum allowed.
		if target.Cmp(powLimit) > 0 {
			str := fmt.Sprintf("block target difficulty of %064x is "+
				"higher than max of %064x", target, powLimit)
			return ruleError(ErrUnexpectedDifficulty, str), false
		}

		// The block hash must be less than the claimed target unless the flag
		// to avoid proof of work checks is set.
		if flags&BFNoPoWCheck != BFNoPoWCheck {
			// The block hash must be less than the claimed target.
			hash := header.BlockHash()
			hashNum := HashToBig(&hash)
			target = target.Mul(target, big.NewInt(wire.DifficultyRatio))
			if hashNum.Cmp(target) > 0 {
				str := fmt.Sprintf("block hash of %064x is higher than "+
					"expected max of %064x", hashNum, target)
				return ruleError(ErrHighHash, str), false
			}
		}
	} else {
		if parent != nil {
			// examine nonce
			if parent.Data.GetNonce() > 0 {
				// if previous block was a POW block, this block must be either a POW block, or a rotate
				// block that phase out all the previous committee members
				if header.Nonce != -1 { // - int32(rotate + wire.MINER_RORATE_FREQ + 1) {
					//				str := fmt.Sprintf("The previous block was a POW block, this block must be either a POW block, or a rotate block that phase out all the previous committee members.")
					return fmt.Errorf("The previous block was a POW block, this block must be either a POW block, or a rotate block that phase out all the previous committee members."), true
					// ruleError(ErrHighHash, str)
				}
			} else {
				switch {
				case parent.Data.GetNonce() == -wire.MINER_RORATE_FREQ+1:
					// this is a rotation block, nonce must be -(height of next Miner block)
					if header.Nonce != - int32(rotate+1+wire.MINER_RORATE_FREQ) {
						//					str := fmt.Sprintf("The this is a rotation block, nonce %d must be height of next Miner block %d.", -header.Nonce, rotate + 1 + wire.MINER_RORATE_FREQ)
						return fmt.Errorf("The this is a rotation block, nonce %d must be height of next Miner block %d.", -header.Nonce, rotate+1+wire.MINER_RORATE_FREQ), true
						// ruleError(ErrHighHash, str)
					}

				case parent.Data.GetNonce() <= -wire.MINER_RORATE_FREQ:
					// previous block is a rotation block, this block none must be -1
					if header.Nonce != -1 {
						//					str := fmt.Sprintf("Previous block is a rotation block, this block nonce must be -1.")
						return fmt.Errorf("Previous block is a rotation block, this block nonce must be -1."), true
					}

				default:
					if header.Nonce != parent.Data.GetNonce()-1 {
						// if parent.Nonce < 0 && header.Nonce != -((-parent.Nonce + 1) % ROT) { error }
						//					str := fmt.Sprintf("The previous block is a block in a series, this block must be the next in the series (%d vs. %d).", header.Nonce, parent.nonce)
						return fmt.Errorf("The previous block is a block in a series, this block must be the next in the series (%d vs. %d).", header.Nonce, parent.Data.GetNonce()), true
					}
				}
			}
		} else {
			return nil, true
		}

		if wire.CommitteeSize > 1 && flags&(BFNoConnect|BFSubmission) != 0 {
			return fmt.Errorf("Unexpected flags"), true
		}

		if len(block.MsgBlock().Transactions[0].SignatureScripts) <= wire.CommitteeSigs {
			return fmt.Errorf("Insufficient signature"), false
		}
		if len(block.MsgBlock().Transactions[0].SignatureScripts[1]) < btcec.PubKeyBytesLenCompressed {
			return fmt.Errorf("Incorrect signature"), false
		}

		_,awd := block.MsgBlock().Transactions[0].TxOut[0].Value.Value()
		for _, txo := range block.MsgBlock().Transactions[0].TxOut {
			if txo.IsSeparator() {
				break
			}
			if txo.TokenType != 0 {
				return fmt.Errorf("Coinbase output tokentype is not 0."), false
			}
			if txo.Value.(*token.NumToken).Val != awd {
				return fmt.Errorf("Award is not evenly distributed among quanlified miners."), false
			}
		}

		// examine signatures
		hash := MakeMinerSigHash(block.Height(), *block.Hash())

		usigns := make(map[[20]byte]struct{})

		for _, sign := range block.MsgBlock().Transactions[0].SignatureScripts[1:] {
			signer, err := btcutil.VerifySigScript(sign, hash, b.ChainParams)
			if err != nil {
				return err, false
			}

			pkh := signer.Hash160()
			if _, ok := usigns[*pkh]; ok {
				return fmt.Errorf("Duplicated Miner signature"), false
			}

			usigns[*pkh] = struct{}{}
		}
		if len(usigns) < wire.CommitteeSigs {
			return fmt.Errorf("Insufficient number of Miner signatures."), false
		}
	}

	return nil, false
}

// CheckProofOfWork ensures the block header bits which indicate the target
// difficulty is in min/max range and that the block hash is less than the
// target difficulty as claimed.
func (b *BlockChain) CheckProofOfWork(block *btcutil.Block, parent * chainutil.BlockNode, powLimit *big.Int) error {
	err, _ := b.checkProofOfWork(block, parent, powLimit, BFNone)
	return err
}

func CheckProofOfWork(stubBlock * btcutil.Block, powLimit *big.Int) error {
	return nil
}

// CountSigOps returns the number of signature operations for all transaction
// input and output scripts in the provided transaction.  This uses the
// quicker, but imprecise, signature operation counting mechanism from
// txscript.
func CountSigOps(tx *btcutil.Tx) int {
	if tx.IsCoinBase() {
		return len(tx.MsgTx().SignatureScripts) - 1
	}
	return len(tx.MsgTx().SignatureScripts)
}

func MakeMinerSigHash(height int32, hash chainhash.Hash) []byte {
	s1 := "Omega chain Miner block "
	s2 := " at height "
	lenth := 36 + len(s1) + len(s2)
	t := make([]byte, lenth)
	copy(t[:], []byte(s1))
	copy(t[len(s1):], hash[:])
	binary.LittleEndian.PutUint32(t[len(s1)+32:], uint32(height))
	return chainhash.DoubleHashB(t[:])
}

// checkBlockHeaderSanity performs some preliminary checks on a block header to
// ensure it is sane before continuing with processing.  These checks are
// context free.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to checkProofOfWork.
func checkBlockHeaderSanity(header *wire.BlockHeader, powLimit *big.Int, timeSource chainutil.MedianTimeSource, flags BehaviorFlags) error {
	// A block timestamp must not have a greater precision than one second.
	// This check is necessary because Go time.Time values support
	// nanosecond precision whereas the consensus rules only apply to
	// seconds and it's much nicer to deal with standard Go time values
	// instead of converting to seconds everywhere.
	if !header.Timestamp.Equal(time.Unix(header.Timestamp.Unix(), 0)) {
		str := fmt.Sprintf("block timestamp of %v has a higher "+
			"precision than one second", header.Timestamp)
		return ruleError(ErrInvalidTime, str)
	}

	// Ensure the block time is not too far in the future.
	maxTimestamp := timeSource.AdjustedTime().Add(time.Second *
		MaxTimeOffsetSeconds)
	if header.Timestamp.After(maxTimestamp) {
		str := fmt.Sprintf("block timestamp of %v is too far in the "+
			"future", header.Timestamp)
		return ruleError(ErrTimeTooNew, str)
	}

	return nil
}

// checkBlockSanity performs some preliminary checks on a block to ensure it is
// sane before continuing with block processing.  These checks are context free.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to checkBlockHeaderSanity.
func checkBlockSanity(block *btcutil.Block, powLimit *big.Int, timeSource chainutil.MedianTimeSource, flags BehaviorFlags) error {
	msgBlock := block.MsgBlock()
	header := &msgBlock.Header
	err := checkBlockHeaderSanity(header, powLimit, timeSource, flags)
	if err != nil {
		return err
	}

	// A block must have at least one transaction.
	numTx := len(msgBlock.Transactions)
	if numTx == 0 {
		return ruleError(ErrNoTransactions, "block does not contain "+
			"any transactions")
	}

	// The first transaction in a block must be a coinbase.
	transactions := block.Transactions()
	if !IsCoinBase(transactions[0]) {
		return ruleError(ErrFirstTxNotCoinbase, "first transaction in "+
			"block is not a coinbase")
	}

	// A block must not have more than one coinbase.
	for i, tx := range transactions[1:] {
		if IsCoinBase(tx) {
			str := fmt.Sprintf("block contains second coinbase at "+
				"index %d", i+1)
			return ruleError(ErrMultipleCoinbases, str)
		}
	}

	// Do some preliminary checks on each transaction to ensure they are
	// sane before continuing.
	for _, tx := range transactions {
		err := CheckTransactionSanity(tx)
		if err != nil {
			return err
		}
	}

	// Build merkle tree and ensure the calculated merkle root matches the
	// entry in the block header.  This also has the effect of caching all
	// of the transaction hashes in the block to speed up future hash
	// checks.  Bitcoind builds the tree here and checks the merkle root
	// after the following checks, but there is no reason not to check the
	// merkle root matches here.
	merkles := BuildMerkleTreeStore(block.Transactions(), false)
	calculatedMerkleRoot := merkles[len(merkles)-1]
	if !header.MerkleRoot.IsEqual(calculatedMerkleRoot) {
		str := fmt.Sprintf("block merkle root is invalid - block "+
			"header indicates %v, but calculated value is %v",
			header.MerkleRoot, calculatedMerkleRoot)
		return ruleError(ErrBadMerkleRoot, str)
	}

	if len(block.MsgBlock().Transactions[0].SignatureScripts) > 0 {
		merkles := BuildMerkleTreeStore(block.Transactions(), true)
		calculatedMerkleRoot := merkles[len(merkles)-1]
		if bytes.Compare(block.MsgBlock().Transactions[0].SignatureScripts[0], calculatedMerkleRoot[:]) != 0 {
			str := fmt.Sprintf("block signature merkle root is invalid - block "+
				"indicates %v, but calculated value is %v",
				block.MsgBlock().Transactions[0].SignatureScripts[0], calculatedMerkleRoot)
			return ruleError(ErrBadMerkleRoot, str)
		}
	}

	// Check for duplicate transactions.  This check will be fairly quick
	// since the transaction hashes are already cached due to building the
	// merkle tree above.
	existingTxHashes := make(map[chainhash.Hash]struct{})
	for _, tx := range transactions {
		hash := tx.Hash()
		if _, exists := existingTxHashes[*hash]; exists {
			str := fmt.Sprintf("block contains duplicate transaction %v", hash)
			return ruleError(ErrDuplicateTx, str)
		}
		existingTxHashes[*hash] = struct{}{}
	}

	// The number of signature operations must be less than the maximum
	// allowed per block.
	totalSigOps := 0
	for _, tx := range transactions {
		// We could potentially overflow the accumulator so check for
		// overflow.
		lastSigOps := totalSigOps
		totalSigOps += CountSigOps(tx)	// * chaincfg.WitnessScaleFactor)
		if totalSigOps < lastSigOps || totalSigOps > chaincfg.MaxBlockSigOpsCost {
			str := fmt.Sprintf("block contains too many signature "+
				"operations - got %v, max %v", totalSigOps,
				chaincfg.MaxBlockSigOpsCost)
			return ruleError(ErrTooManySigOps, str)
		}
	}

	return nil
}

// CheckBlockSanity performs some preliminary checks on a block to ensure it is
// sane before continuing with block processing.  These checks are context free.
func CheckBlockSanity(block *btcutil.Block, powLimit *big.Int, timeSource chainutil.MedianTimeSource) error {
	return checkBlockSanity(block, powLimit, timeSource, BFNone)
}

// checkBlockHeaderContext performs several validation checks on the block header
// which depend on its position within the block chain.
//
// The flags modify the behavior of this function as follows:
//  - BFFastAdd: All checks except those involving comparing the header against
//    the checkpoints are not performed.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) checkBlockHeaderContext(header *wire.BlockHeader, prevNode *chainutil.BlockNode, flags BehaviorFlags) error {
	fastAdd := flags&BFFastAdd == BFFastAdd
	if !fastAdd {
		// Ensure the timestamp for the block header is after the
		// median time of the last several blocks (medianTimeBlocks).
		medianTime := prevNode.CalcPastMedianTime()
		if !header.Timestamp.After(medianTime) {
			str := "block timestamp of %v is not after expected %v"
			str = fmt.Sprintf(str, header.Timestamp, medianTime)
			return ruleError(ErrTimeTooOld, str)
		}
	}

	// The height of this block is one more than the referenced previous
	// block.
	blockHeight := prevNode.Height + 1

	// Ensure chain matches up to predetermined checkpoints.
	blockHash := header.BlockHash()
	if !b.verifyCheckpoint(blockHeight, &blockHash) {
		str := fmt.Sprintf("block at height %d does not match "+
			"checkpoint hash", blockHeight)
		return ruleError(ErrBadCheckpoint, str)
	}

	// Find the previous checkpoint and prevent blocks which fork the main
	// chain before it.  This prevents storage of new, otherwise valid,
	// blocks which build off of old blocks that are likely at a much easier
	// difficulty and therefore could be used to waste cache and disk space.
	checkpointNode, err := b.findPreviousCheckpoint()
	if err != nil {
		return err
	}
	if checkpointNode != nil && blockHeight < checkpointNode.Height {
		str := fmt.Sprintf("block at height %d forks the main chain "+
			"before the previous checkpoint at height %d",
			blockHeight, checkpointNode.Height)
		return ruleError(ErrForkTooOld, str)
	}

	return nil
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
func (b *BlockChain) checkBlockContext(block *btcutil.Block, prevNode *chainutil.BlockNode, flags BehaviorFlags) error {
	// Perform all block header related validation checks.
	header := &block.MsgBlock().Header
	err := b.checkBlockHeaderContext(header, prevNode, flags)
	if err != nil {
		return err
	}
	fastAdd := flags&BFFastAdd == BFFastAdd
	if !fastAdd {
		// Obtain the latest state of the deployed CSV soft-fork in
		// order to properly guard the new validation behavior based on
		// the current BIP 9 version bits state.

		// Once the CSV soft-fork is fully active, we'll switch to
		// using the current median time past of the past block's
		// timestamps for all lock-time based checks.
		blockTime := header.Timestamp
		blockTime = prevNode.CalcPastMedianTime()

		// The height of this block is one more than the referenced
		// previous block.
		blockHeight := prevNode.Height + 1

		// Ensure all transactions in the block are finalized.
		for _, tx := range block.Transactions() {
			if !IsFinalizedTransaction(tx, blockHeight,
				blockTime) {

				str := fmt.Sprintf("block contains unfinalized "+
					"transaction %v", tx.Hash())
				return ruleError(ErrUnfinalizedTx, str)
			}
		}

		coinbaseTx := block.Transactions()[0]
		if len(coinbaseTx.MsgTx().TxIn) == 0 || blockHeight != int32(coinbaseTx.MsgTx().TxIn[0].PreviousOutPoint.Index) {
			str := fmt.Sprintf("Bad blockHeight in coinbaseTx"+
				"transaction %v", block.Hash())
			return ruleError(ErrBadCoinbaseScriptLen, str)
		}

			// Validate the witness commitment (if any) within the
			// block.  This involves asserting that if the coinbase
			// contains the special commitment output, then this
			// merkle root matches a computed merkle root of all
			// the wtxid's of the transactions within the block. In
			// addition, various other checks against the
			// coinbase's witness stack.
			if err := ValidateWitnessCommitment(block); err != nil {
				return err
			}

			// Once the witness commitment, witness nonce, and sig
			// op cost have been validated, we can finally assert
			// that the block's weight doesn't exceed the current
			// consensus parameter.
			blockWeight := len(block.MsgBlock().Transactions) // GetBlockWeight(block)
			blockLimit := int(b.GetBlockLimit(block.Height()))
			if blockWeight > blockLimit { // chaincfg.MaxBlockWeight {
				str := fmt.Sprintf("block's weight metric is "+
					"too high - got %v, max %v",
					blockWeight, blockLimit) //	chaincfg.MaxBlockWeight)
				return ruleError(ErrBlockWeightTooHigh, str)
			}
		}

	return nil
}

// CheckTransactionInputs performs a series of checks on the inputs to a
// transaction to ensure they are valid.  An example of some of the checks
// include verifying all inputs exist, ensuring the coinbase seasoning
// requirements are met, detecting double spends, validating all values and fees
// are in the legal range and the total output amount doesn't exceed the input
// amount, and verifying the signatures to prove the spender was the owner of
// the bitcoins and therefore allowed to spend them.  As it checks the inputs,
// it also calculates the total fees for the transaction and returns that value.
//
// NOTE: The transaction MUST have already been sanity checked with the
// CheckTransactionSanity function prior to calling this function.
func CheckTransactionInputs(tx *btcutil.Tx, txHeight int32, views * viewpoint.ViewPointSet, chainParams *chaincfg.Params) error {
	// Coinbase transactions have no inputs.
	if IsCoinBase(tx) {
		return nil
	}

	utxoView := views.Utxo

	if err := validate.CheckTransactionInputs(tx, views); err != nil {
		// actually check definitions only
		return err
	}

	totalIns := make(map[uint64]int64)
	for txInIndex, txIn := range tx.MsgTx().TxIn {
		if txIn.IsSeparator() {
			continue
		}
		// Ensure the referenced input transaction is available.
		utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if utxo == nil || utxo.IsSpent() {
			str := fmt.Sprintf("output %v referenced from "+
				"transaction %s:%d either does not exist or "+
				"has already been spent", txIn.PreviousOutPoint,
				tx.Hash(), txInIndex)
			return ruleError(ErrMissingTxOut, str)
		}

		// Ensure the transaction is not spending coins which have not
		// yet reached the required coinbase maturity.
		if utxo.IsCoinBase() {
			originHeight := utxo.BlockHeight()
			blocksSincePrev := txHeight - originHeight
			coinbaseMaturity := int32(chainParams.CoinbaseMaturity)
			if originHeight != 0 && blocksSincePrev < coinbaseMaturity {
				str := fmt.Sprintf("tried to spend coinbase "+
					"transaction output %v from height %v "+
					"at height %v before required maturity "+
					"of %v blocks", txIn.PreviousOutPoint,
					originHeight, txHeight,
					coinbaseMaturity)
				return ruleError(ErrImmatureSpend, str)
			}
		}

		// Ensure the transaction amounts are in range.  Each of the
		// output values of the input transactions must not be negative
		// or more than the max allowed per transaction.  All amounts in
		// a transaction are in a unit value known as a satoshi.  One
		// bitcoin is a quantity of satoshi as defined by the
		// SatoshiPerBitcoin constant.
		if utxo.TokenType & 3 != 0 {
			continue
		}

		originTxSatoshi := utxo.Amount.(*token.NumToken).Val
		if originTxSatoshi < 0 {
			str := fmt.Sprintf("transaction output has negative "+
				"value of %v", btcutil.Amount(originTxSatoshi))
			return ruleError(ErrBadTxOutValue, str)
		}
		if originTxSatoshi > btcutil.MaxSatoshi {
			str := fmt.Sprintf("transaction output value of %v is "+
				"higher than max allowed value of %v",
				btcutil.Amount(originTxSatoshi),
				btcutil.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}

		// The total of all outputs must not be more than the max
		// allowed per transaction.  Also, we could potentially overflow
		// the accumulator so check for overflow.
		lastSatoshiIn := totalIns[utxo.TokenType]
		totalIns[utxo.TokenType] += originTxSatoshi
		if totalIns[utxo.TokenType] < lastSatoshiIn ||
			totalIns[utxo.TokenType] > btcutil.MaxSatoshi {
			str := fmt.Sprintf("total value of all transaction "+
				"inputs is %v which is higher than max "+
				"allowed value of %v", totalIns[utxo.TokenType],
				btcutil.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
	}

	return nil
}

func CheckAdditionalTransactionInputs(tx *btcutil.Tx, txHeight int32, views * viewpoint.ViewPointSet, chainParams *chaincfg.Params) error {
	// Coinbase transactions have no inputs.
	if IsCoinBase(tx) {
		return nil
	}

	utxoView := views.Utxo

	if err := validate.CheckTransactionAdditionalInputs(tx, views); err != nil {
		// actually check definitions only
		return err
	}

	totalIns := make(map[uint64]int64)
	additional := false
	for txInIndex, txIn := range tx.MsgTx().TxIn {
		if txIn.IsSeparator() {
			additional = true
			continue
		}
		if !additional {
			continue
		}
		// Ensure the referenced input transaction is available.
		utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if utxo == nil || utxo.IsSpent() {
			str := fmt.Sprintf("output %v referenced from "+
				"transaction %s:%d either does not exist or "+
				"has already been spent", txIn.PreviousOutPoint,
				tx.Hash(), txInIndex)
			return ruleError(ErrMissingTxOut, str)
		}

		// Ensure the transaction is not spending coins which have not
		// yet reached the required coinbase maturity.
		if utxo.IsCoinBase() {
			originHeight := utxo.BlockHeight()
			blocksSincePrev := txHeight - originHeight
			coinbaseMaturity := int32(chainParams.CoinbaseMaturity)
			if originHeight != 0 && blocksSincePrev < coinbaseMaturity {
				str := fmt.Sprintf("tried to spend coinbase "+
					"transaction output %v from height %v "+
					"at height %v before required maturity "+
					"of %v blocks", txIn.PreviousOutPoint,
					originHeight, txHeight,
					coinbaseMaturity)
				return ruleError(ErrImmatureSpend, str)
			}
		}

		// Ensure the transaction amounts are in range.  Each of the
		// output values of the input transactions must not be negative
		// or more than the max allowed per transaction.  All amounts in
		// a transaction are in a unit value known as a satoshi.  One
		// bitcoin is a quantity of satoshi as defined by the
		// SatoshiPerBitcoin constant.
		if utxo.TokenType & 3 != 0 {
			continue
		}

		originTxSatoshi := utxo.Amount.(*token.NumToken).Val
		if originTxSatoshi < 0 {
			str := fmt.Sprintf("transaction output has negative "+
				"value of %v", btcutil.Amount(originTxSatoshi))
			return ruleError(ErrBadTxOutValue, str)
		}
		if originTxSatoshi > btcutil.MaxSatoshi {
			str := fmt.Sprintf("transaction output value of %v is "+
				"higher than max allowed value of %v",
				btcutil.Amount(originTxSatoshi),
				btcutil.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}

		// The total of all outputs must not be more than the max
		// allowed per transaction.  Also, we could potentially overflow
		// the accumulator so check for overflow.
		lastSatoshiIn := totalIns[utxo.TokenType]
		totalIns[utxo.TokenType] += originTxSatoshi
		if totalIns[utxo.TokenType] < lastSatoshiIn ||
			totalIns[utxo.TokenType] > btcutil.MaxSatoshi {
			str := fmt.Sprintf("total value of all transaction "+
				"inputs is %v which is higher than max "+
				"allowed value of %v", totalIns[utxo.TokenType],
				btcutil.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
	}

	return nil
}

func CheckTransactionIntegrity(tx *btcutil.Tx,  views * viewpoint.ViewPointSet) error {
	if IsCoinBase(tx) {
		return nil
	}

	// Check numeric token w/ rights. If no new geometry is introduced, we can
	// make quick check geometry too by treating them as numeric token.

	inputs := make([]token.Token, len(tx.MsgTx().TxIn))
	for i, txIn := range tx.MsgTx().TxIn {
		if txIn.IsSeparator() {
			continue
		}
		out := txIn.PreviousOutPoint
		x := views.Utxo.LookupEntry(out)
		if x == nil {
			r := make(map[wire.OutPoint]struct{})
			r[out] = struct{}{}
			x = views.Utxo.LookupEntry(out)
		}
		inputs[i] = x.ToTxOut().Token
	}
//	ntx := tx.Copy() // Deep copy
//	ntx.Spends = append(inputs, ntx.Spends...)

	res, err := validate.QuickCheckRight(tx, views)
	if res {
		return nil
	}
	if err != nil {
		return err
	}

	// check geometry integrity
	if !validate.CheckGeometryIntegrity(tx, views) {
		str := fmt.Sprintf("The Tx is not geometrically integral")
		return ruleError(ErrSpendTooHigh, str)
	}
	return nil
}

func CheckTransactionFees(tx *btcutil.Tx, txHeight int32, views * viewpoint.ViewPointSet, chainParams *chaincfg.Params) (int64, error) {
	// Coinbase transactions have no inputs.
	utxoView := views.Utxo

	txHash := tx.Hash()
	totalIns := make(map[uint64]int64)

	for _, txIn := range tx.MsgTx().TxIn {
		if txIn.IsSeparator() {
			continue
		}
		// Ensure the referenced input transaction is available.
		var utxo *wire.TxOut
		utxo = utxoView.LookupEntry(txIn.PreviousOutPoint).ToTxOut()

		// Ensure the transaction amounts are in range.  Each of the
		// output values of the input transactions must not be negative
		// or more than the max allowed per transaction.  All amounts in
		// a transaction are in a unit value known as a satoshi.  One
		// bitcoin is a quantity of satoshi as defined by the
		// SatoshiPerBitcoin constant.
		if utxo.TokenType & 3 != 0 {
			continue
		}

		originTxSatoshi := utxo.Token.Value.(*token.NumToken).Val

		// The total of all outputs must not be more than the max
		// allowed per transaction.  Also, we could potentially overflow
		// the accumulator so check for overflow.
		lastSatoshiIn := totalIns[utxo.TokenType]
		totalIns[utxo.TokenType] += originTxSatoshi
		if totalIns[utxo.TokenType] < lastSatoshiIn ||
			totalIns[utxo.TokenType] > btcutil.MaxSatoshi {
			str := fmt.Sprintf("total value of all transaction "+
				"inputs is %v which is higher than max "+
				"allowed value of %v", totalIns[utxo.TokenType],
				btcutil.MaxSatoshi)
			return 0, ruleError(ErrBadTxOutValue, str)
		}
	}

	// Calculate the total output amount for this transaction.  It is safe
	// to ignore overflow and out of range errors here because those error
	// conditions would have already been caught by checkTransactionSanity.
	totalSatoshiOut := make(map[uint64]int64)

	for _, txOut := range tx.MsgTx().TxOut {
		if txOut.IsSeparator() {
			continue
		}
		if txOut.TokenType & 3 == 0 {
			if _, ok := totalSatoshiOut[txOut.TokenType]; ok {
				totalSatoshiOut[txOut.TokenType] += txOut.Value.(*token.NumToken).Val
			} else {
				totalSatoshiOut[txOut.TokenType] = txOut.Value.(*token.NumToken).Val
			}
		}
	}

	// Ensure the transaction does not spend more than its inputs.
	for in,out := range totalSatoshiOut {
		if v,ok := totalIns[in]; !ok || v < out {
			str := fmt.Sprintf("total value of all transaction inputs for "+
				"transaction %v is %v which is less than the amount "+
				"spent of %v", txHash, v, out)
			return 0, ruleError(ErrSpendTooHigh, str)
		} else if in != 0 && v != out {
			str := fmt.Sprintf("total %d type token value of all transaction inputs for "+
				"transaction %v is %v which is not equal to the amount "+
				"spent of %v", in, txHash, v, out)
			return 0, ruleError(ErrSpendTooHigh, str)
		}
	}

	// NOTE: bitcoind checks if the transaction fees are < 0 here, but that
	// is an impossible condition because of the check above that ensures
	// the inputs are >= the outputs.
	txFeeInSatoshi := totalIns[0] - totalSatoshiOut[0]

	n := 0
	for _,d := range tx.MsgTx().TxDef {
		if d.DefType() == token.DefTypeBorder && d.(*token.BorderDef).Father.IsEqual(&zeroHash) {
			n++
		}
	}
	if txFeeInSatoshi < int64(n * chainParams.MinBorderFee) {
		return 0, fmt.Errorf("Transaction fee is less than the mandatory storage fee.")
	}

	return txFeeInSatoshi, nil
}

// checkConnectBlock performs several checks to confirm connecting the passed
// block to the chain represented by the passed view does not violate any rules.
// In addition, the passed view is updated to spend all of the referenced
// outputs and add all of the new utxos created by block.  Thus, the view will
// represent the state of the chain as if the block were actually connected and
// consequently the best hash for the view is also updated to passed block.
//
// An example of some of the checks performed are ensuring connecting the block
// would not cause any duplicate transaction hashes for old transactions that
// aren't already fully spent, double spends, exceeding the maximum allowed
// signature operations per block, invalid values in relation to the expected
// block subsidy, or fail transaction script validation.
//
// The CheckConnectBlockTemplate function makes use of this function to perform
// the bulk of its work.  The only difference is this function accepts a node
// which may or may not require reorganization to connect it to the main chain
// whereas CheckConnectBlockTemplate creates a new node which specifically
// connects to the end of the current main chain and then calls this function
// with that node.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) checkConnectBlock(node *chainutil.BlockNode, block *btcutil.Block, views *viewpoint.ViewPointSet, stxos *[]viewpoint.SpentTxOut, Vm * ovm.OVM) error {
	// If the side chain blocks end up in the database, a call to
	// CheckBlockSanity should be done here in case a previous version
	// allowed a block that is no longer valid.  However, since the
	// implementation only currently uses memory for the side chain blocks,
	// it isn't currently necessary.

	// Ensure the view is for the node being checked.
	parentHash := &block.MsgBlock().Header.PrevBlock
	if !views.Utxo.BestHash().IsEqual(parentHash) {
		return AssertError(fmt.Sprintf("inconsistent view when "+
			"checking block connection: best hash is %v instead "+
			"of expected %v", views.Utxo.BestHash(), parentHash))
	}

	// Load all of the utxos referenced by the inputs for all transactions
	// in the block don't already exist in the utxo view from the database.
	//
	// These utxo entries are needed for verification of things such as
	// transaction inputs, counting pay-to-script-hashes, and scripts.
	err := views.FetchInputUtxos(block)
	if err != nil {
		return err
	}

	// The number of signature operations must be less than the maximum
	// allowed per block.  Note that the preliminary sanity checks on a
	// block also include a check similar to this one, but this check
	// expands the count to include a precise count of pay-to-script-hash
	// signature operations in each of the input transaction public key
	// scripts.
	transactions := block.Transactions()
	totalSigOpCost := 0
	for i, tx := range transactions {
		// Since the first (and only the first) transaction has
		// already been verified to be a coinbase transaction,
		// use i == 0 as an optimization for the flag to
		// countP2SHSigOps for whether or not the transaction is
		// a coinbase transaction rather than having to do a
		// full coinbase check again.
		sigOpCost, err := GetSigOpCost(tx, i == 0, views.Utxo, true,true)
		if err != nil {
			return err
		}

		// Check for overflow or going over the limits.  We have to do
		// this on every loop iteration to avoid overflow.
		lastSigOpCost := totalSigOpCost
		totalSigOpCost += sigOpCost
		if totalSigOpCost < lastSigOpCost || totalSigOpCost > chaincfg.MaxBlockSigOpsCost {
			str := fmt.Sprintf("block contains too many "+
				"signature operations - got %v, max %v",
				totalSigOpCost, chaincfg.MaxBlockSigOpsCost)
			return ruleError(ErrTooManySigOps, str)
		}
	}

	// Don't run scripts if this node is before the latest known good
	// checkpoint since the validity is verified via the checkpoints (all
	// transactions are included in the merkle root hash and any changes
	// will therefore be detected by the next checkpoint).  This is a huge
	// optimization because running the scripts is the most time consuming
	// portion of block handling.
	checkpoint := b.LatestCheckpoint()
	runScripts := true
	if checkpoint != nil && node.Height <= checkpoint.Height {
		runScripts = false
	}

	// Perform several checks on the inputs for each transaction.  Also
	// accumulate the total fees.  This could technically be combined with
	// the loop above instead of running another loop over the transactions,
	// but by separating it we can avoid running the more expensive (though
	// still relatively cheap as compared to running the scripts) checks
	// against all the inputs when the signature operations are out of
	// bounds.

	coinBase := btcutil.NewTx(transactions[0].MsgTx().Stripped())
	coinBase.SetIndex(transactions[0].Index())
	coinBaseHash := *coinBase.Hash()

	Vm.SetCoinBaseOp(
		func(txo wire.TxOut) wire.OutPoint {
			if !coinBase.HasOuts {
				// this servers as a separater. only TokenType is serialized
				to := wire.TxOut{}
				to.Token = token.Token{TokenType: token.DefTypeSeparator}
				coinBase.MsgTx().AddTxOut(&to)
				coinBase.HasOuts = true
			}
			coinBase.MsgTx().AddTxOut(&txo)
			op := wire.OutPoint { coinBaseHash, uint32(len(coinBase.MsgTx().TxOut) - 1)}
			views.Utxo.AddRawTxOut(op, &txo, false, block.Height())
			return op
		})

	Vm.GasLimit = block.MsgBlock().Header.ContractExec
	Vm.BlockNumber = func() uint64 {
		return uint64(block.Height())
	}
	Vm.Block = func() *btcutil.Block { return block }
	Vm.GetCoinBase = func() *btcutil.Tx { return coinBase }

	var totalFees int64
	for i, tx := range transactions {
		txFee := int64(0)

		if i != 0 {
			if runScripts {
				err = ovm.VerifySigs(tx, node.Height, b.ChainParams, views)
				if err != nil {
					return err
				}
			}

			if !tx.Executed {
				newtx := btcutil.NewTx(tx.MsgTx().Stripped())
				newtx.SetIndex(tx.Index())
				newtx.HasIns, newtx.HasDefs, newtx.HasOuts = false, false, false

				err := CheckTransactionInputs(newtx, node.Height, views, b.ChainParams)
				if err != nil {
					return err
				}

				err = Vm.ExecContract(newtx, node.Height)
				if err != nil {
					return err
				}

				// compare tx & newtx
				if !tx.Match(newtx) {
					return fmt.Errorf("Mismatch contract execution result")
				}
				tx.Executed = newtx.Executed
			} else {
				err := CheckTransactionInputs(tx, node.Height, views, b.ChainParams)
				if err != nil {
					return err
				}
			}

			err = CheckAdditionalTransactionInputs(tx, node.Height, views, b.ChainParams)
			if err != nil {
				return err
			}

			err = CheckTransactionIntegrity(tx, views)
			if err != nil {
				return err
			}

			txFee, err = CheckTransactionFees(tx, node.Height, views, b.ChainParams)
			if err != nil {
				return err
			}
		} else {
			err := CheckTransactionInputs(tx, node.Height, views, b.ChainParams)
			if err != nil {
				return err
			}
		}

		// Sum the total fees and ensure we don't overflow the
		// accumulator.
		lastTotalFees := totalFees
		totalFees += txFee
		if totalFees < lastTotalFees {
			return ruleError(ErrBadFees, "total fees for block "+
				"overflows accumulator")
		}

		// Add all of the outputs for this transaction which are not
		// provably unspendable as available utxos.  Also, the passed
		// spent txos slice is updated to contain an entry for each
		// spent txout in the order each transaction spends them.
		err = views.ConnectTransaction(tx, node.Height, stxos)
		if err != nil {
			return err
		}
	}
	if Vm.GasLimit != 0 {
		return fmt.Errorf("Incorrect contract execution cost.")
	}

	// compare coinBase and transactions[0]
	if !transactions[0].Executed && !transactions[0].Match(coinBase) {
		return fmt.Errorf("Mismatch contract execution result")
	}

	// The total output values of the coinbase transaction must not exceed
	// the expected subsidy value plus total transaction fees gained from
	// mining the block.  It is safe to ignore overflow and out of range
	// errors here because those error conditions would have already been
	// caught by checkTransactionSanity.
	var totalSatoshiOut int64

	for _, txOut := range transactions[0].MsgTx().TxOut {
		if !txOut.IsSeparator() && txOut.TokenType == 0 {
			totalSatoshiOut += txOut.Value.(*token.NumToken).Val
		}
	}

	prevPows := uint(0)
	if node.Data.GetNonce() > 0 {
		for pw := node.Parent; pw != nil && pw.Data.GetNonce() > 0; pw = pw.Parent {
			prevPows++
		}
	}
	adj := int64(0)

	if prevPows != 0 {
		best := b.BestSnapshot()
		adj = CalcBlockSubsidy(best.Height, b.ChainParams, 0) -
			CalcBlockSubsidy(best.Height, b.ChainParams, prevPows)
	}

	expectedSatoshiOut := CalcBlockSubsidy(node.Height, b.ChainParams, prevPows) + adj + totalFees
	if totalSatoshiOut > expectedSatoshiOut {
		str := fmt.Sprintf("coinbase transaction for block pays %v "+
			"which is more than expected value of %v",
			totalSatoshiOut, expectedSatoshiOut)
		return ruleError(ErrBadCoinbaseValue, str)
	}

	// We obtain the MTP of the *previous* block in order to
	// determine if transactions in the current block are final.
	medianTime := node.Parent.CalcPastMedianTime()

	// we also enforce the relative sequence number based
	// lock-times within the inputs of all transactions in this
	// candidate block.
	for _, tx := range block.Transactions() {
		// A transaction can only be included within a block
		// once the sequence locks of *all* its inputs are
		// active.
		sequenceLock, err := b.calcSequenceLock(node, tx, views.Utxo,
			false)
		if err != nil {
				return err
			}
		if !SequenceLockActive(sequenceLock, node.Height,
			medianTime) {
			str := fmt.Sprintf("block contains " +
				"transaction whose input sequence " +
				"locks are not met")
			return ruleError(ErrUnfinalizedTx, str)
		}
	}

	// blacklist check
	for _, tx := range block.Transactions() {
		for _, txo := range tx.MsgTx().TxOut {
			if txo.IsSeparator() {
				continue
			}
			var name [20]byte
			copy(name[:], txo.PkScript[1:21])
			if b.Blacklist.IsBlack(name) {
				return fmt.Errorf("Blacklised txo")
			}
		}
		for _, txi := range tx.MsgTx().TxIn {
			if txi.IsSeparator() {
				continue
			}
			utxo := views.Utxo.LookupEntry(txi.PreviousOutPoint)
			if utxo == nil || utxo.IsSpent() {
				continue
			}

			// check blacklist
			var name [20]byte
			copy(name[:], utxo.PkScript()[1:21])
			if b.Blacklist.IsBlack(name) {
				return fmt.Errorf("Blacklised input")
			}
		}
	}

	// Update the best hash for view to include this block since all of its
	// transactions have been connected.
	views.Utxo.SetBestHash(&node.Hash)

	return nil
}

// CheckConnectBlockTemplate fully validates that connecting the passed block to
// the main chain does not violate any consensus rules, aside from the proof of
// work requirement. The block must connect to the current tip of the main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) CheckConnectBlockTemplate(block *btcutil.Block) error {
//	log.Infof("CheckConnectBlockTemplate: ChainLock.RLock")
	b.ChainLock.Lock()
	defer b.ChainLock.Unlock()

	// Skip the proof of work check as this is just a block template.
	flags := BFNoPoWCheck

	// This only checks whether the block can be connected to the tip of the
	// current chain.
	tip := b.BestChain.Tip()
	header := block.MsgBlock().Header
	if tip.Hash != header.PrevBlock {
		str := fmt.Sprintf("previous block must be the current chain tip %v, "+
			"instead got %v", tip.Hash, header.PrevBlock)
		return ruleError(ErrPrevBlockNotBest, str)
	}

	err := checkBlockSanity(block, b.ChainParams.PowLimit, b.timeSource, flags)
	if err != nil {
		return err
	}

	if len(block.MsgBlock().Transactions) > int(b.GetBlockLimit(block.Height())) {
		str := fmt.Sprintf("serialized block is too big - got %d, "+
			"max %d", block.Size(), b.GetBlockLimit(block.Height()))
		return ruleError(ErrBlockTooBig, str)
	}

	err = b.checkBlockContext(block, tip, flags)
	if err != nil {
		return err
	}

	// Leave the spent txouts entry nil in the state since the information
	// is not needed and thus extra work can be avoided.
	views, Vm := b.Canvas(block)

	views.SetBestHash(&tip.Hash)

	newNode := NewBlockNode(&header, tip)

	return b.checkConnectBlock(newNode, block, views, nil, Vm)
}
