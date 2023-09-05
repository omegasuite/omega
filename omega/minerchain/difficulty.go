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
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/omega/token"
	"math/big"
	"strconv"
	"time"

	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
)

var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// oneLsh256 is 1 shifted left 256 bits.  It is defined here to avoid
	// the overhead of creating it multiple times.
	oneLsh256 = new(big.Int).Lsh(bigOne, 256)
)

// HashToBig converts a chainhash.Hash into a big.Int that can be used to
// perform math comparisons.
func HashToBig(hash *chainhash.Hash) *big.Int {
	// A Hash is in little-endian, but the big package wants the bytes in
	// big-endian, so reverse them.
	buf := *hash
	blen := len(buf)
	for i := 0; i < blen/2; i++ {
		buf[i], buf[blen-1-i] = buf[blen-1-i], buf[i]
	}

	return new(big.Int).SetBytes(buf[:])
}

// CompactToBig converts a compact representation of a whole number N to an
// unsigned 32-bit number.  The representation is similar to IEEE754 floating
// point numbers.
//
// Like IEEE754 floating point, there are three basic components: the sign,
// the exponent, and the mantissa.  They are broken out as follows:
//
//	* the most significant 8 bits represent the unsigned base 256 exponent
// 	* bit 23 (the 24th bit) represents the sign bit
//	* the least significant 23 bits represent the mantissa
//
//	-------------------------------------------------
//	|   Exponent     |    Sign    |    Mantissa     |
//	-------------------------------------------------
//	| 8 bits [31-24] | 1 bit [23] | 23 bits [22-00] |
//	-------------------------------------------------
//
// The formula to calculate N is:
// 	N = (-1^sign) * mantissa * 256^(exponent-3)
//
// This compact form is only used in bitcoin to encode unsigned 256-bit numbers
// which represent difficulty targets, thus there really is not a need for a
// sign bit, but it is implemented here to stay consistent with bitcoind.
func CompactToBig(compact uint32) *big.Int {
	// Extract the mantissa, sign bit, and exponent.
	mantissa := compact & 0x007fffff
	isNegative := compact&0x00800000 != 0
	exponent := uint(compact >> 24)

	// Since the base for the exponent is 256, the exponent can be treated
	// as the number of bytes to represent the full 256-bit number.  So,
	// treat the exponent as the number of bytes and shift the mantissa
	// right or left accordingly.  This is equivalent to:
	// N = mantissa * 256^(exponent-3)
	var bn *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		bn = big.NewInt(int64(mantissa))
	} else {
		bn = big.NewInt(int64(mantissa))
		bn.Lsh(bn, 8*(exponent-3))
	}

	// Make it negative if the sign bit is set.
	if isNegative {
		bn = bn.Neg(bn)
	}

	return bn
}

// BigToCompact converts a whole number N to a compact representation using
// an unsigned 32-bit number.  The compact representation only provides 23 bits
// of precision, so values larger than (2^23 - 1) only encode the most
// significant digits of the number.  See CompactToBig for details.
func BigToCompact(n *big.Int) uint32 {
	// No need to do any work if it's zero.
	if n.Sign() == 0 {
		return 0
	}

	// Since the base for the exponent is 256, the exponent can be treated
	// as the number of bytes.  So, shift the number right or left
	// accordingly.  This is equivalent to:
	// mantissa = mantissa / 256^(exponent-3)
	var mantissa uint32
	exponent := uint(len(n.Bytes()))
	if exponent <= 3 {
		mantissa = uint32(n.Bits()[0])
		mantissa <<= 8 * (3 - exponent)
	} else {
		// Use a copy to avoid modifying the caller's original number.
		tn := new(big.Int).Set(n)
		mantissa = uint32(tn.Rsh(tn, 8*(exponent-3)).Bits()[0])
	}

	// When the mantissa already has the sign bit set, the number is too
	// large to fit into the available 23-bits, so divide the number by 256
	// and increment the exponent accordingly.
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		exponent++
	}

	// Pack the exponent, sign bit, and mantissa into an unsigned 32-bit
	// int and return it.
	compact := uint32(exponent<<24) | mantissa
	if n.Sign() < 0 {
		compact |= 0x00800000
	}
	return compact
}

// CalcWork calculates a work value from difficulty bits.  Bitcoin increases
// the difficulty for generating a block by decreasing the value which the
// generated hash must be less than.  This difficulty target is stored in each
// block header using a compact representation as described in the documentation
// for CompactToBig.  The main chain is selected by choosing the chain that has
// the most proof of work (highest difficulty).  Since a lower target difficulty
// value equates to higher actual difficulty, the work value which will be
// accumulated must be the inverse of the difficulty.  Also, in order to avoid
// potential division by zero and really small floating point numbers, the
// result adds 1 to the denominator and multiplies the numerator by 2^256.
func CalcWork(bits uint32) *big.Int {
	// Return a work value of zero if the passed difficulty bits represent
	// a negative number. Note this should not happen in practice with valid
	// blocks, but an invalid block could trigger it.
	difficultyNum := CompactToBig(bits)
	if difficultyNum.Sign() <= 0 {
		return big.NewInt(0)
	}

	// (1 << 256) / (difficultyNum + 1)
	denominator := new(big.Int).Add(difficultyNum, bigOne)
	return new(big.Int).Div(oneLsh256, denominator)
}

// findPrevTestNetDifficulty returns the difficulty of the previous block which
// did not have the special testnet minimum difficulty rule applied.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *MinerChain) findPrevTestNetDifficulty(startNode *chainutil.BlockNode) uint32 {
	// Search backwards through the chain for the last block without
	// the special rule applied.
	iterNode := startNode
	for iterNode != nil && iterNode.Height%b.blocksPerRetarget != 0 &&
		iterNode.Data.(*blockchainNodeData).block.Bits == b.chainParams.PowLimitBits {

		iterNode = iterNode.Parent
	}

	// Return the found difficulty or the minimum difficulty if no
	// appropriate block was found.
	lastBits := b.chainParams.PowLimitBits
	if iterNode != nil {
		lastBits = iterNode.Data.(*blockchainNodeData).block.Bits
	}
	return lastBits
}

func (b *MinerChain) NextRequiredDifficulty(lastNode *chainutil.BlockNode, newBlockTime time.Time) (uint32, uint32, error) {
	return b.calcNextRequiredDifficulty(lastNode, newBlockTime)
}

var collaterals [2016] int
var nextAdjustHeight = int32(-1)

// calcNextRequiredDifficulty calculates the required difficulty for the block
// after the passed previous block node based on the difficulty retarget rules.
// This function differs from the exported CalcNextRequiredDifficulty in that
// the exported version uses the current best chain as the previous block node
// while this function accepts any block node.
func (b *MinerChain) calcNextRequiredDifficulty(lastNode *chainutil.BlockNode, newBlockTime time.Time) (uint32, uint32, error) {
	if lastNode == nil || lastNode.Height < b.blocksPerRetarget + 10 {
		return b.chainParams.PowLimitBits, 1, nil
	}

	coll := lastNode.Data.(*blockchainNodeData).block.Collateral
	if coll == 0 {
		coll = 1
	}

	v2 := lastNode.Data.GetVersion() >= chaincfg.Version2
	v3 := lastNode.Data.GetVersion() >= chaincfg.Version3

	// Return the previous block's difficulty requirements if this block
	// is not at a difficulty retarget interval.
	if (lastNode.Height+1)%b.blocksPerRetarget != 0 {
		// For networks that support it, allow special reduction of the
		// required difficulty once too much time has elapsed without
		// mining a block.
		if nextAdjustHeight < 0 || nextAdjustHeight != (lastNode.Height+1) - ((lastNode.Height+1)%b.blocksPerRetarget) + b.blocksPerRetarget {
			nextAdjustHeight = (lastNode.Height+1) - ((lastNode.Height+1)%b.blocksPerRetarget) + b.blocksPerRetarget
			for i := 0; i < 2016; i++ {
				collaterals[i] = 0
			}
		}
		firstNode := lastNode.RelativeAncestor(b.blocksPerRetarget - 1)
		if firstNode == nil || !v3 {
			return lastNode.Data.(*blockchainNodeData).block.Bits, coll, nil
		}

		pb := firstNode

		for i := 5; i >= 0; {
			// to avoid long delay caused when adjustment is needed, we retrieve some collaterals each time
			// to cause loading of missing nodes
			//		b.blockChain.HeaderByHash(&pb.Data.(*blockchainNodeData).block.BestBlock)
			block := pb.Data.(*blockchainNodeData).block
			j := b.blocksPerRetarget - (nextAdjustHeight - pb.Height)
			if j < 0 {
				i = -1
			} else if collaterals[j] == 0 && pb.Height < lastNode.Height-7 { // block is considered finalized after 7 confirmations
				i--
				if block.Version&0x7FFF0000 >= chaincfg.Version5 && block.Utxos != nil {
					var op = block.Utxos

					// it could have been spent, so we get the raw tx and find out its value
					blockRegion, err := b.TxIndex.TxBlockRegion(&op.Hash)

					if err != nil || blockRegion == nil {
						panic("Failed to retrieve transaction location for tx: " + op.Hash.String())
					}

					// Load the raw transaction bytes from the database.
					var txBytes []byte
					err = b.db.View(func(dbTx database.Tx) error {
						var err error
						txBytes, err = dbTx.FetchBlockRegion(blockRegion)
						return err
					})

					if err != nil {
						blk, err := b.blockChain.BlockByHash(blockRegion.Hash)
						if err != nil {
							panic(strconv.Itoa(int(i)) + ": Failed to retrieve transaction " + op.Hash.String() + " for " + err.Error())
						}
						fd := false
						for _, tx := range blk.Transactions() {
							if tx.Hash().IsEqual(&op.Hash) {
								collaterals[j] = int(tx.MsgTx().TxOut[op.Index].Value.(*token.NumToken).Val / 1e8)
								fd = true
								break
							}
						}
						if !fd {
							panic(strconv.Itoa(int(i)) + ": Failed to retrieve transaction " + op.Hash.String() + " at " + blockRegion.Hash.String() + " " + strconv.Itoa(int(blockRegion.Len)) + " : " + strconv.Itoa(int(blockRegion.Offset)))
						}
					} else {
						// Deserialize the transaction
						var msgTx wire.MsgTx
						err = msgTx.Deserialize(bytes.NewReader(txBytes))
						collaterals[j] = int(msgTx.TxOut[op.Index].Value.(*token.NumToken).Val / 1e8)
					}
				}
			}
			pb = pb.Parent
		}
/*
		if b.chainParams.ReduceMinDifficulty {
			// Return minimum difficulty when more than the desired
			// amount of time has elapsed without mining a block.
			reductionTime := int64(b.chainParams.MinDiffReductionTime /
				time.Second)
			allowMinTime := lastNode.Data.(*blockchainNodeData).block.Timestamp.Unix() + reductionTime
			if newBlockTime.Unix() > allowMinTime {
				return b.chainParams.PowLimitBits, coll, nil
			}

			// The block was mined within the desired timeframe, so
			// return the difficulty for the last block which did
			// not have the special minimum difficulty rule applied.
			return b.findPrevTestNetDifficulty(lastNode), coll, nil
		}
 */
		// For the main network (or any unrecognized networks), simply
		// return the previous block's difficulty requirements.
		return lastNode.Data.(*blockchainNodeData).block.Bits, coll, nil
	}

	// Get the block node at the previous retarget (targetTimespan days
	// worth of blocks).
	firstNode := lastNode.RelativeAncestor(b.blocksPerRetarget - 1)
	if firstNode == nil {
		return 0, 0, AssertError("unable to obtain previous retarget block")
	}

	d := 0 // uint32(firstNode.height) - baseh

	// normalize time span. account for difficulty adjust factor due to # of exceeding blocks in history
	// collateral, TPS score
	normalizedTimespan := int64(0)
	pb := firstNode

	coll = 0x7FFFFFFF // max. min coll for next period is the min coll of all in the last period

	//	bb := b.blockChain.BestChain.Tip()
	for i := b.blocksPerRetarget - 2; i >= 0; i-- {
		// to cause loading of missing nodes
		//		b.blockChain.HeaderByHash(&pb.Data.(*blockchainNodeData).block.BestBlock)
		block := pb.Data.(*blockchainNodeData).block
		bb := b.blockChain.NodeByHash(&block.BestBlock)

		if block.Collateral < coll && block.Version&0x7FFF0000 < chaincfg.Version5 {
			coll = block.Collateral
		}

		j := pb.Height % b.blocksPerRetarget
		if collaterals[j] != 0 {
			if uint32(collaterals[j]) < coll {
				coll = uint32(collaterals[j])
			}
		} else if v3 && block.Version&0x7FFF0000 >= chaincfg.Version5 && block.Utxos != nil {
			var op = block.Utxos

			// it could have been spent, so we get the raw tx and find out its value
			blockRegion, err := b.TxIndex.TxBlockRegion(&op.Hash)

			if err != nil || blockRegion == nil {
				panic("Failed to retrieve transaction location for tx: " + op.Hash.String())
			}

			// Load the raw transaction bytes from the database.
			var txBytes []byte
			err = b.db.View(func(dbTx database.Tx) error {
				var err error
				txBytes, err = dbTx.FetchBlockRegion(blockRegion)
				return err
			})

			if err != nil {
				blk, err := b.blockChain.BlockByHash(blockRegion.Hash)
				if err != nil {
					panic(strconv.Itoa(int(i)) + ": Failed to retrieve transaction " + op.Hash.String() + " for " + err.Error())
				}
				fd := false
				for _, tx := range blk.Transactions() {
					if tx.Hash().IsEqual(&op.Hash) {
						v := tx.MsgTx().TxOut[op.Index].Value.(*token.NumToken).Val / 1e8
						if uint32(v) < coll {
							coll = uint32(v)
						}
						fd = true
						break
					}
				}
				if !fd {
					panic(strconv.Itoa(int(i)) + ": Failed to retrieve transaction " + op.Hash.String() + " at " + blockRegion.Hash.String() + " " + strconv.Itoa(int(blockRegion.Len)) + " : " + strconv.Itoa(int(blockRegion.Offset)))
				}
				//				panic(strconv.Itoa(int(i)) + ": Failed to retrieve transaction " + op.Hash.String() + " at " + blockRegion.Hash.String() + " " + strconv.Itoa(int(blockRegion.Len)) + " : " + strconv.Itoa(int(blockRegion.Offset)))
			} else {
				// Deserialize the transaction
				var msgTx wire.MsgTx
				err = msgTx.Deserialize(bytes.NewReader(txBytes))
				v := msgTx.TxOut[op.Index].Value.(*token.NumToken).Val / 1e8
				if uint32(v) < coll {
					coll = uint32(v)
				}
			}
		}
/*
		for bb != nil && bb.Hash != pb.Data.(*blockchainNodeData).block.BestBlock {
			if bb.Parent == nil && bb.Height != 0 {
				// this should not happen. but we keep code here in case something is wrong
				h := bb.Height - 100
				if h < 0 {
					h = 0
				}
				b.blockChain.FetchMissingNodes(&bb.Hash, h)
			}
			bb = bb.Parent
		}
 */
		if bb == nil {
			// error. abort recalculation
			return lastNode.Data.(*blockchainNodeData).block.Bits, coll, fmt.Errorf("unexpected BestBlock for %s", pb.Hash)
		}
		mb, h, dh := bb, int32(-1), int32(0)
		// find out length of waiting list. this is a simplified, ignores POW tx blocks
		for mb != nil && (mb.Data.GetNonce() > -wire.MINER_RORATE_FREQ) {
			if mb.Data.GetNonce() < 0 {
				mb = b.blockChain.NodeByHeight(mb.Height + mb.Data.GetNonce())
				continue
			}
			dh -= 2
			pmb := b.blockChain.ParentNode(mb)
			if pmb == nil && mb.Height != 0 {
				// this should not happen. but we keep code here in case something is wrong
				return lastNode.Data.(*blockchainNodeData).block.Bits, coll, fmt.Errorf("broken best chain at %s", mb.Hash)
			}

			mb = pmb
		}
		if mb != nil {
			h = - mb.Data.GetNonce() - wire.MINER_RORATE_FREQ
		}
		if lastNode.Data.GetVersion() >= chaincfg.Version2 {
			h += dh
		}
		d = int(pb.Height - h)
		nb := pb.Parent

		// Time between the 2 nodes
		dt := int64(float64(block.Timestamp.Unix() - nb.Data.(*blockchainNodeData).block.Timestamp.Unix()))
		// if there is an difficulty adjustment (increase) due to waiting list control
		// adjusting dt as it the block is generated faster, this will cause increase
		// in difficulty target, so we will less likely run into long waiting list
		if d - wire.DESIRABLE_MINER_CANDIDATES > wire.SCALEFACTORCAP {
			dt = dt >> wire.SCALEFACTORCAP
		} else if d > wire.DESIRABLE_MINER_CANDIDATES {
			dt = dt >> (d - wire.DESIRABLE_MINER_CANDIDATES)
		} else if v2 && d < wire.DESIRABLE_MINER_CANDIDATES / 2 {
			m := wire.DESIRABLE_MINER_CANDIDATES / 2 - d
			if m > 10 {
				m = 10
			}
			dt = dt << m
		}

		// do we need to cancel adjustments for collateral & TPS scores? no.
		// because these adjustment is given on competition basis, so when we
		// calculate average block time, winners and losers will cancel out
		// each other.

		normalizedTimespan += dt

		pb = nb
	}

	// Limit the amount of adjustment that can occur to the previous
	// difficulty.

	actualTimespan := normalizedTimespan
	adjustedTimespan := normalizedTimespan
	if actualTimespan < b.minRetargetTimespan {
		adjustedTimespan = b.minRetargetTimespan
	} else if actualTimespan > b.maxRetargetTimespan {
		adjustedTimespan = b.maxRetargetTimespan
	}

	// Calculate new target difficulty as:
	//  currentDifficulty * (adjustedTimespan / targetTimespan)
	// The result uses integer division which means it will be slightly
	// rounded down.  Bitcoind also uses integer division to calculate this
	// result.
	oldTarget := CompactToBig(lastNode.Data.(*blockchainNodeData).block.Bits)
	var newTarget * big.Int

	if b.chainParams.Name != "mainnet" {
		newTarget = new(big.Int).Mul(oldTarget, big.NewInt(adjustedTimespan))
		targetTimeSpan := int64(b.chainParams.TargetTimespan / time.Second)
		newTarget.Div(newTarget, big.NewInt(targetTimeSpan))
	} else {
		newTarget = new(big.Int).Mul(oldTarget, big.NewInt(adjustedTimespan))
		targetTimeSpan := int64(b.chainParams.TargetTimespan / time.Second)
		newTarget.Div(newTarget, big.NewInt(targetTimeSpan))
	}

	// Limit new value to the proof of work limit.
	newTargetBits := b.chainParams.PowLimitBits
	if newTarget.Cmp(b.chainParams.PowLimit) <= 0 {
		newTargetBits = BigToCompact(newTarget)
	}

	// Log new target difficulty and return it.  The new target logging is
	// intentionally converting the bits back to a number instead of using
	// newTarget since conversion to the compact representation loses
	// precision.
	if v3 && coll < 100 {
		coll = 100
	}
	coll = (coll * 7) >> 3
	if coll == 0 {
		coll = 1
	}
	return newTargetBits, coll, nil
}

// CalcNextRequiredDifficulty calculates the required difficulty for the block
// after the end of the current best chain based on the difficulty retarget
// rules.
//
// This function is safe for concurrent access.
func (b *MinerChain) CalcNextRequiredDifficulty(timestamp time.Time) (uint32, uint32, error) {
//	log.Infof("MinerChain.CalcNextRequiredDifficulty: ChainLock.RLock")
	b.chainLock.Lock()
	difficulty, col, err := b.calcNextRequiredDifficulty(b.BestChain.Tip(), timestamp)
	b.chainLock.Unlock()
//	log.Infof("MinerChain.CalcNextRequiredDifficulty: ChainLock.Unlock")

	return difficulty, col, err
}
