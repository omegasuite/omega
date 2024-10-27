// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/famofchains/btcd/blockchain/chainutil"
	"github.com/omegasuite/famofchains/btcd/database"
	"github.com/omegasuite/famofchains/btcd/wire"
	"github.com/omegasuite/famofchains/btcd/wire/common"
	"github.com/omegasuite/famofchains/btcutil"
	"github.com/omegasuite/famofchains/omega/chainmap"
	"time"
)

func (b *BlockChain) CheckCrossChainTx(tx *wire.MsgTx) error {
	src := b.ChainParams.ChainID
	if len(tx.TxIn) == 1 && (tx.TxIn[0].PreviousOutPoint.Index&wire.CrossChainFalg) != 0 {
		src = tx.TxIn[0].PreviousOutPoint.Index &^ wire.CrossChainFalg
	}

	for _, txo := range tx.TxOut {
		if txo.IsSeparator() || !txo.IsCrossChain() {
			continue
		}
		if txo.IsContractCall() {
			return fmt.Errorf("cross chain tx with contract call")
		}

		tdest := uint32(txo.TokenType >> 40)
		if _, ok := chainmap.ChainMap[tdest]; tdest != 0 && !ok {
			b.SrvReq <- ReqChain(tdest)
			return fmt.Errorf("Cross chain TokenType not found")
		}

		if tdest != 0 && tdest != src && tdest != txo.DestChain() {
			return fmt.Errorf("Invalid cross chain tokentype")
		}

		if src != 0 && tdest == 0 {
			return fmt.Errorf("Local Tokentype in a cross chain tx")
		}

		dest := common.LittleEndian.Uint32(txo.PkScript[21:]) >> 8
		if tdest != b.ChainParams.ChainID && tdest != dest {
			return fmt.Errorf("Incorrect cross chain destination")
		}
		if uint32(txo.TokenType>>40) == b.ChainParams.ChainID && tdest == dest {
			return fmt.Errorf("Incorrect cross chain destination")
		}
		if len(txo.PkScript) != 26 && len(txo.PkScript) != 29 {
			return fmt.Errorf("incorrect cross chain pkscript length")
		}
		if ((txo.TokenType >> 40) & 0xFFFFFF) == 0 {
			return fmt.Errorf("Local tokentype in cross chain tx")
		}
		/*
			var chain [4]byte
			copy(chain[:], txo.PkScript[22:25])
			chain[3] = 0
			cid := common.LittleEndian.Uint32(chain[:])

		*/

		cid := dest

		if cid == b.ChainParams.ChainID {
			return fmt.Errorf("cross chain transferring to local chain")
		}
		if _, ok := chainmap.ChainMap[cid]; !ok {
			b.SrvReq <- ReqChain(cid)
			return fmt.Errorf("unknown cross chain destination")
		}
		if src != 0 && src != tdest && tdest != cid {
			return fmt.Errorf("Incorrect cross chain destination")
		}
	}

	return nil
}

func (b *BlockChain) validateCrossChain(tx *wire.MsgTx) error {
	if err := b.CheckCrossChainTx(tx); err != nil {
		return err
	}

	if !b.IsSVP && tx.IsCrossChain() {
		return b.db.View(func(dbtx database.Tx) error {
			// bucket := dbtx.Metadata().Bucket([]byte(common.SVPHeights))
			rawc := tx.TxIn[0].PreviousOutPoint.Index &^ wire.CrossChainFalg
			/*
				h := tx.TxIn[0].SignatureIndex
				if (rawc & (wire.CrossChainFalg) >> 1) != 0 {
					rawc = 0xFFFFFF - rawc
				} else {
					rawc = rawc &^ wire.CrossChainFalg
				}
				common.LittleEndian.PutUint32(key[:], rawc)
				bh := bucket.Get(key[:4])
				svph := common.LittleEndian.Uint32(bh)
				if svph < h+chainmap.ChainMap[rawc].Mature {
					return fmt.Errorf("cross chain tx is not validateCrossChain yet")
				}
			*/

			// ensure the txo are in the pool
			bucket := dbtx.Metadata().Bucket([]byte(common.INCOMINGPOOL))

			key := tx.TxIn[0].PreviousOutPoint.ToBytes()
			v := bucket.Get(key[:])
			if v == nil || len(v) == 0 {
				return fmt.Errorf("tx not in INCOMINGPOOL")
			}
			xdata := wire.XchainData{}
			if err := xdata.DeSerialize(v); err != nil {
				return err
			}
			if xdata.Txs[0].Txo.PkScript[21] != 0x66 {
				fmt.Printf("bad XchainData")
			}
			if xdata.Finalized == 0 {
				return fmt.Errorf("tx not finalized")
			}
			if xdata.ChainID != rawc {
				return fmt.Errorf("chain ID incorrect")
			}
			if len(tx.TxOut) != len(xdata.Txs) {
				return fmt.Errorf("txout size incorrect")
			}
			if !xdata.Hash.IsEqual(&tx.TxIn[0].PreviousOutPoint.Hash) {
				return fmt.Errorf("block hash incorrect")
			}
			//			if uint32(xdata.Height) != h {
			//				return fmt.Errorf("height incorrect")
			//			}

			for _, txo := range tx.TxOut {
				match := false
				for i, xto := range xdata.Txs {
					if (common.LittleEndian.Uint32(xto.Txo.PkScript[21:]) >> 8) == b.ChainParams.ChainID {
						b.normalizeTxo(&xto.Txo)
					}
					if txo.Match(&xto.Txo) {
						match = true
						xdata.Txs = append(xdata.Txs[:i], xdata.Txs[i+1:]...)
						break
					}
				}
				if !match {
					return fmt.Errorf("txo mismatch")
				}
			}

			return nil
		})
	}
	return nil
}

// maybeAcceptBlock potentially accepts a block into the block chain and, if
// accepted, returns whether or not it is on the main chain.  It performs
// several validation checks which depend on its position within the block chain
// before adding it.  The block is expected to have already gone through
// ProcessBlock before calling this function with it.
//
// The flags are also passed to checkBlockContext and connectBestChain.  See
// their documentation for how the flags modify their behavior.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) maybeAcceptBlock(block *btcutil.Block, flags BehaviorFlags) (bool, error, int32) {
	// The height of this block is one more than the referenced previous
	// block.
	prevHash := &block.MsgBlock().Header.PrevBlock
	prevNode := b.NodeByHash(prevHash)

	// The block must pass all of the validation rules which depend on the
	// position of the block within the block chain.
	err := b.checkBlockContext(block, prevNode, flags)
	if err != nil {
		return false, err, -1
	}

	if flags&BFNoConnect == BFNoConnect {
		// now we have passed all the tests
		return true, nil, -1
	}

	if block.MsgBlock().Header.Nonce < 0 && len(block.MsgBlock().Transactions[0].SignatureScripts) <= wire.CommitteeSigs {
		return false, fmt.Errorf("insifficient signatures"), -1
	}
	if block.MsgBlock().Header.Nonce < 0 {
		for _, sig := range block.MsgBlock().Transactions[0].SignatureScripts[1:] {
			if len(sig) < 33 {
				return false, fmt.Errorf("incorrect signatures"), -1
			}
		}
	}

	if block.MsgBlock().Header.Nonce <= -wire.MINER_RORATE_FREQ {
		// make sure the rotate in Miner block is there
		if prevNode.Data.GetNonce() != -wire.MINER_RORATE_FREQ+1 {
			return false, fmt.Errorf("this is a rotation node and previous nonce is not %d", -wire.MINER_RORATE_FREQ+1), -1
		}
		if mb, err := b.Miners.BlockByHeight(-block.MsgBlock().Header.Nonce - wire.MINER_RORATE_FREQ); err != nil || mb == nil {
			return false, err, -block.MsgBlock().Header.Nonce - wire.MINER_RORATE_FREQ
		}
	}

	// Create a new block node for the block and add it to the node index. Even
	// if the block ultimately gets connected to the main chain, it starts out
	// on a side chain.
	blockHeader := &block.MsgBlock().Header

	// check cross chain txs
	coinbase := block.MsgBlock().Transactions[0]
	if coinbase.IsCrossChain() {
		return false, fmt.Errorf("Coinbase tx can not be a cross chain transaction"), -1
	}
	for _, txo := range coinbase.TxOut {
		if txo.IsSeparator() {
			continue
		}
		if txo.IsCrossChain() {
			return false, fmt.Errorf("Coinbase tx can not be a cross chain transaction"), -1
		}
	}
	if !b.IsSVP {
		m := chainmap.ChainMap[b.ChainParams.ChainID]
		initems := make(map[chainhash.Hash]*wire.XchainData)
		b.db.View(func(dbtx database.Tx) error {
			bucket := dbtx.Metadata().Bucket([]byte(common.INCOMINGPOOL))
			for _, tx := range block.MsgBlock().Transactions[1:] {
				if !tx.IsCrossChain() {
					continue
				}
				if _, ok := initems[tx.TxIn[0].PreviousOutPoint.Hash]; ok {
					return fmt.Errorf("Duplicated Cross chain item.")
				}
				t := bucket.Get(tx.TxIn[0].PreviousOutPoint.ToBytes())
				if t == nil || len(t) == 0 {
					return fmt.Errorf("Cross chain item does not exist. SVP chain not ready?")
				}
				x := &wire.XchainData{}
				if x.DeSerialize(t) != nil {
					return fmt.Errorf("bad XchainData")
				}
				if x.Txs[0].Txo.PkScript[21] != 0x66 {
					fmt.Printf("bad XchainData")
				}
				initems[tx.TxIn[0].PreviousOutPoint.Hash] = x
			}
			return nil
		})
		if err != nil {
			return false, err, -1
		}

		for _, tx := range block.MsgBlock().Transactions[1:] {
			if tx.IsCrossChain() {
				srcchain := tx.TxIn[0].PreviousOutPoint.Index & wire.CrossChainSrcMask

				for _, txo := range tx.TxOut {
					if txo.IsCrossChain() {
						destchain := common.LittleEndian.Uint32(txo.PkScript[21:]) >> 8
						if destchain == 0 {
							destchain = b.ChainParams.ChainID
						}
						if !m.PassThru(srcchain, destchain) {
							return false, fmt.Errorf("Mix of cross chain and regular txout"), -1
						}
					}
				}

				if err != nil {
					return false, err, -1
				}
			}
			if err := b.validateCrossChain(tx); err != nil {
				return false, err, -1
			}
		}
	}

	newNode := b.MainChainNodeByHash(block.Hash())

	// Insert the block into the database if it's not already there.
	// This is necessary since it allows block download to be decoupled
	// from the much more expensive connection logic.  It is also
	// necessary to blocks that never become part of the main chain or
	// blocks that fail to connect available for forfeture and compensation.
	err = b.db.Update(func(dbTx database.Tx) error {
		return dbStoreBlock(dbTx, block)
	})

	if err != nil {
		return false, err, -1
	}

	if newNode == nil {
		newNode = NewBlockNode(blockHeader, prevNode)
		newNode.Status = chainutil.StatusDataStored
		b.index.AddNode(newNode)
	} else {
		newNode.Height = block.Height()
		if newNode.Height <= 0 {
			return false, err, -1
		}
		b.index.UnsetStatusFlags(newNode, chainutil.BlockStatus(0xFF))
		b.index.SetStatusFlags(newNode, chainutil.StatusDataStored)
		newNode.Parent = prevNode
		b.index.AddNodeDirect(newNode)

		flags |= BFAlreadyInChain
	}
	err = b.index.FlushToDB(dbStoreBlockNode)
	if err != nil {
		return false, err, -1
	}

	if flags&BFAlreadyInChain == BFAlreadyInChain {
		return false, nil, -1
	}

	isMainChain := false

	if block.Height() > b.BestChain.Height() {
		// if it is a POW block and we are in committee, we keep the committee going
		// until the POW block is followed by signed block
		if block.MsgBlock().Header.Nonce < 0 || block.Height() > b.ConsensusRange[1] {
			// Connect the passed block to the chain while respecting proper chain
			// selection according to the chain with the most proof of work.  This
			// also handles validation of the transaction scripts.
			isMainChain, err = b.connectBestChain(newNode, block, flags)
			if err != nil {
				return false, err, -1
			}
		}
	}

	// Notify the caller that the new block was accepted into the block
	// chain.  The caller would typically want to react by relaying the
	// inventory to other peers.
	b.ChainLock.Unlock()
	b.SendNotification(NTBlockAccepted, block)
	b.ChainLock.Lock()

	if b.BTfile != nil {
		r := time.Now().Unix()
		s := fmt.Sprintf("%d rcvd %d lat %d (%d)\n", block.Height(), r, r-block.MsgBlock().Header.Timestamp.Unix(), block.MsgBlock().Header.Timestamp.Unix())
		b.BTfile.Write([]byte(s))
	}

	return isMainChain, nil, -1
}
