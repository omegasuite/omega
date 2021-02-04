// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"fmt"
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/ovm"
	"github.com/omegasuite/omega/token"
	"sort"
)

type TreeNode struct {
	block * btcutil.Block
	children []*TreeNode
}

type compensatee struct {
	tx * btcutil.Tx
	fee int64
}

func (g *BlockChain) ProcessForfeitBlock(b *TreeNode, usable map[wire.OutPoint]int64, compensable []compensatee, vm *ovm.OVM) {
	for _,tx := range b.block.Transactions()[1:] {
		out, in := int64(0), int64(0)
		if g.MainChainTx(*tx.Hash()) != nil {
			// no comp if the tx is also in main chain
			continue
		}
		// calculate tx fees
		// calculate input sum
		for _, txin := range tx.MsgTx().TxIn {
			if txin.IsSeparator() {
				break
			}
			if u,ok := usable[txin.PreviousOutPoint]; ok {
				in += u
				delete(usable, txin.PreviousOutPoint)
			} else {
				tk := g.MainChainTx(txin.PreviousOutPoint.Hash)
				if tk == nil || tk.TxOut[txin.PreviousOutPoint.Index].TokenType != 0 {
					continue
				}
				in += tk.TxOut[txin.PreviousOutPoint.Index].Token.Value.(*token.NumToken).Val
			}
		}
		if in == 0 {
			continue
		}
		// calculate output sum
		op := wire.OutPoint{*tx.Hash(), 0}
		pt := 0
		for i, txo := range tx.MsgTx().TxOut {
			if txo.IsSeparator() {
				break
			}
			if txo.PkScript[0] != g.ChainParams.ContractAddrID {
				pt++
			} else {
				var addr ovm.Address
				copy(addr[:], txo.PkScript[1:21])
				owner, err := vm.ContractCall(addr, []byte{ovm.OP_OWNER, 0, 0,0})
				if err != nil || len(owner) != 21 {
					continue
				}
				pt++
			}
			if txo.TokenType != 0 {
				continue
			}
			op.Index = uint32(i)
			usable[op] = txo.Token.Value.(*token.NumToken).Val
			out += txo.Token.Value.(*token.NumToken).Val
		}
		if pt == 0 || in == out {
			// no output requires comp
			continue
		}
		compensable = append(compensable, compensatee{tx, in - out})
	}

	switch len(b.children) {
	case 0:
		return

	case 1:
		g.ProcessForfeitBlock(b.children[0], usable, compensable, vm)

	default:
		for _,c := range b.children {
			dup := make(map[wire.OutPoint]int64)
			for u,v := range usable {
				dup[u] = v
			}
			g.ProcessForfeitBlock(c, dup, compensable, vm)
		}
	}
}

func (g *BlockChain) CompTxs(nonde int32, prevNode *chainutil.BlockNode, vm *ovm.OVM) ([]*wire.MsgTx, error) {
	complist, rbase, err := g.PrepForfeit(nonde, prevNode)
	if err != nil || rbase == 0 {
		return nil, err
	}

	ctx := &wire.MsgTx{}
	ctx.Version = wire.ForfeitTxVersion | wire.TxNoLock | wire.TxNoDefine

	forrest := make(map[chainhash.Hash]*TreeNode)
	roots := make(map[chainhash.Hash][]*TreeNode)
	avail := int64(0)

	for i,p := range complist {
		mb, _ := g.Miners.BlockByHeight(int32(i) + rbase)
		ctx.AddTxIn(&wire.TxIn{
			wire.OutPoint{mb.MsgBlock().Utxos.Hash, mb.MsgBlock().Utxos.Index},
			0xFFFFFFFF, 0,
		})
		tk := g.MainChainTx(mb.MsgBlock().Utxos.Hash)
		if tk == nil || tk.TxOut[mb.MsgBlock().Utxos.Index].TokenType != 0 {
			continue
		}
		avail += tk.TxOut[mb.MsgBlock().Utxos.Index].Value.(*token.NumToken).Val

		for q, _ := range p {
			blk, _ := g.BlockByHash(&q)
			if _, ok := forrest[*blk.Hash()]; ok {
				continue
			}
			t := &TreeNode{
				block:    blk,
				children: make([]*TreeNode, 0),
			}
			forrest[*blk.Hash()] = t
			if _, ok := forrest[blk.MsgBlock().Header.PrevBlock]; ok {
				forrest[blk.MsgBlock().Header.PrevBlock].children =
					append(forrest[blk.MsgBlock().Header.PrevBlock].children, t)
			} else if _,ok := roots[blk.MsgBlock().Header.PrevBlock]; ok {
				roots[blk.MsgBlock().Header.PrevBlock] = append(
					roots[blk.MsgBlock().Header.PrevBlock], t)
			} else {
				roots[blk.MsgBlock().Header.PrevBlock] = []*TreeNode{t}
			}
			for h, s := range roots {
				if h == *blk.Hash() {
					t.children = s
					delete(roots, h)
					break
				}
			}
		}
	}

	compensable := make([]compensatee, 0)
	for h, s := range roots {
		node := g.NodeByHash(&h)
		if node == nil || !g.BestChain.Contains(node) {
			continue
		}
		for _,blk := range s {
			g.ProcessForfeitBlock(blk, make(map[wire.OutPoint]int64), compensable, vm)
		}
	}

	// sort txs in ascending order by tx fees
	sort.Slice(compensable, func(i int, j int) bool {
		if compensable[i].fee < compensable[j].fee {
			return true
		} else if compensable[i].fee > compensable[j].fee {
			return false
		}
		// tie break by hash to ensure consistent result across nodes
		return bytes.Compare((*compensable[i].tx.Hash())[:], (*compensable[j].tx.Hash())[:]) < 0
	})

	ctransactions := make([]*wire.MsgTx, 0)
	for i,t := range compensable {		// for each compensable tx
		if avail <= 0 || len(ctx.TxOut) == wire.MaxTxOutPerMessage - 1 || i == len(compensable) - 1 {
			if avail > 0 {
				rto := &wire.TxOut{}
				rto.TokenType = 0
				rto.Value = &token.NumToken{avail}
				rto.PkScript = make([]byte, 22)
				rto.PkScript[0] = g.ChainParams.PubKeyHashAddrID
				rto.PkScript[1] = 1
				rto.PkScript[21] = ovm.OP_PAY2ANY
				ctx.AddTxOut(rto)
			}
			hash := ctx.TxHash()
			toi := len(ctransactions)
			if len(ctx.TxOut) > 0 {
				ctransactions = append(ctransactions, ctx)
			}
			ctx = &wire.MsgTx{}
			ctx.Version = wire.ForfeitTxVersion | wire.TxNoLock | wire.TxNoDefine
			ctx.AddTxIn(&wire.TxIn{
				wire.OutPoint{hash, uint32(toi)}, 0xFFFFFFFF, 0,
			})
		}
		if avail <= 0 {
			break
		}

		rto := &wire.TxOut{}
		rto.TokenType = 0
		if avail >= t.fee * 10000 {
			rto.Value = &token.NumToken{t.fee * 10000}
			avail -= t.fee * 10000
		} else {
			rto.Value = &token.NumToken{avail}
			avail = 0
		}

		rto.PkScript = make([]byte, 22)

		mn := uint16(0)

		scripts := make([]byte, 4)

		for _,tto := range t.tx.MsgTx().TxOut {
			if tto.IsSeparator() {
				// can not compensate contract calls because contracts don't know
				// how to express agreement to a settlement plan. leave to future
				continue
			}
			if tto.PkScript[0] == g.ChainParams.ContractAddrID {
				var addr ovm.Address
				copy(addr[:], tto.PkScript[1:21])
				owner, err := vm.ContractCall(addr, []byte{ovm.OP_OWNER, 0, 0, 0})
				if err != nil || len(owner) != 21 || owner[0] == g.ChainParams.ContractAddrID {
					continue
				}
				scripts = append(scripts, owner...)
				scripts = append(scripts, []byte{ovm.OP_PAY2PKH,0,0,0}...)
			} else {
				scripts = append(scripts, tto.PkScript...)
			}
			mn++
		}

		common.LittleEndian.PutUint16(scripts, mn)
		common.LittleEndian.PutUint16(scripts[2:], mn)

		// check pkscript
		if mn == 1 {
			rto.PkScript = scripts[4:]
		} else {
			rto.PkScript[0] = g.ChainParams.MultiSigAddrID
			rto.PkScript[21] = ovm.OP_PAYMULTISIG

			h := btcutil.Hash160(scripts)
			copy(rto.PkScript[1:21], h[:])
		}
		ctx.AddTxOut(rto)
	}

	if len(ctx.TxOut) > 0 {
		ctransactions = append(ctransactions, ctx)
	}

	return ctransactions, nil
}

func (b *BlockChain) PrepForfeit(nonce int32, prevNode *chainutil.BlockNode) ([]map[chainhash.Hash]struct{}, int32, error) {
	// check bond/forfeiture
	// all violations about one MR block shall be handled in in TX block,
	// i.e. the block when rotation of the 100-th MR block after the violating block
	// not sooner, not later.
	var forfeiture []map[chainhash.Hash]struct{}
	var pmh, rbase int32
	reportee := make(map[int32]*wire.MinerBlock)
	var prevminer *chainutil.BlockNode

	if nonce < -wire.MINER_RORATE_FREQ {
		pmh = -(nonce + wire.MINER_RORATE_FREQ)
		mb,err := b.Miners.BlockByHeight(pmh - wire.ViolationReportDeadline)
		if err != nil {
			return nil, 0, err
		}
		reportee[pmh - wire.ViolationReportDeadline] = mb
		rbase = pmh - wire.ViolationReportDeadline
		prevminer = b.Miners.NodeByHeight(pmh - 1)
		forfeiture = make([]map[chainhash.Hash]struct{}, 1)
		forfeiture[0] = make(map[chainhash.Hash]struct{})
	} else if nonce > 0	{
		forfeiture = make([]map[chainhash.Hash]struct{}, wire.POWRotate)
		for i := 0; i < wire.POWRotate; i++ {
			forfeiture[i] = make(map[chainhash.Hash]struct{})
		}
		q, m := prevNode, wire.POWRotate
		for ; q != nil && q.Data.GetNonce() > -wire.MINER_RORATE_FREQ; q = q.Parent {
			if q.Data.GetNonce() > 0 {
				m += wire.POWRotate
			}
		}
		if q != nil {
			pmh = int32(m + 1) - (q.Data.GetNonce() + wire.MINER_RORATE_FREQ)
			prevminer = b.Miners.NodeByHeight(pmh - 1)
			rbase = pmh - wire.ViolationReportDeadline - wire.POWRotate + 1
			for j, h := 0, rbase; j < wire.POWRotate; j++ {
				mb, err := b.Miners.BlockByHeight(h)
				if err != nil {
					return nil, 0, err
				}
				h++
				reportee[h] = mb
			}
		}
	} else {
		return nil, 0, nil
	}

	for i := 0; i < wire.ViolationReportDeadline + wire.POWRotate; i++ {
		blk := b.Miners.NodetoHeader(prevminer)
		for _,r := range blk.ViolationReport {
			rptd := int32(-1)
			for _,u := range reportee {
				if r.MRBlock == *u.Hash() {
					rptd = u.Height()
				}
			}
			if rptd < 0 {
				continue
			}
			for _,u := range r.Blocks {
				if b.InBestChain(&u) {
					continue
				}
				forfeiture[rptd - rbase][u] = struct{}{}
			}
		}
		prevminer = prevminer.Parent
	}

	sum := 0
	for _,f := range forfeiture {
		sum += len(f)
	}

	if sum == 0 {
		return nil, 0, nil
	}

	return forfeiture, rbase, nil
}

type txlistitem struct {
	hash chainhash.Hash
	fees int64
}
type txlist struct {
	txs []*txlistitem
}

func (b *BlockChain) CheckForfeit(block *btcutil.Block, prevNode *chainutil.BlockNode, vm *ovm.OVM) error {
	ftxs, err := b.CompTxs(block.MsgBlock().Header.Nonce, prevNode, vm)
	if err != nil {
		return err
	}

	// all foreit txs in a block must process exactly all blacklists
	for _,tx := range block.MsgBlock().Transactions[1:] {
		if !tx.IsForfeit() {
			if len(ftxs) != 0 {
				return fmt.Errorf("Incorrect forfeiture txs")
			}
			return nil
		}
		if len(ftxs) == 0 {
			return fmt.Errorf("Incorrect forfeiture txs")
		}

		var w1 bytes.Buffer
		var w2 bytes.Buffer
		if err := tx.SerializeFull(&w1); err != nil {
			return err
		}
		if err := ftxs[0].SerializeFull(&w2); err != nil {
			return err
		}
		if bytes.Compare(w1.Bytes(), w2.Bytes()) != 0 {
			return fmt.Errorf("Incorrect forfeiture txs")
		}
		ftxs = ftxs[1:]
	}

	if len(ftxs) != 0 {
		return fmt.Errorf("Incorrect forfeiture txs")
	}

	return nil
}
