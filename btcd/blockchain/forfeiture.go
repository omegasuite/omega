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
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/ovm"
	"github.com/omegasuite/omega/token"
)

type reportedblk struct {
	block * chainhash.Hash
	reporter * [20]byte
}

var ADDVTM = []byte{45,12,45,65,0,0,0,0,0,0,0,0,28,0,0,0,}		// TBD correct methid

type txfee struct {
	tx * btcutil.Tx
	fee int64
}

func (g *BlockChain) compensatedTx(tx *chainhash.Hash) bool {
	r := false
	g.db.View(func (dbtx database.Tx) error {
		meta := dbtx.Metadata()
		index := meta.Bucket(compendatedBucketName)
		if t := index.Get((*tx)[:]); t != nil {
			r = true
		}
		return nil
	})
	return r
}

func (g *BlockChain) recordCompensation(tx *chainhash.Hash) error {
	return g.db.Update(func (dbtx database.Tx) error {
		meta := dbtx.Metadata()
		index := meta.Bucket(compendatedBucketName)
		return index.Put((*tx)[:], []byte{1})
	})
}

func (g *BlockChain) ProcessForfeitBlock(b *btcutil.Block,
	usable map[wire.OutPoint]int64,	processed map[chainhash.Hash]*txfee, vm *ovm.OVM) {
	// script

	for _, tx := range b.Transactions()[1:] {
		out, in := int64(0), int64(0)
		if g.MainChainTx(*tx.Hash()) != nil {
			// no comp if the tx is also in main chain
			continue
		}
		if _, ok := processed[*tx.Hash()]; ok {
			// no comp if the tx has already been processed
			continue
		}
		// check database
		if g.compensatedTx(tx.Hash()) {
			// record it to avoid db access in the future
			processed[*tx.Hash()] = nil
			continue
		}
		// calculate tx fees
		// calculate input sum
		for _, txin := range tx.MsgTx().TxIn {
			if txin.IsSeparator() {
				break
			}
			if u, ok := usable[txin.PreviousOutPoint]; ok {
				in += u
			} else {
				tk := g.MainChainTx(txin.PreviousOutPoint.Hash)
				if tk == nil || tk.TxOut[txin.PreviousOutPoint.Index].TokenType != 0 {
					continue
				}
				in += tk.TxOut[txin.PreviousOutPoint.Index].Token.Value.(*token.NumToken).Val
			}
		}
		if in == 0 {
			processed[*tx.Hash()] = nil
			continue
		}
		// calculate output sum
		op := wire.OutPoint{*tx.Hash(), 0}
		for i, txo := range tx.MsgTx().TxOut {
			if txo.IsSeparator() {
				break
			}
			if txo.PkScript[0] == g.ChainParams.ContractAddrID {
				var addr ovm.Address
				copy(addr[:], txo.PkScript[1:21])
				// if contract has designated an owner, pay the owner,
				// otherwide, contract may add an 0 payment to an address for receiving
				// comp. if neither, contract give up comp
				owner, err := vm.ContractCall(addr, []byte{ovm.OP_OWNER, 0, 0, 0})
				if err != nil || len(owner) != 21 {
					continue
				}
			}
			if txo.TokenType != 0 {
				continue
			}
			op.Index = uint32(i)
			usable[op] = txo.Token.Value.(*token.NumToken).Val
			out += txo.Token.Value.(*token.NumToken).Val
		}
		if in <= out {
			// no comp
			processed[*tx.Hash()] = nil
			continue
		}

		mn := uint16(0)

		for _,tto := range tx.MsgTx().TxOut {
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
			}
			mn++
		}
		if mn == 0 {
			// no comp
			processed[*tx.Hash()] = nil
			continue
		}

		processed[*tx.Hash()] = &txfee{ tx, in - out }
	}
}

func (g *BlockChain) comptx(tx *txfee, vm *ovm.OVM) []byte {
	added := int64(0)
	scripts := make([]byte, 4)
	mn := uint16(0)

	for _,tto := range tx.tx.MsgTx().TxOut {
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
		} else {
			scripts = append(scripts, tto.PkScript[:21]...)
		}
		mn++
	}

	common.LittleEndian.PutUint16(scripts, mn)
	common.LittleEndian.PutUint16(scripts[2:], mn)

	// check pkscript
	if mn == 1 {
		scripts = scripts[4:25]
		var fmap = map[byte]byte{
			g.ChainParams.PubKeyHashAddrID: ovm.OP_PAY2PKH,
			g.ChainParams.ScriptHashAddrID: ovm.OP_PAY2SCRIPTH,
			g.ChainParams.MultiSigAddrID: ovm.OP_PAYMULTISIG,
		}
		scripts = append(scripts, fmap[scripts[0]])
	} else {
		var script [22]byte
		script[0] = g.ChainParams.MultiSigAddrID
		script[21] = ovm.OP_PAYMULTISIG

		h := btcutil.Hash160(scripts)
		copy(script[1:21], h[:])
		scripts = script[:]
	}

	added++
	script := make([]byte, 0, 32 + 8 + 8 + 22 + 4)
	script = append(script, tx.tx.Hash()[:]...)

	var fee [8]byte
	common.LittleEndian.PutUint64(fee[:], uint64(tx.fee * 10000))
	script = append(script, fee[:]...)

	script = append(script, scripts[:]...)
	return script
}

func (g *BlockChain) CompTxs(prevNode *chainutil.BlockNode, vm *ovm.OVM) ([]*wire.MsgTx, error) {
	nonce := prevNode.Data.GetNonce()
	var pmh, rbase int32

	reportee := make(map[int32]*wire.MinerBlock)
	var prevminer *chainutil.BlockNode

	if nonce < -wire.MINER_RORATE_FREQ {
		pmh = -(nonce + wire.MINER_RORATE_FREQ)
		mb, err := g.Miners.BlockByHeight(pmh - wire.ViolationReportDeadline)
		if err != nil {
			return nil, err
		}
		reportee[pmh-wire.ViolationReportDeadline] = mb
		rbase = pmh - wire.ViolationReportDeadline
		prevminer = g.Miners.NodeByHeight(pmh - 1)
	} else if nonce > 0 {
		q, m := prevNode, wire.POWRotate
		for ; q != nil && q.Data.GetNonce() > -wire.MINER_RORATE_FREQ; q = q.Parent {
			if q.Data.GetNonce() > 0 {
				m += wire.POWRotate
			}
		}
		if q != nil {
			pmh = int32(m+1) - (q.Data.GetNonce() + wire.MINER_RORATE_FREQ)
			prevminer = g.Miners.NodeByHeight(pmh - 1)
			rbase = pmh - wire.ViolationReportDeadline - wire.POWRotate + 1
			for j, h := 0, rbase; j < wire.POWRotate; j++ {
				mb, err := g.Miners.BlockByHeight(h)
				if err != nil {
					return nil, err
				}
				h++
				reportee[h] = mb
			}
		}
	} else {
		return nil, nil
	}

	// MR blocks to be scanned for reports. to make them in ascending order by height
	mrblks := make([]wire.MingingRightBlock, wire.ViolationReportDeadline+wire.POWRotate)
	for i := 0; i < wire.ViolationReportDeadline+wire.POWRotate; i++ {
		mrblks[wire.ViolationReportDeadline+wire.POWRotate-i-1] = g.Miners.NodetoHeader(prevminer)
		prevminer = prevminer.Parent
	}

	ctransactions := make([]*wire.MsgTx, 0)

	for _, blk := range reportee {
		stx, x, err := g.processviolator(blk, mrblks, vm)
		if err != nil {
			return nil, err
		}

		if stx != nil {
			ctransactions = append(ctransactions, stx)
		}

		if len(x) == 0 {
			continue
		}

		ctx := &wire.MsgTx{}
		ctx.Version = wire.ForfeitTxVersion | wire.TxNoLock | wire.TxNoDefine
		cto := &wire.TxOut{}
		cto.TokenType = 0
		cto.Value = &token.NumToken{0}
		cto.PkScript = make([]byte, len(ADDVTM))
		copy(cto.PkScript, ADDVTM)

		count := uint64(0)
		for _, tx := range x {
			if tx != nil {
				count++
			}
		}

		var ht [8]byte
		common.LittleEndian.PutUint64(ht[:],uint64(blk.Height()))
		cto.PkScript = append(cto.PkScript, ht[:]...)
		common.LittleEndian.PutUint64(ht[:], count)
		cto.PkScript = append(cto.PkScript, ht[:]...)
		cto.PkScript = append(cto.PkScript, []byte{36,0,0,0,0,0,0,0}...)

		sum := int64(0)
		for _, tx := range x {
			if tx == nil {
				continue
			}
			sum += tx.fee + 1000
		}
		if sum <= stx.TxOut[0].Value.(*token.NumToken).Val {
			for _, tx := range x {
				if tx == nil {
					continue
				}
				tx.fee = -tx.fee	// mark it as full payment upon request
			}
		} else {
			bal := stx.TxOut[0].Value.(*token.NumToken).Val
			mr := true
			level := int64(0)
			for mr && count != 0 {
				mr = false
				level = bal / int64(count) - 1000
				for _, tx := range x {
					if tx == nil || tx.fee < 0 {
						continue
					}
					if tx.fee <= level {
						tx.fee = -tx.fee	// mark it as full payment upon request
						bal -= level + 1000
						count--
						mr = true
					}
				}
			}
		}
		for _, tx := range x {
			cto.PkScript = append(cto.PkScript, g.comptx(tx, vm)...)
		}

		ctransactions = append(ctransactions, ctx)
	}
	return ctransactions, nil
}

func (g *BlockChain) processviolator(blk *wire.MinerBlock, mrblks []wire.MingingRightBlock, vm *ovm.OVM) (*wire.MsgTx, map[chainhash.Hash]*txfee, error) {
	reportblks := make(map[[20]byte]int)
	totalblks := 0
	totaltxs := 0
	forfeiture := make([]*chainhash.Hash, 0)

	bhash := blk.Hash()

	for _,u := range mrblks {
		if _,ok := reportblks[u.Miner]; !ok {
			reportblks[u.Miner] = 0
		}
		for _, r := range u.ViolationReport {
			if !bhash.IsEqual(&r.MRBlock)  {
				continue
			}

			totalblks += len(r.Blocks) - 1
			reportblks[u.Miner] = reportblks[u.Miner] + len(r.Blocks) - 1
			for i, _ := range r.Blocks {
				if g.InBestChain(&r.Blocks[i]) {
					continue
				}
				bbk,_ := g.BlockByHash(&r.Blocks[i])
				totaltxs += len(bbk.MsgBlock().Transactions)
				forfeiture = append(forfeiture, &r.Blocks[i])
			}
		}
	}

	if len(forfeiture) == 0 {
		return nil, nil, nil
	}

	// forfeiture tx
	ctx := &wire.MsgTx{}
	ctx.Version = wire.ForfeitTxVersion | wire.TxNoLock | wire.TxNoDefine

	// collateral distributions:
	// 1/8 to all reporters
	// 1/8 to miner
	// 3/4 to victims

	// spend collateral
	avail, forcontract := int64(0), int64(0)
	forfeiturecontract := []byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,171,8,19,20}
	const DEPOSIT = byte(ovm.OP_PAY2PKH)

	ctx.AddTxIn(&wire.TxIn{
		*blk.MsgBlock().Utxos,
		0xFFFFFFFF,
		0xFFFFFFFF,
	})
	tk := g.MainChainTx(blk.MsgBlock().Utxos.Hash)
	u := tk.TxOut[blk.MsgBlock().Utxos.Index].Value.(*token.NumToken).Val
	avail += u
	forcontract += (u * 6) >> 3

	// pay to contract
	rpo := &wire.TxOut{}
	rpo.TokenType = 0
	rpo.Value = &token.NumToken{ forcontract }
	rpo.PkScript = forfeiturecontract
	rpo.PkScript = append(rpo.PkScript, []byte{DEPOSIT,0,0,0}...)
	var ht [8]byte
	common.LittleEndian.PutUint32(ht[:], uint32(blk.Height()))
	rpo.PkScript = append(rpo.PkScript, ht[:]...)
	ctx.AddTxOut(rpo)

	// pay to reporters
	r125 := avail >> 2		// 1/8 of collaterals goes to all reports
	for r,s := range reportblks {
		rpo := &wire.TxOut{}
		rpo.TokenType = 0
		rpo.Value = &token.NumToken{r125 * int64(s) / int64(totalblks) }
		rpo.PkScript = make([]byte, 22)
		rpo.PkScript[0] = g.ChainParams.PubKeyHashAddrID
		copy(rpo.PkScript[1:], r[:])
		rpo.PkScript[21] = ovm.OP_PAY2PKH
		ctx.AddTxOut(rpo)
	}

	processed := make(map[chainhash.Hash]*txfee)
	usable := make(map[wire.OutPoint]int64)

	for _,p := range forfeiture {
		blk,_ := g.BlockByHash(p)
		g.ProcessForfeitBlock(blk, usable, processed, vm)
	}

	return ctx, processed, nil
}

// perpare to make compensation for double signing victims
// this function returns side chain violating blocks that should be compensated
// in the block after prevNode for each violating miner (upto 2).
func (b *BlockChain) PrepForfeit(prevNode *chainutil.BlockNode) ([]reportedblk, int32, error) {
	nonce := prevNode.Data.GetNonce()
	var pmh, rbase int32
	reportee := make(map[int32]*wire.MinerBlock)
	var prevminer *chainutil.BlockNode

	forfeiture := make([]reportedblk, 0)

	if nonce < -wire.MINER_RORATE_FREQ {
		pmh = -(nonce + wire.MINER_RORATE_FREQ)
		mb,err := b.Miners.BlockByHeight(pmh - wire.ViolationReportDeadline)
		if err != nil {
			return nil, 0, err
		}
		reportee[pmh - wire.ViolationReportDeadline] = mb
		rbase = pmh - wire.ViolationReportDeadline
		prevminer = b.Miners.NodeByHeight(pmh - 1)
	} else if nonce > 0	{
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

	// MR blocks to be scanned for reports
	mrblks := make([]wire.MingingRightBlock, wire.ViolationReportDeadline + wire.POWRotate)

	for i := 0; i < wire.ViolationReportDeadline + wire.POWRotate; i++ {
		mrblks[wire.ViolationReportDeadline+wire.POWRotate-i-i] = b.Miners.NodetoHeader(prevminer)
		prevminer = prevminer.Parent
	}
	for _, blk := range mrblks {
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
			for i,_ := range r.Blocks {
				if b.InBestChain(&r.Blocks[i]) {
					continue
				}
				forfeiture = append(forfeiture, reportedblk{
					&r.Blocks[i], &blk.Miner,
				})
			}
		}
	}

	if len(forfeiture) == 0 {
		return nil, 0, nil
	}

	return forfeiture, rbase, nil
}

func (b *BlockChain) CheckForfeit(block *btcutil.Block, prevNode *chainutil.BlockNode, vm *ovm.OVM) error {
	ftxs, err := b.CompTxs(prevNode, vm)
	if err != nil {
		return err
	}

	// all foreit txs in a block must process exactly all violation reports
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
