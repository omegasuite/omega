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
	"github.com/omegasuite/omega/viewpoint"
)

type reportedblk struct {
	block * chainhash.Hash
	reporter * [20]byte
}

type txfee struct {
	tx * btcutil.Tx
	fee int64
	sure int64
	payees [][21]byte
}

// CompTxs is the main function to genrate compensation transactions.
func (g *BlockChain) CompTxs(prevNode *chainutil.BlockNode, views *viewpoint.ViewPointSet) ([]*wire.MsgTx, error) {
	// prevNode is the node in tx chain just before us. it normally is tip of chain

	// we only do compensation in the first block after rotation. i.e., nonce of prev block
	// is either positive or less than MINER_RORATE_FREQ
	nonce := prevNode.Data.GetNonce()
	var pmh, rbase int32

	reportee := make(map[int32]*wire.MinerBlock)
	var prevminer *chainutil.BlockNode

	// determine the violator that should be processed. the reporting deadline is 100 (ViolationReportDeadline)
	// MR blocks. the violator is the 100-th block (or two blocks) before the just-rotated-in MR block
	if nonce < -wire.MINER_RORATE_FREQ {
		pmh = -(nonce + wire.MINER_RORATE_FREQ)
		prevminer = g.Miners.NodeByHeight(pmh - 1)
		mb, err := g.Miners.BlockByHeight(pmh - wire.ViolationReportDeadline)
		if err != nil {
			return nil, err
		}
		reportee[pmh-wire.ViolationReportDeadline] = mb
		rbase = pmh - wire.ViolationReportDeadline
	} else if nonce > 0 {
		q, m := prevNode, 0
		for ; q != nil && q.Data.GetNonce() > -wire.MINER_RORATE_FREQ; q = q.Parent {
			if q.Data.GetNonce() > 0 {
				m += wire.POWRotate
			}
		}
		if q != nil {
			pmh = - (q.Data.GetNonce() + wire.MINER_RORATE_FREQ) + int32(m)
			prevminer = g.Miners.NodeByHeight(pmh - 1)
			rbase = pmh - wire.ViolationReportDeadline - int32(m)
			for j, h := 0, rbase; j < m; j++ {
				mb, err := g.Miners.BlockByHeight(h)
				if err != nil {
					return nil, err
				}
				reportee[h] = mb
				h++
			}
		}
	} else {
		return nil, nil
	}

	// MR blocks to be scanned for reports. to make them in ascending order by height
	// get the MR blocks between the violator and the rotated-in MR blocks. the violation reports
	// if any are in these blocks
	mrblks := make([]wire.MingingRightBlock, wire.ViolationReportDeadline+wire.POWRotate)
	for i := 0; i < wire.ViolationReportDeadline+wire.POWRotate; i++ {
		mrblks[wire.ViolationReportDeadline+wire.POWRotate-i-1] = g.Miners.NodetoHeader(prevminer)
		prevminer = prevminer.Parent
	}

	avgtx := -1

	// usage score by addresses
	usescores := make(map[[21]byte]uint32)

	ctransactions := make([]*wire.MsgTx, 0)
	for _, blk := range reportee {
		// process one violator at a time. stx contains the awards to reporters. x is the list
		// of victims to be compensated
		stx, x, err := g.processviolator(blk, mrblks, views)
		if err != nil {
			return nil, err
		}

		if stx == nil {
			// this miner is innocent
			continue
		}

		ctransactions = append(ctransactions, stx)

		// this is the opening contract call
		bal := stx.TxOut[0].Value.(*token.NumToken).Val

		if len(x) == 0 {
			// no claim. no need to open, destroy the entire bal.
			stx.TxOut[0].PkScript = []byte{g.ChainParams.PubKeyHashAddrID, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ovm.OP_PAY2NONE}
			continue
		}

		ctx := &wire.MsgTx{}
		ctx.Version = wire.ForfeitTxVersion | wire.TxNoLock | wire.TxNoDefine
		cto := &wire.TxOut{}
		cto.TokenType = 0

		cto.Value = &token.NumToken{0}
		cto.PkScript = make([]byte, 25)
		// contract call for filing claim records
		copy(cto.PkScript, g.ChainParams.Forfeit.Contract[:])
		copy(cto.PkScript[21:], g.ChainParams.Forfeit.Filing[:])

		count, sum := uint64(0), int64(0)
		// is available fund more than what is needed to compensate all? if yes, no
		// nned to prioritize txs
		for _, tx := range x {
			if tx != nil {
				sum += tx.fee
				count++
			}
		}

		var ht [8]byte
		// claim record call parameters: paypoint, count, claim list
		// paypoint
		common.LittleEndian.PutUint64(ht[:], uint64(blk.Height()))
		cto.PkScript = append(cto.PkScript, ht[:]...)
		// count
		common.LittleEndian.PutUint64(ht[:], count)
		cto.PkScript = append(cto.PkScript, ht[:]...)

//		cto.PkScript = append(cto.PkScript, []byte{36, 0, 0, 0, 0, 0, 0, 0}...)

		if sum <= bal {
			for _, tx := range x {
				if tx == nil {
					continue
				}
				tx.sure = tx.fee // mark it as full payment upon request
			}
			// destroy the left over
			if sum < bal {
				leftover := &wire.TxOut{}
				leftover.Value = &token.NumToken{bal - sum}
				leftover.TokenType = 0
				leftover.PkScript = []byte{g.ChainParams.PubKeyHashAddrID, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ovm.OP_PAY2NONE}
				ctx.AddTxOut(leftover)
			}

			// append claim list for txs
			for _, tx := range x {
				cto.PkScript = append(cto.PkScript, g.comptx(tx)...)
			}

			ctx.AddTxOut(cto)

			ctransactions = append(ctransactions, ctx)
			continue
		}

		if avgtx < 0 {
			// get 200 block avergae txs in the reporting period. we will decide allocation unit based on this
			// reporting period = ViolationReportDeadline (100) * MINER_RORATE_FREQ (200)
			for i, p := 0, prevNode; i < wire.ViolationReportDeadline * wire.MINER_RORATE_FREQ; i++ {
				t,_ := g.BlockByHash(&p.Hash)
				if t == nil {
					return nil, nil
				}
				avgtx += len(t.MsgBlock().Transactions) - 1
				p = p.Parent
			}
			avgtx /= wire.ViolationReportDeadline		// should we use avg txs in 1 rotation , or 2, or 3?
			if avgtx < 10 {
				avgtx = 10
			}
		}

		// collateral is not enough to pay all, need to decide who gets paid first
		// score calculation closure
		score := func(tx *txfee) uint32 {
			s := uint32(0xFFFFFFFF)
			for _, adr := range tx.payees {
				if _, ok := usescores[adr]; !ok {
					if s > usescores[adr] {
						s = usescores[adr]
					}
				}
			}
			return s
		}

		for _, tx := range x {
			if tx != nil {
				s := uint32(0xFFFFFFFF)
				for _, adr := range tx.payees {
					if _, ok := usescores[adr]; !ok {
						var address btcutil.Address
						switch adr[0] {
						case g.ChainParams.PubKeyHashAddrID:
							address, _ = btcutil.NewAddressPubKeyHash(adr[1:], g.ChainParams)
						case g.ChainParams.ContractAddrID:
							address, _ = btcutil.NewAddressContract(adr[1:], g.ChainParams)
						case g.ChainParams.ScriptHashAddrID:
							address, _ = btcutil.NewAddressScriptHash(adr[1:], g.ChainParams)
						case g.ChainParams.MultiSigAddrID:
							address, _ = btcutil.NewAddressMultiSig(adr[1:], g.ChainParams)
						}
						usescores[adr] = g.AddrUsage(address)
					}
					if s > usescores[adr] {
						s = usescores[adr]
					}
				}
			}
		}

		// now we allocate fund by their uscore
		for bal > 0 && count > 0 {
			admit := uint32(0)
			for _, tx := range x {
				if tx != nil {
					t := score(tx)
					if t > admit {
						admit = t
					}
				}
			}

			allocunit := bal / int64(count)
			if count > uint64(avgtx) {
				allocunit = bal / int64(avgtx)
			}

			for _, tx := range x {
				if tx == nil || tx.fee == tx.sure || admit > score(tx) {
					continue
				}
				allocable := allocunit
				if allocunit > bal {
					allocable = bal
				}
				if tx.fee > allocable {
					tx.sure += allocable
					tx.fee -= allocable
					bal -= allocable
				} else {
					bal -= (tx.fee - tx.sure)
					tx.sure += tx.fee
					tx.fee = 0
					count--
				}
				for _,adr := range tx.payees {
					if usescores[adr] > 0 {
						usescores[adr]--
					}
				}
			}
		}

		// append contract script for txs
		for _, tx := range x {
			if tx != nil {
				cto.PkScript = append(cto.PkScript, g.comptx(tx)...)
			}
		}

		ctx.AddTxOut(cto)

		ctransactions = append(ctransactions, ctx)
	}

	return ctransactions, nil
}

// process violation by one miner (blk). the reports are in mrblks
// returns: 1. a transaction giving awards to reporters 2. a list of victim txs to be compansated
func (g *BlockChain) processviolator(blk *wire.MinerBlock, mrblks []wire.MingingRightBlock, views *viewpoint.ViewPointSet) (*wire.MsgTx, map[chainhash.Hash]*txfee, error) {
	reportblks := make(map[[20]byte]int)
	totalblks := 0
	totaltxs := 0
	forfeiture := make([]*chainhash.Hash, 0)

	bhash := blk.Hash()

	// reporter award are given proportional to the number of violating blocks they
	// report. so the first step is to collect number of blocks reported by each reporter
	for _,u := range mrblks {
		if _,ok := reportblks[u.Miner]; !ok {
			reportblks[u.Miner] = 0
		}
		for _, r := range u.ViolationReport {
			if !bhash.IsEqual(&r.MRBlock)  {
				continue
			}
			// if collateral is gone, skip it

			mrb, err := g.Miners.BlockByHash(&r.MRBlock)
			if err != nil || mrb == nil {
				continue
			}
			op := mrb.MsgBlock().Utxos

			e := views.Utxo.LookupEntry(*op)
/*			if e == nil {
				ftchs := make(map[wire.OutPoint]struct{})
				ftchs[*op] = struct{}{}
				views.Utxo.FetchUtxosMain(views.Db, ftchs)
				e = views.Utxo.LookupEntry(*op)
			}
 */
			if e == nil {
				continue
			}
			totalblks += len(r.Blocks) - 1
			reportblks[u.Miner] = reportblks[u.Miner] + len(r.Blocks) - 1
			for i, _ := range r.Blocks {
				if g.InBestChain(&r.Blocks[i]) {
					continue
				}
				bbk,_ := g.HashToBlock(&r.Blocks[i])
				totaltxs += len(bbk.MsgBlock().Transactions)
				forfeiture = append(forfeiture, &r.Blocks[i])
			}
		}
	}

	// nothing reported.
	if len(forfeiture) == 0 {
		return nil, nil, nil
	}

	// forfeiture tx
	ctx := &wire.MsgTx{}
	ctx.Version = wire.ForfeitTxVersion | wire.TxNoLock | wire.TxNoDefine

	// collateral distributions:
	// 1/8 to all reporters
	// 1/8 to miner (by holding back from distribution)
	// upto 3/4 to victims
	// any leftover collateral will be destroyed.

	// spend collateral
	const DEPOSIT = byte(ovm.OP_PAY2PKH)

	ctx.AddTxIn(&wire.TxIn{
		*blk.MsgBlock().Utxos,
		0xFFFFFFFF,
		0xFFFFFFFF,
	})
	tk := g.MainChainTx(blk.MsgBlock().Utxos.Hash)
	avail := tk.TxOut[blk.MsgBlock().Utxos.Index].Value.(*token.NumToken).Val
	forcontract := (avail * 6) >> 3

	// pay to forfeiture disbursing contract. we use a contract instead of handing out directly
	// for 1. flexibility of changing disbursing policy in the future by consensus of community
	// 2. if a victim does claim award in certain time, the award is considered abandoned and
	// the fund will be divert to someone claim it. thus a claim step by victim is needed.
	rpo := &wire.TxOut{}
	rpo.TokenType = 0
	rpo.Value = &token.NumToken{ forcontract }
	rpo.PkScript = make([]byte, 21, 25)
	copy(rpo.PkScript, g.ChainParams.Forfeit.Contract[:])
	rpo.PkScript = append(rpo.PkScript, g.ChainParams.Forfeit.Opening[:]...)	// open contract call
	var ht [8]byte
	common.LittleEndian.PutUint32(ht[:], uint32(blk.Height()))
	rpo.PkScript = append(rpo.PkScript, ht[:]...)
	ctx.AddTxOut(rpo)

	// pay to reporters
	r125 := avail >> 3		// 1/8 of collaterals goes to all reports
	for r,s := range reportblks {
		if s == 0 {
			continue
		}
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

	// collect victim txs to compensate
	for _,p := range forfeiture {
		blk,_ := g.HashToBlock(p)
		g.processForfeitBlock(blk, usable, processed)
	}

	return ctx, processed, nil
}

func (g *BlockChain) processForfeitBlock(b *btcutil.Block,
	usable map[wire.OutPoint]int64,	processed map[chainhash.Hash]*txfee) {
	// scan for qualified txs. coinbase is not qualified of course
	for _, tx := range b.Transactions()[1:] {
		if tx.MsgTx().Version & wire.TxTypeMask > wire.TxVersion || g.MainChainTx(*tx.Hash()) != nil{
			// it is a forfeiture tx, ignore;  no comp if the tx is also in main chain
			continue
		}
		if _, ok := processed[*tx.Hash()]; ok {
			// no comp if the tx has already been processed
			continue
		}
		// check database, if it has been compensated (e.g., by another violator signed the same block)
		if g.compensatedTx(tx.Hash()) {
			// record it to avoid db access in the future
			processed[*tx.Hash()] = nil
			continue
		}

		// calculate tx fees paid
		out, in := int64(0), int64(0)
		// calculate input sum
		for _, txin := range tx.MsgTx().TxIn {
			if txin.PreviousOutPoint.Hash.IsEqual(&zerohash) {
				continue
			}
			if u, ok := usable[txin.PreviousOutPoint]; ok {
				in += u
			} else {
				tk := g.MainChainTx(txin.PreviousOutPoint.Hash)
				if tk == nil || txin.PreviousOutPoint.Index >= uint32(len(tk.TxOut)) || tk.TxOut[txin.PreviousOutPoint.Index].TokenType != 0 {
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
			if txo.IsSeparator() || txo.TokenType != 0 {
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

		// calculate number of payees. if no, no payment
		payees := make([][21]byte, 0)
		mn := uint16(0)
		for _,tto := range tx.MsgTx().TxOut {
			if tto.IsSeparator() {
				// can not compensate contract calls because contracts don't know
				// how to express agreement to a settlement plan. leave to future
				continue
			}

			var pye [21]byte
			if tto.PkScript[0] == g.ChainParams.ContractAddrID {
					continue
			} else {
				copy(pye[:], tto.PkScript[:21])
			}
			payees = append(payees, pye)
			mn++
		}
		if mn == 0 {
			// no comp
			processed[*tx.Hash()] = nil
			continue
		}

		processed[*tx.Hash()] = &txfee{ tx, (in - out) * 10000, 0,  payees}
	}
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

func (g *BlockChain) comptx(tx *txfee) []byte {
	added := int64(0)
	scripts := make([]byte, 4)
	mn := uint16(0)

	for _,tto := range tx.tx.MsgTx().TxOut {
		if tto.IsSeparator() {
			continue
		}
		if tto.PkScript[0] == g.ChainParams.ContractAddrID {
				continue
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
	script := make([]byte, 0, 32 + 8 + 8 + 8 + 22 + 4)
	script = append(script, tx.tx.Hash()[:]...)

	var fee [8]byte
	common.LittleEndian.PutUint64(fee[:], uint64(tx.fee))
	script = append(script, fee[:]...)

	common.LittleEndian.PutUint64(fee[:], uint64(tx.sure))
	script = append(script, fee[:]...)

	script = append(script, scripts[:]...)
	return script
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

func (b *BlockChain) CheckForfeit(block *btcutil.Block, prevNode *chainutil.BlockNode, views *viewpoint.ViewPointSet) error {
	nonce := prevNode.Data.GetNonce()
	if nonce < 0 && nonce > -wire.MINER_RORATE_FREQ {
		// this is not a block after rotation, make sure there is no Forfeit tx
		for _,tx := range block.MsgBlock().Transactions[1:] {
			if tx.IsForfeit() {
				return fmt.Errorf("Incorrect forfeiture txs. Forfeit in a son of non rotation signed block at height %d.", block.Height())
			}
		}
		return nil
	}

	ftxs, err := b.CompTxs(prevNode, views)
	if err != nil {
		return err
	}

	// all foreit txs in a block must process exactly all violation reports
	cnt := 0
	for i,tx := range block.MsgBlock().Transactions[1:] {
		if !tx.IsForfeit() {
			if len(ftxs) > i {
				return fmt.Errorf("Incorrect forfeiture txs. Less forfeiture txs than required %d. Forfeited UTXO: %s",
					len(ftxs), ftxs[i].TxIn[0].PreviousOutPoint.String())
			}
			return nil
		}
		if len(ftxs) < i + 1 {
			return fmt.Errorf("Incorrect forfeiture txs. More forfeiture txs than required %d", len(ftxs))
		}
		cnt++

		var w1 bytes.Buffer
		var w2 bytes.Buffer
		if err := tx.SerializeFull(&w1); err != nil {
			return err
		}
		if err := ftxs[i].SerializeFull(&w2); err != nil {
			return err
		}
		if bytes.Compare(w1.Bytes(), w2.Bytes()) != 0 {
			return fmt.Errorf("Incorrect forfeiture txs. ")
		}
	}

	if len(ftxs) != cnt {
		t := ""
		if len(ftxs) > cnt {
			t = "missing" + ftxs[cnt].TxIn[0].PreviousOutPoint.String()
		}

		return fmt.Errorf("Incorrect forfeiture txs. Block has %d forfeiture tx while %d is expected. %s",
			cnt, len(ftxs), t)
	}

	return nil
}
