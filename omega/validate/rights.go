/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package validate

import (
	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/token"
	"github.com/omegasuite/omega/viewpoint"
)

type tokenElement struct {
	tokenType uint64
	right chainhash.Hash
}

func decentOf(son * viewpoint.RightEntry, h * chainhash.Hash, anc * viewpoint.RightEntry, h2 * chainhash.Hash,
	views *viewpoint.ViewPointSet) bool {
	if !son.Root.IsEqual(&anc.Root) {
		return false
	}

	d := anc.Depth - son.Depth
	lh := *h
	for d > 0 {
		f, _ := views.FetchRightEntry(&lh)
		lh = f.(*viewpoint.RightEntry).Father
		if lh.IsEqual(h2) {
			return true
		}
		d--
	}

	return false
}

func TokenRights(views *viewpoint.ViewPointSet, x interface{}) []chainhash.Hash {
//	hasneg := []chainhash.Hash{{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
//		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,},}

	var tokenType uint64
	var rs * chainhash.Hash

	switch x.(type) {
	case * viewpoint.UtxoEntry:
		tokenType = x.(* viewpoint.UtxoEntry).TokenType
		rs = x.(* viewpoint.UtxoEntry).Rights
		break
	case * wire.TxOut:
		tokenType = x.(* wire.TxOut).TokenType
		rs = x.(* wire.TxOut).Rights
		break
	case * tokenElement:
		tokenType = x.(* tokenElement).tokenType
		rs = & x.(*tokenElement).right
		break
	case * tokennelement:
		tokenType = x.(* tokennelement).tokenType
		rs = & x.(*tokennelement).right
		break
	}

	y := make([]chainhash.Hash, 0)

	if tokenType & 2 != 0 {
		t, _ := views.FetchRightEntry(rs)
		if yy := viewpoint.SetOfRights(views, t); yy != nil {
			for _, r := range yy {
				y = append(y, r.ToToken().Hash())
			}
		}
	}
	return y
}

func parseRights(tx *btcutil.Tx, views *viewpoint.ViewPointSet, checkPolygon bool, uncheck uint64) * map[chainhash.Hash]struct{}  {
//	neg := chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }

	// put all rights in input & output to rset
	rset := make(map[chainhash.Hash]struct{})
//	rset[neg] = struct{}{}

	txouts := make([]*wire.TxOut, 0, len(tx.MsgTx().TxOut) + len(tx.MsgTx().TxIn))

	for i, n := 0, len(tx.MsgTx().TxOut); i < n; i++ {
		if tx.MsgTx().TxOut[i].IsSeparator() {
			continue
		}
		txouts = append(txouts, tx.MsgTx().TxOut[i])
	}
	for i, n := 1, len(tx.MsgTx().TxIn); i < n; i++ {
		if tx.MsgTx().TxIn[i].IsSeparator() {
			continue
		}
		txin := views.Utxo.LookupEntry(tx.MsgTx().TxIn[i].PreviousOutPoint)
		txouts = append(txouts, txin.ToTxOut())
	}

	for _, txOut := range txouts {
		if !checkPolygon && txOut.TokenType & 1 == uncheck {
			continue
		}
		if txOut.TokenType & 2 == 0 {
			continue
		}

		if txOut.Rights != nil {
			p := views.Rights.LookupEntry(*txOut.Rights)
			if p == nil {
				views.FetchRightEntry(txOut.Rights)
				p = views.Rights.LookupEntry(*txOut.Rights)
			}

			switch p.(type) {
			case *viewpoint.RightSetEntry:
				for _, r := range p.(*viewpoint.RightSetEntry).Rights {
					if _, ok := rset[r]; !ok {
						rset[r] = struct{}{}
					}
				}
			case *viewpoint.RightEntry:
				rset[*txOut.Rights] = struct{}{}
			}
		}
	}

	return &rset
}

func getBasicRightSet(rset map[chainhash.Hash]struct{}, view * viewpoint.ViewPointSet) map[chainhash.Hash]struct{} {
	ancester := getAncester(&rset, view)

	for _, as := range *ancester {
		for i := len(as) - 1; i > 0; i-- {
			if _, ok := rset[as[i]]; ok {
				p,_ := view.FetchRightEntry(&as[i-1])
				q := p.(*viewpoint.RightEntry).Sibling()
				delete(rset, as[i])
				rset[q] = struct{}{}
				rset[as[i-1]] = struct{}{}
			}
		}
	}

	return rset
}

func getAncester(rset * map[chainhash.Hash]struct{}, view * viewpoint.ViewPointSet) * map[chainhash.Hash][]chainhash.Hash {
	// for every right in rset, if it is decendent of another, find out all the links between them
	// put the relationship in ancester
//	neg := chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }
	roots := make(map[chainhash.Hash]int32, 0)

	for r,_ := range * rset {
		p,_ := view.FetchRightEntry(&r)
		if p == nil {
			continue
		}
		rt := p.(*viewpoint.RightEntry).Root
		if _,ok := roots[rt]; !ok {
			roots[rt] = p.(*viewpoint.RightEntry).Depth
		} else if roots[rt] > p.(*viewpoint.RightEntry).Depth {
			roots[rt] = p.(*viewpoint.RightEntry).Depth
		}
	}

	ancester := make(map[chainhash.Hash][]chainhash.Hash)
	for r,_ := range * rset {
		ancester[r] = make([]chainhash.Hash, 1, 5)
		ancester[r][0] = r
//		if r.IsEqual(&neg) {
//			continue
//		}
		p := view.Rights.LookupEntry(r)
		ok := true
		for _,ok = (*rset)[p.(*viewpoint.RightEntry).Father]; !ok && p.(*viewpoint.RightEntry).Depth > roots[p.(*viewpoint.RightEntry).Root]; {
			ancester[r] = append(ancester[r], p.(*viewpoint.RightEntry).Father)
			p,_ = view.FetchRightEntry(&p.(*viewpoint.RightEntry).Father)
		}
		if !ok {
			ancester[r] = make([]chainhash.Hash, 1)
			ancester[r][0] = r
		} else {
//			ancester[r] = append(ancester[r], p.(*viewpoint.RightEntry).Father)
//			if len(ancester[p.(*viewpoint.RightEntry).Father]) > 1 {
				ancester[r] = append(ancester[r], ancester[p.(*viewpoint.RightEntry).Father][:]...)
//			}
		}
	}

	// make it everyone's ancester all the way to the highest
	repeat := true
	for repeat {
		repeat = false
		for r,s := range ancester {
			if len(s) > 1 {
				p := s[len(s)-1]
				if len(ancester[p]) > 1 {
					repeat = true
					ancester[r] = append(ancester[r], ancester[p][1:]...)
				}
			}
		}
	}

	return &ancester
}

type tokennelement struct {
	tokenElement
	polygon chainhash.Hash
	value token.TokenValue
}

func ioTokens(tx *btcutil.Tx, views *viewpoint.ViewPointSet) [][]tokennelement {
	res := [2][]tokennelement {make([]tokennelement, 0, len(tx.MsgTx().TxIn)),
		make([]tokennelement, 0, len(tx.MsgTx().TxOut))}
	for _, y := range tx.MsgTx().TxIn {
		if y.IsSeparator() {
			continue
		}
		x := views.Utxo.LookupEntry(y.PreviousOutPoint).ToTxOut()
		te := tokennelement{}
		te.tokenType = x.TokenType
		if x.TokenType & 1 == 1 {
			te.polygon = x.Value.(*token.HashToken).Hash
		}
		if x.TokenType & 2 == 2 {
			te.right = *x.Rights
		}
		te.value = x.Value
		res[0] = append(res[0], te)
	}
/*
	for i, x := range tx.Spends {
		res[0][i] = tokennelement{}
		res[0][i].tokenType = x.TokenType
		if x.TokenType & 1 == 1 {
			res[0][i].polygon = x.Value.(*token.HashToken).Hash
		}
		if x.TokenType & 2 == 2 {
			res[0][i].right = *x.Rights
		}
		res[0][i].value = x.Value
	}
 */
	for _, x := range tx.MsgTx().TxOut {
		if x.IsSeparator() {
			continue
		}
		te := tokennelement{}
		te.tokenType = x.TokenType
		if x.TokenType & 1 == 1 {
			te.polygon = x.Value.(*token.HashToken).Hash
		}
		if x.TokenType & 2 == 2 {
			te.right = *x.Rights
		}
		te.value = x.Value
		res[1] = append(res[1], te)
	}
	return res[:]
}

func monitored(r * token.RightSetDef, views *viewpoint.ViewPointSet) bool {
	for _,d := range r.Rights {
		e, _ := views.FetchRightEntry(&d)
		if e.(*viewpoint.RightEntry).Attrib & token.Monitored != 0 {
			return true
		}
	}
	return false
}

// handle monitored tokens. In a Tx, if any token has monitored right, then all the input/output must have
// monitored right, monitor, or a father of monitored right
func QuickCheckRight(tx *btcutil.Tx, views *viewpoint.ViewPointSet) (bool, error) {
	checkPolygon := true

	for _, txDef := range tx.MsgTx().TxDef {
		switch txDef.(type) {
		case *token.PolygonDef:
			checkPolygon = false
		}
	}

	zerohash := chainhash.Hash{}
	polyhash := chainhash.Hash{}
	if checkPolygon {
		// is there more than one polygon?
		for _, txOut := range tx.MsgTx().TxOut {
			if txOut.IsSeparator() {
				continue
			}
			if txOut.TokenType == 3 && checkPolygon {
				if polyhash.IsEqual(&zerohash) {
					polyhash = txOut.Token.Value.(*token.HashToken).Hash
				} else if !txOut.Token.Value.(*token.HashToken).Hash.IsEqual(&polyhash) {
					checkPolygon = false
				}
			}
		}
	}
	if checkPolygon {
		for _, txIn := range tx.MsgTx().TxIn {
			if txIn.IsSeparator() {
				continue
			}
			txin := views.Utxo.LookupEntry(txIn.PreviousOutPoint).ToTxOut()
			if txin.TokenType == 3 && checkPolygon && txin.Rights != nil {
				rt := views.Rights.LookupEntry(*txin.Rights)
				var m bool
				switch rt.(type) {
				case *viewpoint.RightSetEntry:
					rv := rt.(*viewpoint.RightSetEntry).ToToken()
					m = monitored(rv, views)
				case *viewpoint.RightEntry:
					m = monitored(&token.RightSetDef{Rights:[]chainhash.Hash{*txin.Rights}}, views)
				}

				if m {
					checkPolygon = false
				} else if polyhash.IsEqual(&zerohash) {
					polyhash = txin.Token.Value.(*token.HashToken).Hash
				} else if !txin.Token.Value.(*token.HashToken).Hash.IsEqual(&polyhash) {
					checkPolygon = false
				}
			}
		}
	}

	// we can treat polygon as a hash token only if there is no more than one polygon in IO
	rset := parseRights(tx, views, checkPolygon,1)

	ancester := getAncester(rset, views)

	// Use superset method for right validation.
	// calculate right sum, a right is expressed as its top ancester minus all the siblings of
	// itself & other non-top ancesters
	sumVals := make(map[tokenElement]int64)

	tokens := ioTokens(tx, views)
	fval := []int64{-1, 1}

	for io, tks := range tokens {
		for _, emt := range tks {
			y := TokenRights(views, &emt)

			for _, r := range y {
				for i, s := range (*ancester)[r] {
					f := fval[io]
					g := views.Rights.LookupEntry(s)
					if g == nil {
						continue
					}
					e := g.(*viewpoint.RightEntry)
//					if e.Attrib & token.Monitored != 0 && emt.tokenType != 3 {
//						return false, fmt.Errorf("Non-polygon token can not have monitored right")
//					}
					if i == len((*ancester)[r])-1 {
						f = - fval[io]
						emt.right = s
					} else {
						emt.right = e.Sibling()
					}
					if emt.tokenType&1 == 0 {
						f *= emt.value.(*token.NumToken).Val
					}
					if _, ok := sumVals[emt.tokenElement]; ok {
						sumVals[emt.tokenElement] += f
					} else {
						sumVals[emt.tokenElement] = f
					}
				}
			}
		}
	}

	// Right merge
	for merge := true; merge; {
		// repeat until nothing to merge
		merge = false
		for r, g := range sumVals {
			s := r
			f := views.Rights.LookupEntry(r.right)
			if f == nil {
				continue
			}
			e := f.(*viewpoint.RightEntry)

			s.right = e.Sibling()
			p := r
			if _, ok := sumVals[s]; !ok {
				continue
			}
			p.right = e.Father

			if m, ok := sumVals[s]; ok {
				if m * g < 0 {
					// different sign, can not merge
					continue
				}
				if _, ok = sumVals[p]; !ok {
					sumVals[p] = 0
				}
				if m == g {
					delete(sumVals, r)
					delete(sumVals, s)
					sumVals[p] += m
				} else {
					if iabs(m) > iabs(g) {
						delete(sumVals, r)
						sumVals[p] += g
					} else {
						delete(sumVals, s)
						sumVals[p] += m
					}
				}
				merge = true
			}
		}
	}

	// is i/o balanced?
	nz := 0
	for emt,v := range sumVals {
		if v != 0 && emt.tokenType & 0x1 == 0 {
			str := fmt.Sprintf("Tx %v input does not match output in rights.", tx.Hash())
			return false, ruleError(1, str)
		} else if v != 0 {
			nz++
		}
	}

	if nz == 0 && checkPolygon {
		return true, nil
	}

	return false, nil
}
