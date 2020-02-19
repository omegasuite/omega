/* Copyright (C) 2019-2020 omega-chain.com - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
* You should have received a copy of the license with this file.
* If not, please visit: <https://omega-chain.com/license.html>
 */

package validate

import (
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/omega/viewpoint"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
)

type tokenElement struct {
	tokenType uint64
	polygon chainhash.Hash
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
		f, _ := views.Rights.FetchEntry(views.Db, &lh)
		lh = f.(*viewpoint.RightEntry).Father
		if lh.IsEqual(h2) {
			return true
		}
		d--
	}

	return false
}

func TokenRights(views *viewpoint.ViewPointSet, x interface{}) []chainhash.Hash {
	hasneg := []chainhash.Hash{{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,},}

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
	}

	var y []chainhash.Hash
	if tokenType & 3 == 1 {
		y = hasneg
	} else {
		t, _ := views.Rights.FetchEntry(views.Db, rs)
		if yy := viewpoint.SetOfRights(views, t); yy != nil {
			y := make([]chainhash.Hash, 0, len(yy))
			for _, r := range yy {
				y = append(y, r.ToToken().Hash())
			}
		}
	}
	return y
}

func parseRights(tx *btcutil.Tx, views *viewpoint.ViewPointSet, checkPolygon bool, uncheck uint64) * map[chainhash.Hash]struct{}  {
	neg := chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }

	// put all rights in input & output to rset
	rset := make(map[chainhash.Hash]struct{})
	rset[neg] = struct{}{}

	for _, txOut := range tx.MsgTx().TxOut {
		if !checkPolygon && txOut.TokenType & 1 == uncheck {
			continue
		}
		if txOut.TokenType == 0xFFFFFFFFFFFFFFFF || txOut.TokenType & 3 == 1 {
			continue
		}

		if txOut.Rights != nil {
			p := views.Rights.LookupEntry(*txOut.Rights)
			if p == nil {
				views.Rights.FetchEntry(views.Db, txOut.Rights)
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

	for _, x := range tx.Spends {
		if x.TokenType & 1 == 0 {
			continue
		}
		if x.TokenType & 3 == 1 {
			continue
		}

		if x.Rights != nil {
			p := views.Rights.LookupEntry(*x.Rights)
			if p == nil {
				views.Rights.FetchEntry(views.Db, x.Rights)
				p = views.Rights.LookupEntry(*x.Rights)
			}

			switch p.(type) {
			case *viewpoint.RightSetEntry:
				for _, r := range p.(*viewpoint.RightSetEntry).Rights {
					if _, ok := rset[r]; !ok {
						rset[r] = struct{}{}
					}
				}
			case *viewpoint.RightEntry:
				rset[*x.Rights] = struct{}{}
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
				p,_ := view.Rights.FetchEntry(view.Db, &as[i-1])
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
	neg := chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }
	roots := make(map[chainhash.Hash]int32, 0)

	for r,_ := range * rset {
		p := view.Rights.LookupEntry(r)
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
		if r.IsEqual(&neg) {
			continue
		}
		p := view.Rights.LookupEntry(r)
		ok := true
		for _,ok = (*rset)[p.(*viewpoint.RightEntry).Father]; !ok && p.(*viewpoint.RightEntry).Depth > roots[p.(*viewpoint.RightEntry).Root]; {
			ancester[r] = append(ancester[r], p.(*viewpoint.RightEntry).Father)
			p,_ = view.Rights.FetchEntry(view.Db, &p.(*viewpoint.RightEntry).Father)
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
	value token.TokenValue
}

func ioTokens(tx *btcutil.Tx, views *viewpoint.ViewPointSet) [][]tokennelement {
	res := make([][]tokennelement, 2)
	res[0] = make([]tokennelement, 0, len(tx.MsgTx().TxIn))
	res[1] = make([]tokennelement, 0, len(tx.MsgTx().TxOut))

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
	for i, x := range tx.MsgTx().TxOut {
		if x.TokenType == 0xFFFFFFFFFFFFFFFF {
			continue
		}
		res[1][i] = tokennelement{}
		res[1][i].tokenType = x.TokenType
		if x.TokenType & 1 == 1 {
			res[1][i].polygon = x.Value.(*token.HashToken).Hash
		}
		if x.TokenType & 2 == 2 {
			res[1][i].right = *x.Rights
		}
		res[1][i].value = x.Value
	}
	return res
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

	rset := parseRights(tx, views, checkPolygon, 1)

	ancester := getAncester(rset, views)

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
					e := views.Rights.LookupEntry(s).(*viewpoint.RightEntry)
					if e.Attrib & token.Monitored != 0 && emt.tokenType != 3 {
						return false, fmt.Errorf("Non-polygon token can not have monitored right")
					}
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
			e := views.Rights.LookupEntry(r.right).(*viewpoint.RightEntry)
			if e == nil {
				continue
			}

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
