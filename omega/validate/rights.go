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
	right     chainhash.Hash
}

type tokenRElement struct {
	tokenType uint64
	right     chainhash.Hash
	polygon   chainhash.Hash
}

func decentOf(son *viewpoint.RightEntry, h *chainhash.Hash, anc *viewpoint.RightEntry, h2 *chainhash.Hash,
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
	var rs *chainhash.Hash

	switch x.(type) {
	case *viewpoint.UtxoEntry:
		tokenType = x.(*viewpoint.UtxoEntry).TokenType
		rs = x.(*viewpoint.UtxoEntry).Rights
		break
	case *wire.TxOut:
		tokenType = x.(*wire.TxOut).TokenType
		rs = x.(*wire.TxOut).Rights
		break
	case *tokenElement:
		tokenType = x.(*tokenElement).tokenType
		rs = &x.(*tokenElement).right
		break
	case *tokennelement:
		tokenType = x.(*tokennelement).tokenType
		rs = &x.(*tokennelement).right
		break
	}

	y := make([]chainhash.Hash, 0)

	if tokenType&2 != 0 {
		t, _ := views.FetchRightEntry(rs)
		if yy := viewpoint.SetOfRights(views, t); yy != nil {
			for _, r := range yy {
				y = append(y, r.ToToken().Hash())
			}
		} else {
			y = append(y, *rs)
		}
	}
	return y
}

func parseRights(tx *btcutil.Tx, views *viewpoint.ViewPointSet, checkPolygon bool, uncheck uint64) *map[chainhash.Hash]struct{} {
	//	neg := chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	//		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }

	// put all rights in input & output to rset
	rset := make(map[chainhash.Hash]struct{})
	//	rset[neg] = struct{}{}

	txouts := make([]*wire.TxOut, 0, len(tx.MsgTx().TxOut)+len(tx.MsgTx().TxIn))

	for _, txo := range tx.MsgTx().TxOut {
		if txo.IsSeparator() || txo.TokenType&2 == 0 {
			continue
		}
		txouts = append(txouts, txo)
	}
	for _, txin := range tx.MsgTx().TxIn {
		if txin.PreviousOutPoint.Hash.IsEqual(&zerohash) {
			continue
		}
		tin := views.Utxo.LookupEntry(txin.PreviousOutPoint).ToTxOut()
		if tin.TokenType&2 != 0 {
			txouts = append(txouts, tin)
		}
	}

	for _, txOut := range txouts {
		if !checkPolygon && txOut.TokenType&1 == uncheck {
			continue
		}

		if txOut.Rights != nil {
			//			p := views.Rights.LookupEntry(*txOut.Rights)
			p := views.Rights.GetRight(views.Db, *txOut.Rights)
			if p == nil {
				views.FetchRightEntry(txOut.Rights)
				//				p = views.Rights.LookupEntry(*txOut.Rights)
				p = views.Rights.GetRight(views.Db, *txOut.Rights)
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

func getBasicRightSet(rset map[chainhash.Hash]struct{}, view *viewpoint.ViewPointSet) map[chainhash.Hash]struct{} {
	ancester := getAncester(&rset, view)

	for _, as := range *ancester {
		for i := len(as) - 1; i > 0; i-- {
			if _, ok := rset[as[i]]; ok {
				p, _ := view.FetchRightEntry(&as[i-1])
				q := p.(*viewpoint.RightEntry).Sibling()
				delete(rset, as[i])
				rset[q] = struct{}{}
				rset[as[i-1]] = struct{}{}
			}
		}
	}

	return rset
}

func getAncester(rset *map[chainhash.Hash]struct{}, view *viewpoint.ViewPointSet) *map[chainhash.Hash][]chainhash.Hash {
	// for every right in rset, if it is decendent of another, find out all the links between them
	// put the relationship in ancester
	//	neg := chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	//		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }
	roots := make(map[chainhash.Hash]int32, 0)

	for r, _ := range *rset {
		p, _ := view.FetchRightEntry(&r)
		if p == nil {
			continue
		}
		rt := p.(*viewpoint.RightEntry).Root
		if _, ok := roots[rt]; !ok {
			roots[rt] = p.(*viewpoint.RightEntry).Depth
		} else if roots[rt] > p.(*viewpoint.RightEntry).Depth {
			roots[rt] = p.(*viewpoint.RightEntry).Depth
		}
	}

	ancester := make(map[chainhash.Hash][]chainhash.Hash)
	for r, _ := range *rset {
		ancester[r] = make([]chainhash.Hash, 1, 5)
		ancester[r][0] = r
		//		if r.IsEqual(&neg) {
		//			continue
		//		}
		//		p := view.Rights.LookupEntry(r)
		p := view.Rights.GetRight(view.Db, r)
		ok := true
		for _, ok = (*rset)[p.(*viewpoint.RightEntry).Father]; !ok && p.(*viewpoint.RightEntry).Depth > roots[p.(*viewpoint.RightEntry).Root]; {
			ancester[r] = append(ancester[r], p.(*viewpoint.RightEntry).Father)
			p, _ = view.FetchRightEntry(&p.(*viewpoint.RightEntry).Father)
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
		for r, s := range ancester {
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
	value   token.TokenValue
}

type tokenrelement struct {
	tokenRElement
	value int64
}

var zerohash chainhash.Hash

func ioTokens(tx *btcutil.Tx, views *viewpoint.ViewPointSet) [][]tokennelement {
	res := [2][]tokennelement{make([]tokennelement, 0, len(tx.MsgTx().TxIn)),
		make([]tokennelement, 0, len(tx.MsgTx().TxOut))}
	for _, y := range tx.MsgTx().TxIn {
		if y.PreviousOutPoint.Hash.IsEqual(&zerohash) {
			continue
		}
		x := views.Utxo.LookupEntry(y.PreviousOutPoint).ToTxOut()
		if x.TokenType&2 == 0 {
			continue
		}
		te := tokennelement{}
		te.tokenType = x.TokenType
		if x.TokenType&1 == 1 {
			te.polygon = x.Value.(*token.HashToken).Hash
		}
		te.right = *x.Rights
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
		if x.IsSeparator() || x.TokenType&2 == 0 {
			continue
		}
		te := tokennelement{}
		te.tokenType = x.TokenType
		if x.TokenType&1 == 1 {
			te.polygon = x.Value.(*token.HashToken).Hash
		}
		te.right = *x.Rights
		te.value = x.Value
		res[1] = append(res[1], te)
	}
	return res[:]
}

func unirightfetch(views *viewpoint.ViewPointSet, right chainhash.Hash, defdrights map[chainhash.Hash]*viewpoint.RightEntry, defdrsets map[chainhash.Hash]*viewpoint.RightSetEntry) interface{} {
	p := views.Rights.GetRight(views.Db, right)

	isnil := false
	switch p.(type) {
	case *viewpoint.RightEntry:
		isnil = p.(*viewpoint.RightEntry) == nil
	case *viewpoint.RightSetEntry:
		isnil = p.(*viewpoint.RightSetEntry) == nil
	}
	if isnil {
		if u, ok := defdrights[right]; ok {
			p = u
		} else {
			p = (*viewpoint.RightEntry)(nil)
			if defdrsets != nil {
				if u, ok := defdrsets[right]; ok {
					p = u
				}
			}
		}
	}
	return p
}

func ioRTokens(tx *btcutil.Tx, views *viewpoint.ViewPointSet) (map[tokenRElement]int64, map[chainhash.Hash]*viewpoint.RightEntry, error) {
	res := make(map[tokenRElement]int64)
	for _, y := range tx.MsgTx().TxIn {
		if y.PreviousOutPoint.Hash.IsEqual(&zerohash) {
			continue
		}

		e := views.Utxo.LookupEntry(y.PreviousOutPoint)
		x := e.ToTxOut()

		if (x.TokenType & 2) == 0 {
			continue
		}

		te := tokenRElement{}
		te.tokenType = x.TokenType
		v := int64(-1)
		if (x.TokenType & 1) == 1 {
			te.polygon = x.Value.(*token.HashToken).Hash
		} else {
			v = -x.Value.(*token.NumToken).Val
		}

		p := views.Rights.GetRight(views.Db, *x.Rights)

		//		p := views.Rights.LookupEntry(*x.Rights)
		switch p.(type) {
		case *viewpoint.RightEntry:
			if p.(*viewpoint.RightEntry) == nil {
				return nil, nil, fmt.Errorf("Right undefined")
			}
			te.right = *x.Rights

			if _, ok := res[te]; !ok {
				res[te] = v
			} else {
				res[te] += v
			}

		case *viewpoint.RightSetEntry:
			if p.(*viewpoint.RightSetEntry) == nil {
				return nil, nil, fmt.Errorf("Right undefined")
			}
			for _, r := range p.(*viewpoint.RightSetEntry).Rights {
				te.right = r

				if _, ok := res[te]; !ok {
					res[te] = v
				} else {
					res[te] += v
				}
			}
		}
	}

	defdrights := map[chainhash.Hash]*viewpoint.RightEntry{}
	defdrsets := map[chainhash.Hash]*viewpoint.RightSetEntry{}
	for _, x := range tx.MsgTx().TxDef {
		if x.IsSeparator() {
			continue
		}
		if x.DefType() == token.DefTypeRight {
			defdrights[x.Hash()] = &viewpoint.RightEntry{
				Father:      x.(*token.RightDef).Father,
				Root:        chainhash.Hash{},
				Depth:       0,
				Desc:        x.(*token.RightDef).Desc,
				Attrib:      x.(*token.RightDef).Attrib,
				PackedFlags: 0,
			}
		} else {
			defdrsets[x.Hash()] = &viewpoint.RightSetEntry{
				Rights:      x.(*token.RightSetDef).Rights,
				PackedFlags: 0,
			}
		}
	}

	for _, x := range tx.MsgTx().TxOut {
		if x.IsSeparator() || (x.TokenType&2) == 0 {
			continue
		}

		te := tokenRElement{}
		te.tokenType = x.TokenType
		v := int64(1)
		if (x.TokenType & 1) == 1 {
			te.polygon = x.Value.(*token.HashToken).Hash
		} else {
			v = x.Value.(*token.NumToken).Val
		}
		te.right = *x.Rights
		//		p := views.Rights.LookupEntry(*x.Rights)
		p := unirightfetch(views, *x.Rights, defdrights, defdrsets)
		/*
			p := views.Rights.GetRight(views.Db, *x.Rights)
			switch p.(type) {
			case *viewpoint.RightEntry:
				if p.(*viewpoint.RightEntry) == nil {
					if u, ok := defdrights[*x.Rights]; ok {
						p = u
					} else if u, ok := defdrsets[*x.Rights]; ok {
						p = u
					}
				}
			case *viewpoint.RightSetEntry:
				if p.(*viewpoint.RightSetEntry) == nil {
					if u, ok := defdrights[*x.Rights]; ok {
						p = u
					} else if u, ok := defdrsets[*x.Rights]; ok {
						p = u
					}
				}
			}
		*/

		switch p.(type) {
		case *viewpoint.RightEntry:
			if p.(*viewpoint.RightEntry) == nil {
				return nil, nil, fmt.Errorf("Right undefined")
			}

			if _, ok := res[te]; !ok {
				res[te] = v
			} else {
				res[te] += v
			}
		case *viewpoint.RightSetEntry:
			if p.(*viewpoint.RightSetEntry) == nil {
				return nil, nil, fmt.Errorf("Right undefined")
			}
			for _, r := range p.(*viewpoint.RightSetEntry).Rights {
				te.right = r

				if _, ok := res[te]; !ok {
					res[te] = v
				} else {
					res[te] += v
				}
			}
		}
	}
	return res, defdrights, nil
}

// handle monitored tokens. In a Tx, if any token has monitored right, then all the input/output must have
// monitored right, monitor, or a father of monitored right
func monitored(r *token.RightSetDef, views *viewpoint.ViewPointSet) bool {
	for _, d := range r.Rights {
		e, _ := views.FetchRightEntry(&d)
		if e.(*viewpoint.RightEntry).Attrib&token.Monitored != 0 {
			return true
		}
	}
	return false
}

func QuickCheckRight(tx *btcutil.Tx, views *viewpoint.ViewPointSet, ver uint32) (bool, error) {
	// we do polygon check here only if the tx involves one polygon
	checkPolygon := true
	zerohash := chainhash.Hash{}
	polyhash := chainhash.Hash{}

	msgtx := tx.MsgTx()

	if ver >= wire.Version4 {
		for _, txOut := range msgtx.TxOut {
			if txOut.IsSeparator() || (txOut.TokenType&3) != 0 {
				continue
			}
			if (txOut.TokenType&1) != 0 && txOut.Token.Value.(*token.HashToken).Hash.IsEqual(&zerohash) {
				return false, fmt.Errorf("Hash token value is zero hash")
			}
			if (txOut.TokenType&2) != 0 && (txOut.Token.Rights == nil || txOut.Token.Rights.IsEqual(&zerohash)) {
				return false, fmt.Errorf("Right is zero hash")
			}
		}
	}

	for _, txDef := range msgtx.TxDef {
		if txDef.IsSeparator() {
			continue
		}
		switch txDef.(type) {
		case *token.PolygonDef:
			checkPolygon = false
		}
	}

	if checkPolygon {
		// is there more than one polygon?
		for _, txOut := range msgtx.TxOut {
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
		for _, txIn := range msgtx.TxIn {
			if txIn.PreviousOutPoint.Hash.IsEqual(&zerohash) {
				continue
			}
			txin := views.Utxo.LookupEntry(txIn.PreviousOutPoint).ToTxOut()
			if txin.TokenType == 3 && checkPolygon {
				if txin.Rights == nil {
					str := fmt.Sprintf("Tx %s input contains zero rights.", tx.Hash().String())
					return false, ruleError(1, str)
				}
				//				rt := views.Rights.LookupEntry(*txin.Rights)
				rt := views.Rights.GetRight(views.Db, *txin.Rights)
				var m bool
				switch rt.(type) {
				case *viewpoint.RightSetEntry:
					rv := rt.(*viewpoint.RightSetEntry).ToToken()
					m = monitored(rv, views)
				case *viewpoint.RightEntry:
					m = monitored(&token.RightSetDef{Rights: []chainhash.Hash{*txin.Rights}}, views)
				}

				if m || polyhash.IsEqual(&zerohash) || !txin.Token.Value.(*token.HashToken).Hash.IsEqual(&polyhash) {
					checkPolygon = false
				}
			}
		}
	}

	// Use superset method for right validation.
	// calculate right sum, a right is expressed as its top ancester minus all the siblings of
	// itself & other non-top ancesters
	sumVals, rts, err := ioRTokens(tx, views)
	if err != nil {
		return false, err
	}

	siblingVals := make(map[tokenRElement]int64)

	checking := true
	for checking && len(sumVals) != 0 {
		checking = false

		for i, tks := range sumVals {
			if tks == 0 {
				checking = true
				delete(sumVals, i)
				continue
			}
			g := unirightfetch(views, i.right, rts, nil)
			/*
			   //			g := views.Rights.LookupEntry(i.right)
			   			g := views.Rights.GetRight(views.Db, i.right)
			   			if g == nil {
			   				if u, ok := rts[i.right]; ok {
			   					g = u
			   				}
			   			}
			*/
			switch g.(type) {
			case *viewpoint.RightEntry:
				if g.(*viewpoint.RightEntry) == nil {
					return false, fmt.Errorf("Right undefined")
				}
			default:
				return false, fmt.Errorf("Right undefined")
			}
			te := i
			if g.(*viewpoint.RightEntry).Attrib&1 != 0 {
				checking = true
				g = g.(*viewpoint.RightEntry).Clone()
				g.(*viewpoint.RightEntry).Attrib &= 0xFE
				te.right = g.(*viewpoint.RightEntry).ToToken().Hash()
				if _, ok := siblingVals[te]; ok {
					siblingVals[te] += tks
				} else {
					siblingVals[te] = tks
				}
				delete(sumVals, i)
			}
			for s, ok := siblingVals[te]; ok && siblingVals[te]*tks > 0; s, ok = siblingVals[te] {
				checking = true
				m := tks
				if abs(tks) > abs(s) {
					m = s
				}

				siblingVals[te] -= m
				sumVals[te] -= m

				if siblingVals[te] == 0 {
					delete(siblingVals, te)
				}
				if sumVals[te] == 0 {
					delete(sumVals, te)
				}

				te.right = g.(*viewpoint.RightEntry).Father
				//				g = views.Rights.LookupEntry(te.right)
				g = unirightfetch(views, te.right, rts, nil)
				/*
					g = views.Rights.GetRight(views.Db, te.right)

					if g == nil {
						if u, ok := rts[te.right]; ok {
							g = u
						}
					}
				*/

				switch g.(type) {
				case *viewpoint.RightEntry:
					if g.(*viewpoint.RightEntry) == nil {
						return false, fmt.Errorf("Right undefined")
					}
				default:
					return false, fmt.Errorf("Right undefined")
				}

				if g.(*viewpoint.RightEntry).Attrib&1 != 0 {
					g = g.(*viewpoint.RightEntry).Clone()
					g.(*viewpoint.RightEntry).Attrib &= 0xFE
					te.right = g.(*viewpoint.RightEntry).ToToken().Hash()
					if _, ok := siblingVals[te]; !ok {
						siblingVals[te] = m
					} else {
						siblingVals[te] += m
					}
				} else {
					if _, ok := sumVals[te]; !ok {
						sumVals[te] = m
					} else {
						sumVals[te] += m
					}
				}
				tks = sumVals[te]
			}
		}
	}

	for i, v := range sumVals {
		if i.tokenType != 3 && v != 0 {
			return false, fmt.Errorf("sumVals: The Tx %s is not integral. Tokentype = %d val %d", tx.Hash().String(), i.tokenType, v)
		}
	}

	for i, v := range siblingVals {
		if i.tokenType != 3 && v != 0 {
			return false, fmt.Errorf("siblingVals: The Tx %s is not integral. Tokentype = %d val %d", tx.Hash().String(), i.tokenType, v)
		}
	}

	if len(sumVals) == 0 && len(siblingVals) == 0 && checkPolygon {
		return true, nil
	}

	return false, nil
}
