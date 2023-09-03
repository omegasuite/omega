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

func CheckDefinitions(msgTx *wire.MsgTx) error {
	e, _, _ := ScanDefinitions(msgTx)
	return e
}

func ScanDefinitions(msgTx *wire.MsgTx) (error, map[chainhash.Hash]*token.RightDef, map[chainhash.Hash]*token.RightSetDef) {
	// for every definition, if it is a new vertex, it must be referenced by a border definition
	// in the same tx. for every top border (father=nil) definition, it must be referenced by a polygon definition
	// in the same tx. for every polygon definition, it must be referenced by a txout in the same tx.
	// for every right definition, it must be referenced by a txout in the same tx.
	var newrights = make(map[chainhash.Hash]*token.RightDef)
	var newrightsets = make(map[chainhash.Hash]*token.RightSetDef)

	for i, def := range msgTx.TxDef {
		if def.IsSeparator() {
			continue
		}

		switch def.(type) {
		case *token.BorderDef:
			v := def.(*token.BorderDef)
			if !v.Father.IsEqual(&chainhash.Hash{}) {
				continue
			}
			h := v.Hash()
			refd := false
			for _, b := range msgTx.TxDef {
				if b.IsSeparator() {
					continue
				}
				switch b.(type) {
				case *token.PolygonDef:
					bd := b.(*token.PolygonDef)
					for _, lp := range bd.Loops {
						for _, l := range lp {
							if l.IsEqual(&h) {
								refd = true
							}
						}
					}
					break
				}
			}
			if !refd {
				str := fmt.Sprintf("Border %s is defined but not referenced.", h.String())
				return ruleError(1, str), nil, nil
			}

		case *token.PolygonDef:
			v := def.(*token.PolygonDef)
			refd := false
			h := v.Hash()
			for _,to := range msgTx.TxOut {
				if to.IsSeparator() || (to.TokenType != 3 && to.TokenType != 1) {
					continue
				}
				n := to.Value.(*token.HashToken).Hash
				if n.IsEqual(&h) {
					refd = true
					break
				}
			}
			if !refd {
			checked:
				for j := i + 1; j < len(msgTx.TxDef); j++ {
					q := msgTx.TxDef[j]
					if q.IsSeparator() {
						continue
					}
					switch q.(type) {
					case *token.PolygonDef:
						v := q.(*token.PolygonDef)
						for _, lp := range v.Loops {
							if len(lp) == 1 && lp[0].IsEqual(&h) {
								refd = true
								break checked
							}
						}
					}
				}
			}
			if !refd {
				str := fmt.Sprintf("Polygon %s is defined but not referenced.", h.String())
				return ruleError(1, str), nil, nil
			}

		case *token.RightDef:
			v := def.(*token.RightDef)
			refd := false
			h := v.Hash()
			if _, ok := newrights[h]; ok {
				str := fmt.Sprintf("Duplicated right definition.", h.String())
				return ruleError(1, str), nil, nil
			}
			newrights[h] = v
			for _, b := range msgTx.TxDef {
				if b.IsSeparator() {
					continue
				}
				switch b.(type) {
				case *token.RightSetDef:
					bd := b.(*token.RightSetDef)
					for _, r := range bd.Rights {
						if h.IsEqual(&r) {
							refd = true
						}
					}

				case *token.RightDef:
					bd := b.(*token.RightDef)
					if h.IsEqual(&bd.Father) {
						refd = true
					}
				}
			}
			for _,to := range msgTx.TxOut {
				if to.IsSeparator() || !to.HasRight() {
					continue
				}
				if to.Rights.IsEqual(&h) {
					refd = true
				}
			}
			if !refd {
				str := fmt.Sprintf("Right %s is defined but not referenced.", h.String())
				return ruleError(1, str), nil, nil
			}
			break
		case *token.RightSetDef:
			v := def.(*token.RightSetDef)
			refd := false
			h := v.Hash()
			if _,ok := newrightsets[h]; ok {
				str := fmt.Sprintf("Duplicated right set definition.", h.String())
				return ruleError(1, str), nil, nil
			}
			newrightsets[h] = v
			for _,to := range msgTx.TxOut {
				if to.IsSeparator() || !to.HasRight() {
					continue
				}
				if to.Rights.IsEqual(&h) {
					refd = true
				}
			}
			if !refd {
				str := fmt.Sprintf("Right %s is defined but not referenced.", h.String())
				return ruleError(1, str), nil, nil
			}
			break
		}
	}

	return nil, newrights, newrightsets
}

// CheckTransactionInputs performs a series of checks on the inputs to a
// transaction to ensure they are valid.  An example of some of the checks
// include verifying all inputs exist, ensuring the coinbase seasoning
// requirements are met, detecting double spends, validating all values and fees
// are in the legal range and the total output amount doesn't exceed the input
// amount, and verifying the signatures to prove the spender was the owner of
// the tokens and therefore allowed to spend them.  As it checks the inputs,
// it also calculates the total fees for the transaction and returns that value.
//
// NOTE: The transaction MUST have already been sanity checked with the
// CheckTransactionSanity function prior to calling this function.
type Cs2Loop map[string]*struct {
	Loops []*token.LoopDef
}

func (s *Cs2Loop) Add(cs string, loop *token.LoopDef) {
	if _, ok := (*s)[cs]; !ok {
		t := struct{ Loops []*token.LoopDef }{
			make([]*token.LoopDef, 0, 1),
		}
		(*s)[cs] = &t
	}
	t := (*s)[cs]
	t.Loops = append(t.Loops, loop)
}

func (s *Cs2Loop) Match(cs string, loop *token.LoopDef) bool {
	if _, ok := (*s)[cs]; !ok {
		return false
	}
	t := (*s)[cs]
	for _,p := range t.Loops {
		if loop.Equal(p) {
			return true
		}
	}
	return false
}

type MatchLoop map[string]*struct {
	Loops []struct{
		checksum string
		loop *token.LoopDef
	}
}

func (s *MatchLoop) Match(cs1, cs2 string, loop1, loop2 *token.LoopDef) bool {
	if _,ok := (*s)[cs1]; !ok {
		return false
	}
	if _,ok := (*s)[cs2]; !ok {
		return false
	}
	t := (*s)[cs1]
	m := false
	for _,p := range t.Loops {
		if p.checksum == cs2 && loop2.Equal(p.loop) {
			m = true
			break
		}
	}
	if !m {
		return false
	}
	t = (*s)[cs2]
	for _,p := range t.Loops {
		if p.checksum == cs1 && loop1.Equal(p.loop) {
			return true
		}
	}
	return false
}

func (s *MatchLoop) Add(cs string, loopcs string, loop *token.LoopDef) {
	if _,ok := (*s)[cs]; !ok {
		t := struct { Loops []struct{
			checksum string
			loop *token.LoopDef
		}} {
			make([]struct{
				checksum string
				loop *token.LoopDef
			}, 0, 1),
		}
		(*s)[cs] = &t
	}
	t := (*s)[cs]
	t.Loops = append(t.Loops, struct{
		checksum string
		loop *token.LoopDef
	}{ loopcs, loop})
}

func CheckTransactionInputs(tx *btcutil.Tx, views * viewpoint.ViewPointSet) error {
	// add definitions
	pendBdr := make(map[chainhash.Hash][]*token.BorderDef)
	redefbl := make(map[chainhash.Hash]struct{})
	redefbl[chainhash.Hash{}] = struct{}{}

	// known facts about loops based on inputs
	ccwloops := make(Cs2Loop, 0)	// ccw loops
	cwloops := make(Cs2Loop, 0)		// cw loops

	inloops := make(MatchLoop, 0)	// loops in a ccw loop
	unxloops := make(MatchLoop, 0)	// loops not intersect each other

	for _,d := range tx.MsgTx().TxIn {
		if d.PreviousOutPoint.Hash.IsEqual(&zerohash) || d.SignatureIndex == 0xFFFFFFFF {
			continue
		}
		utxo := views.Utxo.LookupEntry(d.PreviousOutPoint)
		if utxo == nil {
			return fmt.Errorf("PreviousOutPoint does not exist: %s", d.PreviousOutPoint.String())
		}
		if utxo.TokenType != 3 {
			continue
		}
		plg,err := views.FetchPolygonEntry(&utxo.Amount.(*token.HashToken).Hash)
		if err != nil {
			return err
		}
		ccws := make([]string, 0, 1)
		cs := plg.Loops[0].CheckSum()
		ccws = append(ccws, cs)
		ccwloops.Add(cs, &plg.Loops[0])
		for len(plg.Loops[0]) == 1 {
			plg2,err := views.FetchPolygonEntry(&plg.Loops[0][0])
			if err != nil {
				return err
			}
			cs := plg2.Loops[0].CheckSum()
			ccws = append(ccws, cs)
			ccwloops.Add(cs, &plg2.Loops[0])
		}
		cwws := make([]string, len(plg.Loops) - 1)
		for i := 1; i < len(plg.Loops); i++ {
			is := plg.Loops[i].CheckSum()
			cwws[i-1] = is
			cwloops.Add(is, &plg.Loops[i])
			for _,m := range ccws {
				inloops.Add(m, is, &plg.Loops[i])
			}
			for j := 1; j < i; j++ {
				unxloops.Add(is, cwws[j-1], &plg.Loops[j])
				unxloops.Add(cwws[j-1], is, &plg.Loops[i])
			}
		}
	}

	defdef := map[chainhash.Hash]struct{}{}

	for _, d := range tx.MsgTx().TxDef {
		if d.IsSeparator() {
			continue
		}
		h := d.Hash()
		switch d.(type) {
		case *token.PolygonDef:
			ft, _ := views.FetchPolygonEntry(&h)
			if ft != nil { // polygon already exists
				return ruleError(1, "Illegal Polygon definition.")
			}

			p := d.(*token.PolygonDef)
			if err := sanePolygon(p, views, ccwloops, cwloops, inloops, unxloops); err != nil {
				return err
			}

			// a newly defined polygon must be used in this Tx. it is either a polygon in txout,
			// or be used by other polygon. if it is used in a txout, the first loop must be ccw,
			// otherwise cw.
			ccw := false
			th := p.Hash()
			for _, out := range tx.MsgTx().TxOut {
				if out.IsSeparator() {
					continue
				}
				if out.TokenType == 3 && out.Value.(*token.HashToken).Hash.IsEqual(&th) {
					ccw = true
					break
				}
			}
			var rcw bool
			var bx viewpoint.BoundingBox
			if rcw, bx = views.PolygonInfo(p); rcw != ccw {
				return ruleError(1, "Illegal Polygon definition.")
			}
			views.AddOnePolygon(p, ccw, bx)

		case *token.BorderDef:
			ft, _ := views.FetchBorderEntry(&h)
			if ft != nil { // no repeat definition
				return ruleError(1, "Illegal Border definition.")
			}

			b := d.(*token.BorderDef)
			f := &b.Father

			if _, ok := redefbl[*f]; ok {
				redefbl[h] = struct{}{}
			}

			if !f.IsEqual(&chainhash.Hash{}) {
				ft, _ = views.FetchBorderEntry(f)
				if ft == nil { // father does not exist
					return ruleError(1, "Illegal Border definition.")
				}

				if _, ok := pendBdr[b.Father]; !ok {
					pendBdr[b.Father] = make([]*token.BorderDef, 0, 4)
				}
				pendBdr[b.Father] = append(pendBdr[b.Father], b)

				depth := 0
				for !f.IsEqual(&chainhash.Hash{}) {
					depth++
					if depth > 100 {
						return ruleError(1, "Border definition is too deep.")
					}
					ft, _ = views.FetchBorderEntry(f)
					f = &ft.Father
				}
			}

			if !views.AddOneBorder(b) {
				return ruleError(1, "Illegal Border definition.")
			}

		case *token.RightDef, *token.RightSetDef:
			ft, _ := views.FetchRightEntry(&h)
			if ft != nil { // father does not exist
				return ruleError(1, "Illegal Rights definition.")
			}

			switch d.(type) {
			case *token.RightDef:
				f := &d.(*token.RightDef).Father
				if !f.IsEqual(&chainhash.Hash{}) {
					if _, ok := defdef[*f]; ok {
						defdef[d.(*token.RightDef).Hash()] = struct{}{}
						continue
					}
					ft, _ := views.FetchRightEntry(f)
					if ft == nil || ft.(*viewpoint.RightEntry).Attrib&token.Unsplittable != 0 { // father is indivisible
						return ruleError(1, "Illegal Right definition.")
					}
				}
				defdef[d.(*token.RightDef).Hash()] = struct{}{}

			case *token.RightSetDef:
				for _, r := range d.(*token.RightSetDef).Rights {
					if _, ok := defdef[r]; !ok {
						ft, _ := views.FetchRightEntry(&r)
						if ft == nil {
							return ruleError(1, "Illegal Right definition.")
						}
					}
				}
				defdef[d.(*token.RightSetDef).Hash()] = struct{}{}
			}
		}
	}

	for f, pend := range pendBdr {
		// check whether these borders are allowed
		fb, _ := views.FetchBorderEntry(&f)

		// check for proper connection, build children record
		v := fb.Begin
		fb.Children = make([]chainhash.Hash, 0, len(pend))
		for _,r := range pend {
			if !v.IsEqual(&r.Begin) {
				return ruleError(1, "Illegal border definition.")
			}
			fb.Children = append(fb.Children, r.Hash())
			v = r.End
		}

		if !v.IsEqual(&fb.End) {
			fb.Children = nil
			return ruleError(1, "Illegal border definition.")
		}
		fb.PackedFlags |= viewpoint.TfModified

		if _,ok := redefbl[f]; ok {
			// completely new border, not children of existing border, no need to check whether it is on existing border line
			continue
		}

		// border is allowed if the new vertex is exactly on the border line
		// or total reference count of this border and its anciesters in the inputs is the same as in all the UTXOs

		isonline := true
		delim := (*token.VertexDef)(nil)
		fbv := &fb.Begin
		fev := &fb.End
		for i := 1; i < len(pend); i ++ {
			r := &pend[i].Begin
			if isonline && (r == nil || !online(r, fbv, fev, delim)) {
				isonline = false
			}
			delim = r
		}
		if !isonline && fb.RefCnt != 0 {
			// if RefCnt == 0, it means this parent border itself is a new border. no need to verify it since
			// it is impossible for it to appear in any utxo (what if it is a border defined in a previous Tx
			// in this block? That'ok since a utxo is added at the time of connecting block. That mean any polygon
			// hence border defined in this block can not be used as input in this block, only as output.)
			as := fb.Anciesters(views)
			as[f] = struct{}{}
			sum := int32(0)
			for af, _ := range as {
				sum += views.Border.LookupEntry(af).RefCnt
			}

			for _, txIn := range tx.MsgTx().TxIn {
				if txIn.PreviousOutPoint.Hash.IsEqual(&zerohash) {
					continue
				}
				utxo := views.Utxo.LookupEntry(txIn.PreviousOutPoint)
				if utxo.TokenType != 3 {
					continue
				}
				h := &utxo.Amount.(*token.HashToken).Hash
				sum -= appeared(h, as, views)

				if sum != 0 {
					return ruleError(1, "Illegal border definition.")
				}
				// everyone affected by modification of this border has approved by appearing in input
			}
		}
	}

	return nil
}

func CheckTransactionAdditionalInputs(tx *btcutil.Tx, views * viewpoint.ViewPointSet) error {
	additional := false
	for _,d := range tx.MsgTx().TxDef {
		if d.IsSeparator() {
			additional = true
			continue
		}
		if !additional {
			continue
		}
		h := d.Hash()
		switch d.(type) {
		case *token.RightDef, *token.RightSetDef:
			ft,_ := views.FetchRightEntry(&h)
			if ft != nil {		// father does not exist
				return ruleError(1, "Illegal Rights definition.")
			}

			switch d.(type) {
			case *token.RightDef:
				f := &d.(*token.RightDef).Father
				if !f.IsEqual(&chainhash.Hash{}) {
					ft,_ := views.FetchRightEntry(f)
					if ft == nil || ft.(*viewpoint.RightEntry).Attrib & token.Unsplittable != 0 {		// father is indivisible
						return ruleError(1, "Illegal Right definition.")
					}
				}

			case *token.RightSetDef:
				for _, r := range d.(*token.RightSetDef).Rights {
					ft,_ := views.FetchRightEntry(&r)
					if ft == nil {
						return ruleError(1, "Illegal Right definition.")
					}
				}
			}
		}
	}

	return nil
}

func appeared(p * chainhash.Hash, as map[chainhash.Hash]struct{}, views * viewpoint.ViewPointSet) int32 {
	sum := int32(0)
	plg,_ := views.FetchPolygonEntry(p)
	for _, loop := range plg.Loops {
		if len(loop) == 1 {
			// it is a polygon
			sum += appeared(&loop[0], as, views)
			continue
		}
		for _, bd := range loop {
			nbd := chainhash.Hash{}
			copy(nbd[:], bd[:])
			nbd[0] &= 0xFE
			if _, ok := as[nbd]; ok {
				sum++
			}
		}
	}
	return sum
}

func iabs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// RuleError identifies a rule violation.  It is used to indicate that
// processing of a block or transaction failed due to one of the many validation
// rules.  The caller can use type assertions to determine if a failure was
// specifically due to a rule violation and access the ErrorCode field to
// ascertain the specific reason for the rule violation.
type RuleError struct {
	ErrorCode   int // Describes the kind of error
	Description string    // Human readable description of the issue
}

// Error satisfies the error interface and prints human-readable errors.
func (e RuleError) Error() string {
	return e.Description
}

// ruleError creates an RuleError given a set of arguments.
func ruleError(c int, desc string) RuleError {
	return RuleError{ErrorCode: c, Description: desc}
}
