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
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/omega/viewpoint"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
)

func CheckDefinitions(msgTx *wire.MsgTx) error {
	// for every definition, if it is a new vertex, it must be referenced by a border definition
	// in the same tx. for every top border (father=nil) definition, it must be referenced by a polygon definition
	// in the same tx. for every polygon definition, it must be referenced by a txout in the same tx.
	// for every right definition, it must be referenced by a txout in the same tx.
	for _, def := range msgTx.TxDef {
		switch def.(type) {
		case *token.VertexDef:
			v := def.(*token.VertexDef)
			refd := false
			for _, b := range msgTx.TxDef {
				switch b.(type) {
				case *token.BorderDef:
					bd := b.(*token.BorderDef)
					if bd.Begin.IsEqual(v) || bd.End.IsEqual(v) {
						refd = true
					}
					break
				}
			}
			if !refd {
				str := fmt.Sprintf("Vertex %s is defined but not referenced.", v.Hash().String())
				return ruleError(1, str)
			}
			if !saneVertex(v) {	// check coords is in valid range
				str := fmt.Sprintf("Insane vertex %v (%f， %f, %f) => (%d， %d, %d)", v.Hash(),
					float64(int32(v.Lat())) / token.CoordPrecision, float64(int32(v.Lng())) / token.CoordPrecision,
					float64(int32(v.Alt())) / token.CoordPrecision, v.Lat(), v.Lng(), v.Alt())
				return ruleError(1, str)
			}
			break
		case *token.BorderDef:
			v := def.(*token.BorderDef)
			if !v.Father.IsEqual(&chainhash.Hash{}) {
				continue
			}
			h := v.Hash()
			refd := false
			for _, b := range msgTx.TxDef {
				switch b.(type) {
				case *token.PolygonDef:
					bd := b.(*token.PolygonDef)
					for _,lp := range bd.Loops {
						for _,l := range lp {
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
				return ruleError(1, str)
			}
			break
		case *token.PolygonDef:
			v := def.(*token.PolygonDef)
			refd := false
			h := v.Hash()
			for _,to := range msgTx.TxOut {
				if to.TokenType != 3 && to.TokenType != 1 {
					continue
				}
				n := to.Value.(*token.HashToken).Hash
				if n.IsEqual(&h) {
					refd = true
				}
			}
			if !refd {
				str := fmt.Sprintf("Polygon %s is defined but not referenced.", h.String())
				return ruleError(1, str)
			}
			break
		case *token.RightDef:
			v := def.(*token.RightDef)
			refd := false
			h := v.Hash()
			for _, b := range msgTx.TxDef {
				switch b.(type) {
				case *token.RightSetDef:
					bd := b.(*token.RightSetDef)
					for _,r := range bd.Rights {
						if h.IsEqual(&r) {
							refd = true
						}
					}
					break
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
				return ruleError(1, str)
			}
			break
		case *token.RightSetDef:
			v := def.(*token.RightSetDef)
			refd := false
			h := v.Hash()
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
				return ruleError(1, str)
			}
			break
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
// the tokens and therefore allowed to spend them.  As it checks the inputs,
// it also calculates the total fees for the transaction and returns that value.
//
// NOTE: The transaction MUST have already been sanity checked with the
// CheckTransactionSanity function prior to calling this function.
func CheckTransactionInputs(tx *btcutil.Tx, views * viewpoint.ViewPointSet, chainParams *chaincfg.Params) error {
	// add definitions
	pendBdr := make(map[chainhash.Hash][]*token.BorderDef)
	redefbl := make(map[chainhash.Hash]struct{})
	redefbl[chainhash.Hash{}] = struct{}{}

	for _,d := range tx.MsgTx().TxDef {
		h := d.Hash()
		switch d.(type) {
		case *token.PolygonDef:
			ft,_ := views.Polygon.FetchEntry(views.Db, &h)
			if ft != nil {		// polygon already exists
				return ruleError(1, "Illegal Polygon definition.")
			}

			p := d.(*token.PolygonDef)
			if err := sanePolygon(p, views); err != nil {
				return err
			}
			views.AddOnePolygon(p)

		case *token.BorderDef:
			ft,_ := views.Border.FetchEntry(views.Db, &h)
			if ft != nil {		// no repeat definition
				return ruleError(1, "Illegal Border definition.")
			}

			b := d.(*token.BorderDef)
			f := &b.Father

			if _,ok := redefbl[*f]; ok {
				redefbl[h] = struct{}{}
			}

			if !f.IsEqual(&chainhash.Hash{}) {
				ft,_ = views.Border.FetchEntry(views.Db, f)
				if ft == nil || len(ft.Children) > 0 {		// father does not exist or already has children
					return ruleError(1, "Illegal Border definition.")
				}

				if _, ok := pendBdr[b.Father]; !ok {
					pendBdr[b.Father] = make([]*token.BorderDef, 0, 4)
				}
				pendBdr[b.Father] = append(pendBdr[b.Father], b)
			}

			if !views.AddOneBorder(b) {
				return ruleError(1, "Illegal Border definition.")
			}

		case *token.RightDef, *token.RightSetDef:
			ft,_ := views.Rights.FetchEntry(views.Db, &h)
			if ft != nil {		// father does not exist
				return ruleError(1, "Illegal Rights definition.")
			}

			switch d.(type) {
			case *token.RightDef:
				f := &d.(*token.RightDef).Father
				if !f.IsEqual(&chainhash.Hash{}) {
					ft,_ := views.Rights.FetchEntry(views.Db, f)
					if ft == nil || ft.(*viewpoint.RightEntry).Attrib & token.Unsplittable != 0 {		// father is indivisible
						return ruleError(1, "Illegal Right definition.")
					}
				}

			case *token.RightSetDef:
				for _, r := range d.(*token.RightSetDef).Rights {
					ft,_ := views.Rights.FetchEntry(views.Db, &r)
					if ft == nil {
						return ruleError(1, "Illegal Right definition.")
					}
				}
			}
		}
	}

	for f, pend := range pendBdr {
		// check whether these borders are allowed
		fb, _ := views.Border.FetchEntry(views.Db, &f)

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

		// border is allowed if the new vertex is exactly on the border line (w/i error range)
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
				if txIn.IsSeparator() {
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

func appeared(p * chainhash.Hash, as map[chainhash.Hash]struct{}, views * viewpoint.ViewPointSet) int32 {
	sum := int32(0)
	plg,_ := views.Polygon.FetchEntry(views.Db, p)
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
