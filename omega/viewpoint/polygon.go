/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package viewpoint

import (
	//	"fmt"

	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"fmt"
	"github.com/omegasuite/btcd/blockchain/bccompress"
	//	"github.com/btcsuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/token"
	"math/big"
)

// VtxEntry houses details about an individual vertex definition in a definition
// view.
type PolygonEntry struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.

	Loops []token.LoopDef
	Bound BoundingBox
	FirstCW	bool
	Depth uint8

	// packedFlags contains additional info about vertex. Currently unused.
	PackedFlags txoFlags
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry * PolygonEntry) isModified() bool {
	return entry.PackedFlags & TfModified == TfModified
}

func (entry * PolygonEntry) toDelete() bool {
	return entry.PackedFlags & TfSpent == TfSpent
}

// Clone returns a shallow copy of the vertex entry.
func (entry * PolygonEntry) Clone() *PolygonEntry {
	if entry == nil {
		return nil
	}

	return &PolygonEntry{
		Loops:   entry.Loops,
		Bound:   entry.Bound,
		FirstCW: entry.FirstCW,
		Depth: entry.Depth,
		PackedFlags: entry.PackedFlags,
	}
}

func (entry * PolygonEntry) deReference(view * ViewPointSet) {
	loops :=  view.Flattern(entry.Loops)
	for _, loop := range loops {
		for _, b := range loop {
			b[0] &= 0xFE
			fb, _ := view.FetchBorderEntry(&b)
			fb.deReference()
		}
	}
}

func (entry * PolygonEntry) reference(view * ViewPointSet) {
	loops :=  view.Flattern(entry.Loops)
	for _, loop := range loops {
		for _, b := range loop {
			b[0] &= 0xFE
			fb, _ := view.FetchBorderEntry(&b)
			fb.reference()
		}
	}
}

func (entry * PolygonEntry) ToToken() *token.PolygonDef {
	return &token.PolygonDef{
		Loops: entry.Loops,
	}
}
// VtxViewpoint represents a view into the set of vertex definition
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.

type PolygonViewpoint struct {
	entries  map[chainhash.Hash]*PolygonEntry
	bestHash chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view * PolygonViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view * PolygonViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// LookupEntry returns information about a given vertex according to
// the current state of the view.  It will return nil if the passed vertex does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
func (view * PolygonViewpoint) LookupEntry(p chainhash.Hash) * PolygonEntry {
	return view.entries[p]
}

func (s * ViewPointSet) IsLoop(lp * token.LoopDef) bool {
	if len(*lp) == 1 {
		return false
	}
	var be, be0 *token.VertexDef
	var pe, pb *token.VertexDef

	exists := make(map[token.VertexDef]struct{}, 0)

	for _, b := range *lp {
		d, _ := s.FetchBorderEntry(&b)
		if d == nil {
			return false
		}
		if b[0] & 1 == 0 {
			pe, pb = &d.End, &d.Begin
		} else {
			pb, pe = &d.End, &d.Begin
		}
		if be0 == nil {
			be0 = pb
		} else if !be.IsEqual(pb) {
			return false
		}
		if _,ok := exists[*pb]; ok {
			return false
		}
		exists[*pb] = struct{}{}
		be = pe
	}

	return be0.IsEqual(be)
}

// addVertex adds the specified vertex to the view.
func (view * ViewPointSet) addPolygon(b *token.PolygonDef, ccw bool, bx BoundingBox) bool {
	// polygon must have already passed sanity check
	h := b.Hash()
	entry := view.Polygon.LookupEntry(h)
	if entry == nil {
		entry = new(PolygonEntry)
		entry.Loops = b.Loops
		entry.FirstCW = !ccw
		entry.PackedFlags = TfModified
		entry.Bound = bx
		mx := uint8(0)
		for _,q := range b.Loops {
			if len(q) == 1 {
				r,_ := view.FetchPolygonEntry(&q[0])
				if r.Depth > mx {
					mx = r.Depth
				}
			}
		}
		if mx >= 100 {
			return false
		}
		entry.Depth = mx + 1
		view.Polygon.entries[h] = entry
		return true
	}
	return false
}

func (view * ViewPointSet) PolygonInfo(b *token.PolygonDef) (bool, BoundingBox) {
	bx := (*BoundingBox)(nil)
	first := true
	getfirst := true
	for _, loop := range b.Loops {
		if len(loop) == 1 {
			d,_ := view.FetchPolygonEntry(&loop[0])
			if bx == nil {
				bx = &BoundingBox{}
				*bx = d.Bound
			} else {
				bx.Merge(&d.Bound)
			}
			if getfirst {
				first = !d.FirstCW
				getfirst = false
			}
		} else {
			for _, b := range loop {
				d,_ := view.FetchBorderEntry(&b)
				if bx == nil {
					bx = &BoundingBox{}
					*bx = d.GetBound()
				} else if d.Bound != nil {
					bx.Merge(d.Bound)
				} else {
					bx.Merge(NewBound(d.Begin.Lng(), d.End.Lng(), d.Begin.Lat(), d.End.Lat()))
				}
			}
			if getfirst {
				first,_ = view.LoopCCW(&loop)
				getfirst = false
			}
		}
	}
	return first, *bx
}

type DirectedBorder struct {
	border *BorderEntry
	rev byte
}

func (view * ViewPointSet) ExpandLoop(cl *token.LoopDef) ([]DirectedBorder, BoundingBox) {
	borders := make([]DirectedBorder, 0, len(*cl))
	var box BoundingBox
	box.Reset()

	for _, l := range *cl {
		b0,err := view.FetchBorderEntry(&l)
		if err != nil {
			return nil, box
		}
		if len(b0.Children) == 0 {
			borders = append(borders, DirectedBorder{b0, l[0] & 1})
			gb := b0.GetBound()
			box.Merge(&gb)
		} else {
			t, bx := view.ExpandLoop((*token.LoopDef)(&b0.Children))
			if t == nil {
				return nil, box
			}
			if l[0] & 1 == 1 {
				for i := len(t) - 1; i >= 0; i-- {
					borders = append(borders, t[i])
				}
			} else {
				borders = append(borders, t...)
			}
			box.Merge(&bx)
		}
	}
	return borders, box
}

func (view * ViewPointSet) Intersects(c1, c2 * token.LoopDef, pb1, pb2 * BoundingBox,
	cw1 bool) bool {
	// if c1 == c2, check self intersection, else check intersection
	if pb1 == nil {
		b1 := view.LoopBound(c1)
		pb1 = &b1
	}
	if pb2 == nil {
		b2 := view.LoopBound(c2)
		pb2 = &b2
	}
	if c1 != c2 && !pb1.Intersects(pb2, false) {
		return false
	}

	var loops1, loops2 []token.LoopDef

	if len(*c1) == 1 {
		if c1 == c2 {
			return false
		}
		plg, _ := view.FetchPolygonEntry(&(*c1)[0])
		loops1 = plg.Loops
	} else {
		loops1 = []token.LoopDef{*c1}
	}

	if c1 == c2 {
		loops2 = loops1
	} else {
		if len(*c2) == 1 {
			plg, _ := view.FetchPolygonEntry(&(*c2)[0])
			loops2 = plg.Loops
		} else {
			loops2 = []token.LoopDef{*c2}
		}
	}

	if len(loops1) > 1 || len(loops2) > 1 {
		for _, l1 := range loops1 {
			for _, l2 := range loops2 {
				if t := view.Intersects(&l1, &l2, nil, nil, cw1); t {
					return true
				}
			}
			cw1 = true
		}
		return false
	}

	t,_ := view.BorderIntersects(&loops1[0], &loops2[0], pb1, pb2, nil, nil, cw1)
	return t
}

func ReorderChildren(c []chainhash.Hash, rev bool) []chainhash.Hash {
	if !rev {
		return c
	}
	n := len(c)
	d := make([]chainhash.Hash, n)
	for i,h := range c {
		d[n - 1 - i] = h
		d[n - 1 - i][0] |= 1
	}
	return d
}

func (view * ViewPointSet) BorderIntersects(c1, c2 * token.LoopDef, pb1, pb2 * BoundingBox,
	pb0 * chainhash.Hash, pfe0 * BorderEntry, cw1 bool) (bool, * BorderEntry) {
	var fe1, pfe * BorderEntry
	var tb bool

	// now c1 & c2 are both simple loops, check edges
	for i, lp := range *c2 {
		n := i
		if c1 != c2 {
			n = len(*c1)
		}
		fe2,_ := view.FetchBorderEntry(&lp)
		box1 := fe2.GetBound()

		if !box1.Intersects(pb1, true) {
			continue
		}

		if pb0 == nil {
			pb0 = &(*c1)[len(*c1)-1]
		}

		pb, pfe := pb0, pfe0
		rev2 := lp[0] & 1 == 1

		for j := 0; j < n; j++ {
			lq := (*c1)[j]
			fe1,_ = view.FetchBorderEntry(&lq)
			box2 := fe1.GetBound()
			if !box1.Intersects(&box2, true) {
				pb, pfe = &(*c1)[j], fe1
				continue
			}
			rev1 := lq[0] & 1 == 1
			if len(fe1.Children) > 0 && len(fe2.Children) > 0 {
				nc := ReorderChildren(fe1.Children, rev1)
				nd := ReorderChildren(fe2.Children, rev2)
				if tb, pfe = view.BorderIntersects((*token.LoopDef)(&nc), (*token.LoopDef)(&nd), &box1, &box2, pb, pfe, cw1); tb {
					return true, nil
				}
			} else if len(fe1.Children) > 0 {
				t := token.LoopDef{lp}
				nc := ReorderChildren(fe1.Children, rev1)
				if tb, pfe = view.BorderIntersects((*token.LoopDef)(&nc), &t, &box1, &box2, pb, pfe, cw1); tb {
					return true, nil
				}
			} else if len(fe2.Children) > 0 {
				t := token.LoopDef{lq}
				nd := ReorderChildren(fe2.Children, rev2)
				if tb, pfe = view.BorderIntersects(&t, (*token.LoopDef)(&nd), &box1, &box2, pb, pfe, cw1); tb {
					return true, nil
				}
			} else {
				sh00 := fe1.Begin.IsEqual(&fe2.Begin)
				sh01 := fe1.Begin.IsEqual(&fe2.End)
				sh10 := fe1.End.IsEqual(&fe2.Begin)
				sh11 := fe1.End.IsEqual(&fe2.End)
				if (sh00 || sh01) && (sh10 || sh11) {
					pb, pfe = &(*c1)[j], fe1
					continue	// same edge. should have been excluded already in SameEdge check
				}
				check := sh00 || sh01 || sh10 || sh11	// check both ends of fe2

				if int64(fe1.End.Lat() - fe1.Begin.Lat()) * int64(fe2.End.Lng() - fe2.Begin.Lng()) ==
					int64(fe1.End.Lng() - fe1.Begin.Lng()) * int64(fe2.End.Lat() - fe2.Begin.Lat()) {
					pb, pfe = &(*c1)[j], fe1
					continue
				}
				if c1 != c2 && check {
					switch {
					case (sh00 && !rev1) || (sh10 && rev1):
						if view.Between(pb, pfe, fe1, fe2.End, rev1, cw1) {
							return true, nil
						}
					case (sh01 && !rev1) || (sh11 && rev1):
						if view.Between(pb, pfe, fe1, fe2.Begin, rev1, cw1) {
							return true, nil
						}
					}
				} else if !check {
					ep := fe1.Begin
					if rev1 {
						ep = fe1.End
					}
					if fe2.OnEdge(ep) {
						// touch
						// make temp edges
						ne1 := token.BorderDef{}
						ne1.Father, ne1.Begin, ne1.End = lp, fe2.Begin, ep
						view.AddOneBorder(&ne1)
						ne2 := token.BorderDef{}
						ne2.Father, ne2.Begin, ne2.End = lp, ep, fe2.End
						view.AddOneBorder(&ne2)

						res1, res3 := view.BorderIntersects(c1, c2, pb1, pb2, pb0, pfe0, cw1)		// redo it
						
						// remove temp edges
						fe2.Children = []chainhash.Hash{}
						view.Border.RemoveEntry(ne1.Hash())
						view.Border.RemoveEntry(ne2.Hash())
						return res1, res3
					} else if fe1.Intersects(fe2, rev1, rev2) {
						// real intersection. not touch
						return true, nil
					}
				}
				pfe = fe1
			}
			pb = &(*c1)[j]
		}
	}
	return false, pfe
}

func (view * ViewPointSet) Between(pb * chainhash.Hash, e1, e2 * BorderEntry, p token.VertexDef, rev1, cw bool) bool {
	if e1 == nil {
		e1,_ = view.FetchBorderEntry(pb)
	}

	for len(e1.Children) > 0 {
		var lq chainhash.Hash
		if rev1 {
			lq = e1.Children[len(e1.Children) - 1]
		} else {
			lq = e1.Children[0]
		}
		e1,_ = view.FetchBorderEntry(&lq)
	}

	a, b, c := e1.Begin, e1.End, e2.End
	if rev1 {
		b, a = a, b
	}
	if c.IsEqual(&b) {
		c = e2.Begin
	}
	if cw {
		a, c = c, a
	}
	d1 := int64(b.Lat() - a.Lat()) * int64(c.Lng() - b.Lng()) -
		int64(b.Lng() - a.Lng()) * int64(c.Lat() - b.Lat())
	d2 := int64(b.Lat() - a.Lat()) * int64(p.Lng() - b.Lng()) -
		int64(b.Lng() - a.Lng()) * int64(p.Lat() - b.Lat())
	d3 := int64(b.Lat() - p.Lat()) * int64(c.Lng() - b.Lng()) -
		int64(b.Lng() - p.Lng()) * int64(c.Lat() - b.Lat())
	if d2 == 0 || d3 == 0 {
		return false
	}
	if d1 >= 0 {
		return d2 > 0 && d3 > 0
	}
	return !(d2 < 0 && d3 < 0)
}

func (view * ViewPointSet) CommonEdge(p, q * token.LoopDef) bool {
	if len(*p) == 1 {
		fe, _ := view.FetchPolygonEntry(&(*p)[0])
		for _, t := range fe.Loops {
			if view.CommonEdge(&t, q) {
				return true
			}
		}
		return false
	}
	if len(*q) == 1 {
		return view.CommonEdge(q, p)
	}
	for _, l := range *p {
		fe, _ := view.FetchBorderEntry(&l)
		box := fe.GetBound()
		for _, l2 := range *q {
			ll, ll2 := l, l2
			ll[0] &= 0xFE
			ll2[0] &= 0xFE
			if ll.IsEqual(&ll2) {
				return true
			}
			fe2, _ := view.FetchBorderEntry(&l2)
			box2 := fe2.GetBound()
			if !box.Intersects(&box2, false) {
				continue
			}
			switch {
			case len(fe.Children) == 0 && len(fe2.Children) == 0:
				if fe.SameEdge(fe2) {
					return true
				}

			case len(fe.Children) > len(fe2.Children):
				if view.CommonEdge((* token.LoopDef)(&fe.Children), q) {
					return true
				}

			default:
				if view.CommonEdge(p, (* token.LoopDef)(&fe2.Children)) {
					return true
				}
			}
		}
	}
	return false
}

func (view * ViewPointSet) InOutCheck(p, w * token.LoopDef, wd * BoundingBox) bool {
	// return true if any loop of w is inside any loop of p
	for len(*p) == 1 {
		plg,_ := view.FetchPolygonEntry(&(*p)[0])
		for _,lp := range plg.Loops {
			bd := view.LoopBound(&lp)
			if !bd.Contain(wd) {
				continue
			}
			if view.InOutCheck(&lp, w, wd) {
				return true
			}
		}
		return false
	}

	for len(*w) == 1 {
		plg,_ := view.FetchPolygonEntry(&(*w)[0])
		for _,lp := range plg.Loops {
			bd := view.LoopBound(&lp)
			if view.InOutCheck(p, &lp, &bd) {
				return true
			}
		}
		return false
	}

	// p & w are known not to intersect, but may touch. w's bouding box is inside p's
	// pick any vertex of w, if it does not touch w and is inside, then w is inside
	// if it does not touch w and is outside, then w is outside
	for _, q := range *w {
		b, _ := view.FetchBorderEntry(&q)
		if len(b.Children) > 0 {
			c := ReorderChildren(b.Children, q[0] & 1 == 1)
			if view.InOutCheck(p, (*token.LoopDef)(&c), nil) {
				return true
			}
		}
		v := b.End
		if q[0] & 1 != 0 { // reversed
			v = b.Begin
		}
		r := view.InsidePoint(p, v)
		// if r > 0, v is inside p, if r < 0, v is outside p, otherwise v touches p
		if r > 0 {
			return true
		}
		if r < 0 {
			return false
		}
	}

	if wd == nil {
		return false
	}

	// all of w's vertices are on p!!!
	// w must be a cw loops. examine every point on contral horizontal line until
	// we can decide
	var v token.VertexDef
	v.SetLat((wd.north + wd.south) / 2)
	d := (wd.east - wd.west) / 2
	n := 0
	for d > 0 {
		n, d = n + 1, d >> 1
	}
	d = 1 << n
	for d > 1 {
		d >>= 1
		v.SetLng(wd.east + d)
		for v.Lng() < wd.east {
			if view.InsidePoint(w, v) == 1 {
				r := view.InsidePoint(p, v)
				if r == 1 {
					return true
				}
				if r == -1 {
					return false
				}
			}
			v.SetLng(v.Lng() + 2 * d)
		}
	}
	return true		// impossible
}

func (view * ViewPointSet) SelectBorders(lp * token.LoopDef, p token.VertexDef) []chainhash.Hash {
	loop := make([]chainhash.Hash, 0, len(*lp))
	for _, l := range *lp {
		fe, _ := view.FetchBorderEntry(&l)
		box := fe.GetBound()
		if box.north <= p.Lat() || box.east < p.Lng() || box.west > p.Lng() {
			loop = append(loop, l)
			continue
		}
		if len(fe.Children) > 0 {
			c := ReorderChildren(fe.Children, l[0] & 1 == 1)
			loop = append(loop, view.SelectBorders((*token.LoopDef)(&c), p)...)
		} else {
			loop = append(loop, l)
		}
	}
	return loop
}

func quadrant(v, p token.VertexDef) int8 {
	if v.Lng() < p.Lng() {
		return -1
	}
	if v.Lng() > p.Lng() {
		return 1
	}
	return 0
}

func (view * ViewPointSet) InsidePoint(lp * token.LoopDef, p token.VertexDef) int {
	// we need to find out how many intersections there are for a ray from p.
	// For a ccw loop, If the number is odd, it is inside. otherwise it is outseide.
	// For a cw loop, If the number is odd, it is outseide. otherwise it is inside.
	// we know p is not on border. check # of intersections of a ray from p and vertically up
	intersects := 0
	var begin, end token.VertexDef
	var side int8

	loop := view.SelectBorders(lp, p)

	for _, l := range loop {
		fe,_ := view.FetchBorderEntry(&l)
		if l[0] & 1 == 1 {
			begin, end = fe.End, fe.Begin
		} else {
			end, begin = fe.End, fe.Begin
		}
		if p.IsEqual(&begin) { // touch
			return 0
		}

		box := fe.GetBound()
		if box.north < p.Lat() {
			side = 0
			continue
		} else if box.north == p.Lat() {
			if begin.Lat() == box.north && end.Lat() == box.north { // touch
				return 0
			}
			side = 0
			continue
		}

		if box.east < p.Lng() {
			side = -1
			continue
		} else if box.west > p.Lng() {
			side = 1
			continue
		}

		q1 := quadrant(begin, p)
		q2 := quadrant(end, p)
		switch {
		case q1 == 0 && q2 == 0:
			if (begin.Lat() <= p.Lat() || end.Lat() <= p.Lat()) &&
				(begin.Lat() >= p.Lat() || end.Lat() >= p.Lat()) {
				return 0
			}
			if end.Lat() < p.Lat() {
				side = 0
			}

		case q1 == q2:
			side = q1

		case q2 == 0:

		case q1 == 0 && (side == q2 || side == 0):
			side = q2

		case q1 == 0:
			if begin.Lat() == p.Lat() {
				return 0
			} else if begin.Lat() > p.Lat() {
				intersects++
			}
			side = q2

		default:
			d := int64(end.Lng() - begin.Lng()) * int64(p.Lat() - end.Lat()) -
				int64(end.Lat() - begin.Lat()) * int64(p.Lng() - end.Lng())
			if d == 0 {
				return 0
			}
			if (d < 0 && q2 > q1) || (d > 0 && q2 < q1) {
				intersects++
			}
			side = q2
		}
	}

	if intersects & 1 == 1 {
		return 1
	}

	return -1
}

func abs(in int32) int32 {
	if in < 0 {
		return -in
	}
	return in
}

func (view *ViewPointSet) LoopBound(c *token.LoopDef) BoundingBox {
	var bx BoundingBox
	bx.Reset()
	if len(*c) == 1 {
		plg, _ := view.FetchPolygonEntry(&(*c)[0])
		return plg.Bound
	}
	for _, p := range *c {
		fe, _ := view.FetchBorderEntry(&p)
		box := fe.GetBound()
		bx.Merge(&box)
	}
	return bx
}

func (view *ViewPointSet) LoopCCW(cl *token.LoopDef) (bool, *BoundingBox) {
	sum := big.NewInt(0)
	tmp := big.NewInt(0)

	borders, box := view.ExpandLoop(cl)

	vp := borders[len(borders)-1].border
	ex, ey := int64(vp.End.Lng()-vp.Begin.Lng()), int64(vp.End.Lat()-vp.Begin.Lat())
	if borders[len(borders)-1].rev != 0 {
		ex, ey = -ex, -ey
	}
	for _, f := range borders {
		fx, fy := int64(f.border.End.Lng()-f.border.Begin.Lng()), int64(f.border.End.Lat()-f.border.Begin.Lat())
		if f.rev != 0 {
			fx, fy = -fx, -fy
		}
		u := ex*fy - ey*fx
		tmp.SetInt64(u)
		sum.Add(sum, tmp)
		ex, ey = fx, fy
	}

	return sum.Sign() > 0, &box
}

// addVertex adds the specified vertex to the view.
func (view *ViewPointSet) AddOnePolygon(b *token.PolygonDef, ccw bool, bx BoundingBox) bool {
	return view.addPolygon(b, ccw, bx)
}

// AddPolygon adds all vertex definitions in the passed transaction to the view.
func (view *ViewPointSet) AddPolygon(tx *btcutil.Tx) bool {
	// Loop all of the vertex definitions
	for _, txVtx := range tx.MsgTx().TxDef {
		if txVtx.IsSeparator() {
			continue
		}
		switch txVtx.(type) {
		case *token.PolygonDef:
			ccw := false
			th := txVtx.Hash()
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
			var bx BoundingBox
			if rcw, bx = view.PolygonInfo(txVtx.(*token.PolygonDef)); rcw != ccw {
				return false
			}
			if !view.addPolygon(txVtx.(*token.PolygonDef), ccw, bx) {
				return false
			}
			break
		}
	}
	return true
}

// FetchEntry attempts to find any vertex for the given hash by
// searching the entire view.  It checks the view first and then falls
// back to the database if needed.
func (view *ViewPointSet) FetchPolygonEntry(hash *chainhash.Hash) (*PolygonEntry, error) {
	// First attempt to find a utxo with the provided hash in the view.
	entry := view.Polygon.LookupEntry(*hash)
	if entry != nil {
		return entry, nil
	}

	// Check the database since it doesn't exist in the view.  This will
	// often by the case since only specifically referenced vertex are loaded
	// into the view.
	var err error
	err = view.Db.View(func(dbTx database.Tx) error {
		e, err := DbFetchPolygon(dbTx, hash)
		if err != nil {
				return err
			}
		entry = &PolygonEntry{
			Loops:       e.Loops,
			Bound:       e.Bound,
			FirstCW:     e.FirstCW,
			Depth:		 e.Depth,
			PackedFlags: 0,
		}
		view.Polygon.entries[*hash] = entry
		return err
	})

	return entry, err
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (entry *PolygonEntry) RollBack() {
	// Nothing to do if the output is already spent.
	if entry.toDelete() {
		return
	}

	// Mark the output as spent and modified.
	entry.PackedFlags |= TfSpent | TfModified
}

// disconnectTransactions updates the view by removing all of the transactions
// created by the passed block, removing all vertices defined in the transactions,
// and setting the best hash for the view to the block before the passed block.
func (view *ViewPointSet) disconnectPolygonTransactions(block *btcutil.Block) error {
	for _, tx := range block.Transactions() {
		for _, txDef := range tx.MsgTx().TxDef {
			if txDef.IsSeparator() {
				continue
			}
			switch txDef.(type) {
			case *token.PolygonDef:
				h := txDef.Hash()
				p := view.Polygon.LookupEntry(h)
				if p == nil {
					p, _ = view.FetchPolygonEntry(&h)
				}
				if p != nil {
					p.RollBack()
				}
			}
		}
	}

	// Update the best hash for view to the previous block since all of the
	// transactions for the current block have been disconnected.
	view.Polygon.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return nil
}

// RemoveEntry removes the given transaction output from the current state of
// the view.  It will have no effect if the passed output does not exist in the
// view.
func (view * PolygonViewpoint) RemoveEntry(hash chainhash.Hash) {
	delete(view.entries, hash)
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view * PolygonViewpoint) Entries() map[chainhash.Hash]*PolygonEntry {
	return view.entries
}

// commit. this is to be called after data has been committed to db
func (view * PolygonViewpoint) commit() {
	for outpoint, entry := range view.entries {
		if entry == nil || ((entry.PackedFlags & TfSpent) == TfSpent) {
			delete(view.entries, outpoint)
			continue
		}

		entry.PackedFlags &^= TfModified
	}
}

// fetchVertexMain fetches vertex data about the provided
// set of vertices from the point of view of the end of the main chain at the
// time of the call.
//
// Upon completion of this function, the view will contain an entry for each
// requested vertices.
func (view * PolygonViewpoint) fetchPolygonMain(db database.DB, b map[chainhash.Hash]struct{}) error {
	// Nothing to do if there are no requested outputs.
	if len(b) == 0 {
		return nil
	}

	// Load the requested set of vertices from the point
	// of view of the end of the main chain.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the store as a way
	// to unnecessarily avoid attempting to reload it from the database.
	return db.View(func(dbTx database.Tx) error {
		for vtx,_ := range b {
			e, err := DbFetchPolygon(dbTx, &vtx)
			if err != nil {
				return err
			}

			view.entries[vtx] = &PolygonEntry{
				Loops: e.Loops,
				Bound: e.Bound,
				Depth: e.Depth,
				PackedFlags: 0,
			}
		}

		return nil
	})
}

// fetchVertex loads the vertices for the provided set into the view
// from the database as needed unless they already exist
// in the view in which case they are ignored.
func (view * PolygonViewpoint) FetchPolygon(db database.DB, b map[chainhash.Hash]struct{}) error {
	// Nothing to do if there are no requested vertices.
	if len(b) == 0 {
		return nil
	}

	// Filter entries that are already in the view.
	neededSet := make(map[chainhash.Hash]struct{})
	for vtx := range b {
		// Already loaded into the current view.
		if _, ok := view.entries[vtx]; ok {
			continue
		}

		neededSet[vtx] = struct{}{}
	}

	// Request the input utxos from the database.
	return view.fetchPolygonMain(db, neededSet)
}

// NewVtxViewpoint returns a new empty vertex view.
func NewPolygonViewpoint() * PolygonViewpoint {
	return &PolygonViewpoint{
		entries: make(map[chainhash.Hash]*PolygonEntry),
	}
}


// dbPutVtxView uses an existing database transaction to update the vertex set
// in the database based on the provided utxo view contents and state. In
// particular, only the entries that have been marked as modified (meaning new)
// and not spent (meaning not to be deleted) are written to the database.
func DbPutPolygonView(dbTx database.Tx, view *PolygonViewpoint) error {
	bucket := dbTx.Metadata().Bucket(polygonSetBucketName)
	for hash, entry := range view.Entries() {
		// No need to update the database if the entry was not modified.
		if entry == nil || !entry.isModified() {
			continue
		}

		// Remove the utxo entry if it is spent.
		if entry.toDelete() {
			if err := bucket.Delete(hash[:]); err != nil {
				return err
			}
			continue
		}

		// Serialize and store the utxo entry.
		serialized, err := serializePolygonEntry(entry)
		if err != nil {
			return err
		}

		if err = bucket.Put(hash[:], serialized); err != nil {
			return err
		}
	}

	return nil
}

// serializeVtxEntry returns the entry serialized to a format that is suitable
// for long-term storage.  The format is described in detail above.
func serializePolygonEntry(entry *PolygonEntry) ([]byte, error) {
	// Spent outputs have no serialization.
	if entry.toDelete() {
		return nil, nil
	}

	size := bccompress.SerializeSizeVLQ(uint64(len(entry.Loops))) + 16 + 1 + 1
	for _, l := range entry.Loops {
		size += bccompress.SerializeSizeVLQ(uint64(len(l))) + len(l) * chainhash.HashSize
	}

	var serialized = make([]byte, size)

	bccompress.PutVLQ(serialized[:], uint64(len(entry.Loops)))
	p := bccompress.SerializeSizeVLQ(uint64(len(entry.Loops)))
	for _, l := range entry.Loops {
		bccompress.PutVLQ(serialized[p:], uint64(len(l)))
		p += bccompress.SerializeSizeVLQ(uint64(len(l)))
		for _,t := range l {
			copy(serialized[p:], t[:])
			p +=  chainhash.HashSize
		}
	}

	copy(serialized[p:], entry.Bound.serialize())
	serialized[p + 16] = entry.Depth
	if entry.FirstCW {
		serialized[p + 17] = 1
	}

	return serialized, nil
}

func DbFetchPolygon(dbTx database.Tx, hash *chainhash.Hash) (*PolygonEntry, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(polygonSetBucketName)
	serialized := hashIndex.Get(hash[:])

	if serialized == nil {
		str := fmt.Sprintf("polygon %s does not exist in the main chain", hash)
		return nil, bccompress.ErrNotInMainChain(str)
	}

	b := PolygonEntry {}

	loops, pos := bccompress.DeserializeVLQ(serialized)

	b.Loops = make([]token.LoopDef, loops)

	for i := uint64(0);  i < loops; i++ {
		bds, offset := bccompress.DeserializeVLQ(serialized[pos:])
		pos += offset
		loop := make([]chainhash.Hash, bds)
		for j := uint64(0);  j < bds; j++ {
			copy(loop[j][:], serialized[pos:pos + chainhash.HashSize])
			pos += chainhash.HashSize
		}
		b.Loops[i] = loop
	}
	b.Bound.unserialize(serialized[pos:])
	b.FirstCW = false
	b.Depth = serialized[pos + 16]
	if len(serialized) > pos + 17 {
		b.FirstCW = (serialized[pos + 17] != 0)
	}

	return &b, nil
}

func dbRemovePolygon(dbTx database.Tx, hash *chainhash.Hash) error {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(polygonSetBucketName)

	return hashIndex.Delete(hash[:])
}