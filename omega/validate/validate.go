// Copyright (c) 2019 The Omega developers
// Use of this source code is governed by an license that can
// be found in the LICENSE file.

package validate

import (
	"fmt"
	"math"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/omega"
	"github.com/btcsuite/omega/viewpoint"
	"github.com/btcsuite/btcutil"
	"sort"
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
			h := v.Hash()
			refd := false
			for _, b := range msgTx.TxDef {
				switch b.(type) {
				case *token.BorderDef:
					bd := b.(*token.BorderDef)
					if bd.Begin.IsEqual(&h) || bd.End.IsEqual(&h) {
						refd = true
					}
					break
				}
			}
			if !refd {
				str := fmt.Sprintf("Vertex %s is defined but not referenced.", h.String())
				return ruleError(1, str)
			}
			if !saneVertex(v) {	// check coords is in valid range
				str := fmt.Sprintf("Insane vertex %v (%f， %f) => (%d， %d)", v.Hash(), float64(int32(v.Lat)) / token.CoordPrecision, float64(int32(v.Lng)) / token.CoordPrecision, int32(v.Lat), int32(v.Lng))
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
				if to.IsNumeric() {
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
				if !to.HasRight() {
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

func saneVertex(v * token.VertexDef) bool {
	// it is a valid earth geo coord?
	x := float64(int32(v.Lng)) / token.CoordPrecision
	y := float64(int32(v.Lat)) / token.CoordPrecision
	if y < -90 || y > 90 {
		return false
	}

	var vertices = omega.IntlDateLine

	k := 0
	for i := 0; i < len(vertices) - 1; i++ {
		if vertices[i][0] >= y && y >= vertices[i+1][0] {
			k = i
		}
	}
	var l [2]float64
	var r [2]float64

	if vertices[k][1] > 0 {
		l[0] = vertices[k][1] - 360.0
		r[0] = vertices[k][1]
	} else {
		r[0] = vertices[k][1] + 360.0
		l[0] = vertices[k][1]
	}
	if vertices[k+1][1] > 0 {
		l[0] = vertices[k+1][1] - 360.0
		r[0] = vertices[k+1][1]
	} else {
		r[0] = vertices[k+1][1] + 360.0
		l[0] = vertices[k+1][1]
	}

	if x < (l[0] + (l[1] - l[0]) * (y - vertices[k][0]) / (vertices[k][1] - vertices[k][0])) ||
		x > (r[0] + (r[1] - r[0]) * (y - vertices[k][0]) / (vertices[k][1] - vertices[k][0])) {
		return false
	}
	return true
}

type tokenElement struct {
	tokenType uint64
	polygon chainhash.Hash
	right chainhash.Hash
}

// CheckTransactionInputs performs a series of checks on the inputs to a
// transaction to ensure they are valid.  An example of some of the checks
// include verifying all inputs exist, ensuring the coinbase seasoning
// requirements are met, detecting double spends, validating all values and fees
// are in the legal range and the total output amount doesn't exceed the input
// amount, and verifying the signatures to prove the spender was the owner of
// the bitcoins and therefore allowed to spend them.  As it checks the inputs,
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
			ft,_ := views.Polygon.FetchEntry(*views.Db, &h)
			if ft != nil {		// father does not exist
				return ruleError(1, "Illegal Polygon definition.")
			}

			p := d.(*token.PolygonDef)
			if err := sanePolygon(p, views); err != nil {
				return err
			}
			views.Polygon.AddOnePolygon(p)
			break
		case *token.VertexDef:
			ft,_ := views.Vertex.FetchEntry(*views.Db, &h)
			if ft != nil {		// father does not exist
				return ruleError(1, "Illegal Vertex definition.")
			}

			v := d.(*token.VertexDef)
			views.Vertex.AddOneVertex(v)
			break
		case *token.BorderDef:
			ft,_ := views.Border.FetchEntry(*views.Db, &h)
			if ft != nil {		// no repeat definition
				return ruleError(1, "Illegal Border definition.")
			}

			b := d.(*token.BorderDef)
			f := &b.Father

			if _,ok := redefbl[*f]; ok {
				redefbl[h] = struct{}{}
			}

			if !f.IsEqual(&chainhash.Hash{}) {
				ft,_ = views.Border.FetchEntry(*views.Db, f)
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
			break
		case *token.RightDef, *token.RightSetDef:
			ft,_ := views.Rights.FetchEntry(*views.Db, &h)
			if ft != nil {		// father does not exist
				return ruleError(1, "Illegal Rights definition.")
			}

			switch d.(type) {
			case *token.RightDef:
				f := &d.(*token.RightDef).Father
				if !f.IsEqual(&chainhash.Hash{}) {
					ft,_ := views.Rights.FetchEntry(*views.Db, f)
					if ft == nil || ft.(*token.RightDef).Attrib & 2 != 0 {		// father is indivisible
						return ruleError(1, "Illegal Right definition.")
					}
				}
				break
			case *token.RightSetDef:
				for _, r := range d.(*token.RightSetDef).Rights {
					ft,_ := views.Rights.FetchEntry(*views.Db, &r)
					if ft == nil {
						return ruleError(1, "Illegal Right definition.")
					}
				}
				break
			}
		}
	}

	for f, pend := range pendBdr {
		// check whether these borders are allowed
		fb, _ := views.Border.FetchEntry(*views.Db, &f)

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
		// or union of the right sets of the polygons on both sides have the right set as the root polygon
		isonline := true
		delim := (*viewpoint.VtxEntry)(nil)
		fbv,_ := views.Vertex.FetchEntry(*views.Db, &fb.Begin)
		fev,_ := views.Vertex.FetchEntry(*views.Db, &fb.End)
		for i := 1; i < len(pend); i ++ {
			r,_ := views.Vertex.FetchEntry(*views.Db, &pend[i].Begin)
			if isonline && (r == nil || !online(r, fbv, fev, delim)) {
				isonline = false
			}
			delim = r
		}
		if !isonline {
			for _,r := range pend {
				rights := make([]map[chainhash.Hash]struct{}, 2)
				for _, txIn := range tx.MsgTx().TxIn {
					utxo := views.Utxo.LookupEntry(txIn.PreviousOutPoint)
					if utxo.TokenType != 3 {
						continue
					}
					h := &utxo.Amount.(*token.HashToken).Hash
					p,_ := views.Polygon.FetchEntry(*views.Db, h)
					if dir := containEdge(p, views, r); dir != 2 {
						for _, rt := range viewpoint.SetOfRights(views, utxo.Rights) {
							rights[dir][rt.ToToken().Hash()] = struct{}{}
						}
					}
				}
				mg := true
				for mg {
					mg = false
					for d := 0; d < 2; d++ {
						for rt, _ := range rights[d] {
							rv := views.Rights.LookupEntry(rt)
							s := rv.(*viewpoint.RightEntry).Sibling()
							if _, ok := rights[d][s]; ok {
								delete(rights[d], s)
								delete(rights[d], rt)
								rights[d][rv.(*viewpoint.RightEntry).Father] = struct{}{}
								mg = true
							}
						}
					}
				}
				if len(rights[0]) != 1 || len(rights[1]) != 1  {
					return ruleError(1, "Illegal border definition.")
				}
				for d := 0; d < 2; d++ {
					for rt, _ := range rights[d] {
						if !viewpoint.InSet(views, rt, chainParams.GenesisBlock.Transactions[1].TxOut[0].Rights) {
							return ruleError(1, "Illegal border definition.")
						}
					}
				}
			}
		}
	}

	return nil
}

func containEdge(p * viewpoint.PolygonEntry, views * viewpoint.ViewPointSet, r * token.BorderDef) byte {
	for r != nil {
		for _,loop := range p.Loops {
			for _,b := range loop {
				d := b[0] & 0x1
				b[0] &= 0xFE
				rh := r.Hash()
				if rh.IsEqual(&b) {
					return d
				}
			}
		}
		if r.Father.IsEqual(&chainhash.Hash{}) {
			return 2
		}
		f,_ := views.Border.FetchEntry(*views.Db, &r.Father)
		if f == nil {
			return 2
		}
		r = &token.BorderDef {
			Father:f.Father,
			Begin:f.Begin,
			End:f.End,
		}
	}

	return 2
}

const GeoError = float64(0.0001)	// allowed error relative to length of edge

func online(r * viewpoint.VtxEntry, begin * viewpoint.VtxEntry, end * viewpoint.VtxEntry, delim * viewpoint.VtxEntry) bool {
	rf := [2]float64{float64(int64(r.Lng)), float64(int64(r.Lat))}
	bf := [2]float64{float64(int64(begin.Lng)), float64(int64(begin.Lat))}
	ef := [2]float64{float64(int64(end.Lng)), float64(int64(end.Lat))}

	len := (ef[0] - bf[0]) * (ef[0] - bf[0]) + (ef[1] - bf[1]) * (ef[1] - bf[1])

	t := (rf[0] - bf[0]) * (ef[0] - bf[0]) + (rf[1] - bf[1]) * (ef[1] - bf[1])
	if t < 0 || t > len {
		return false
	}
	d := (rf[0] - bf[0]) * (ef[1] - bf[1]) - (rf[1] - bf[1]) * (ef[0] - bf[0])
	if math.Abs(d) > GeoError * len {
		return false
	}

	if delim != nil {
		df := [2]float64{float64(int64(delim.Lng)), float64(int64(delim.Lat))}
		if (df[0] - bf[0]) * (ef[0] - bf[0]) + (df[1] - bf[1]) * (ef[1] - bf[1]) >= t {
			return false
		}
	}
	return true
}

type edge struct {
	begin chainhash.Hash
	end chainhash.Hash
	hash chainhash.Hash
	children []chainhash.Hash
	rev byte

	// begin coord
	lat int32
	lng int32
	x float64
	y float64

	// bounding box
	west int32
	east int32
	south int32
	north int32
}

func NewEdge(rev byte, hash chainhash.Hash, views *viewpoint.ViewPointSet, lp * viewpoint.BorderEntry) * edge {
	var np *edge
	if rev == 0 {
		np = & edge{
			begin: lp.Begin,
			end: lp.End,
			rev: 0,
			lat: lp.Lat(views, false),
			lng: lp.Lng(views, false),
		}
	} else {
		np = & edge{
			begin: lp.End,
			end: lp.Begin,
			rev: 1,
			lng: lp.Lng(views, true),
			lat: lp.Lat(views, true),
		}
	}
	np.rev = rev
	copy(np.hash[:], hash[:])
	np.hash[0] &= 0xFE
	np.children = lp.Children
	np.west,np.east,np.south,np.north = lp.West(views),lp.East(views),lp.South(views),lp.North(views)
	np.x, np.y = float64(np.lng) / token.CoordPrecision, float64(np.lat) / token.CoordPrecision

}
type polygon struct {
	loops [][]*edge
}

func expandBorder(hash chainhash.Hash, views *viewpoint.ViewPointSet, rev byte) []*edge {
	var h chainhash.Hash

	h.SetBytes(hash.CloneBytes())
	h[0] &= 0xFE
	lp, _ := views.Border.FetchEntry(*views.Db, &h)
	if lp == nil {
		return nil
	}
	if len(lp.Children) > 0 {
		t := make([]*edge, 0, len(lp.Children))
		for _, c := range lp.Children {
			res := expandBorder(c, views, rev)
			if res == nil {
				return nil
			}
			if rev == 1 {
				t = append(res, t[:]...)
			} else {
				t = append(t, res[:]...)
			}
		}
		return t
	}
	if rev == 1 {
		return []*edge{&edge{
				begin:lp.End,
				end:lp.Begin,
				hash:hash,
				rev:rev,
				west: lp.West(views),
				east: lp.East(views),
				south: lp.South(views),
				north: lp.North(views),
			},
		}
	}
	return []*edge{&edge{
		begin:lp.Begin,
		end:lp.End,
		hash:hash,
		west: lp.West(views),
		east: lp.East(views),
		south: lp.South(views),
		north: lp.North(views),
		},
	}
}

func expandBorderOnce(hash chainhash.Hash, views *viewpoint.ViewPointSet, rev byte) []*edge {
	lp, _ := views.Border.FetchEntry(*views.Db, &hash)

	if lp.Children != nil && len(lp.Children) > 0 {
		t := make([]*edge, len(lp.Children))
		for i, c := range lp.Children {
			n := i
			if rev == 1 {
				n = len(lp.Children) - 1 - i
			}
			p, _ := views.Border.FetchEntry(*views.Db, &c)
			t[n] = NewEdge(rev, c, views, p)
		}
		return t
	}
	return nil
}

func disjoint(a * edge, b * edge) bool {
	// test whether bounding boxes are disjoint
	if a.west > b.east || b.west > a.east {
		return true
	}
	if a.south > b.north || b.south > a.north {
		return true
	}
	return false
}

func sanePolygon(p *token.PolygonDef, views *viewpoint.ViewPointSet) error {
	// 1. check everything has been defined and loop is indeed a loop
	q := &polygon{
		loops:make([][]*edge, 0),
	}
	for _,loop := range p.Loops {
		t := make([]*edge, 0, len(loop))
		for _, l := range loop {
			lp, _ := views.Border.FetchEntry(*views.Db, &l)
			if lp == nil {
				return ruleError(2, "Undefined border")
			}
			np := NewEdge(l[0] & 0x1, l, views, lp)
			np.hash = l
			t = append(t, np)
			/*
						res := expandBorder(l, views, l[0] & 0x1)
						if res == nil {
							str := fmt.Sprintf("Undefined border %s in polygon %s", l.String(), p.Hash().String())
							return ruleError(2, str)
						}
						t = append(t, res[:]...)
			*/
		}

		vp := &t[len(t) - 1].end
		for i,l := range t {
			q := &l.begin
			b,_ := views.Vertex.FetchEntry(*views.Db, q)
			if b == nil {
				str := fmt.Sprintf("Undefined vertex %s in polygon ", q.String(), p.Hash().String())
				return ruleError(1, str)
			}

			fmt.Printf("Vertex: %f, %f\n", l.x, l.y)

			if q.IsEqual(vp) {
				vp = &l.end
			} else {
				str := fmt.Sprintf("Unconnected %d-th borders %s,%s,%s in polygon %s", i, t[i-1].begin.String(), t[i-1].end.String(), t[i].begin.String(), p.Hash().String())
				return ruleError(1, str)
			}
		}
		q.loops = append(q.loops, t)
	}

	// 2. check the first loop in polygon is ccw
	cl, sum := q.loops[0], 0.0
	vp := cl[len(cl) - 1]
	ex, ey := cl[0].x - vp.x, cl[0].y - vp.y
	for i,l := range cl {
		f := cl[(i+1) % len(cl)]
		fx := f.x - l.x
		fy := f.y - l.y
		sum += ex * fy - ey * fx
		ex = fx
		ey = fy
	}
	if sum <= 0 {
		str := fmt.Sprintf("First loop is not counter clock-wise in polygon %s", p.Hash().String())
		return ruleError(1, str)
	}

	// 3. check all other loops are completely inside the ccw loop

	// prepare:
	// we need to find out how many intersections there are
	// for a ray from a vertex with the ccw loop. If the number is
	// odd, it is inside. otherwise it is outseide of the ccw loop.
	// remember that edges here are not bottom edges. so we first expand edges until their bounding
	// boxes are not intersecting or the edge is bottom
	// if the bouding boxes are not intersecting, we can use center of bouding box to represent all
	// vertices
	// the the bouding boxes are intersecting even when we have reached the bottom, we have to do it
	// conventional way

	for k,loop := range q.loops {
		if k == 0 {
			continue
		}
reloop:
		for i,v := range loop {
		reloop2:
			for j,l := range cl {
				if disjoint(v, l) {
					continue
				}
				var xspan int32
				var yspan int32
				if v.west < l.west {
					if v.east > l.west {
						xspan = v.east - l.west
					}
				} else {
					if v.east < l.west {
						xspan = l.east - v.west
					}
				}
				if v.south < l.south {
					if v.north > l.south {
						yspan = v.north - l.south
					}
				} else {
					if v.north < l.south {
						yspan = l.north - v.south
					}
				}
				splitv := false
				if (yspan > xspan && v.north-v.south > l.north-l.south) || (xspan > yspan && v.east-v.west > l.east-l.west) {
					splitv = true
					lp,_ := views.Border.FetchEntry(*views.Db, &v.hash)
					if lp.Children != nil && len(lp.Children) > 0 {
						qr := append(loop[:i], expandBorderOnce(v.hash, views, v.hash[0] & 1)[:]...)
						qr = append(qr, loop[i+1:]...)
						q.loops[k] = qr
						loop = qr
						goto reloop
					} else {
						splitv = false
					}
				}
				if !splitv {
					lp,_ := views.Border.FetchEntry(*views.Db, &l.hash)
					if lp.Children != nil && len(lp.Children) > 0 {
						qr := append(cl[:j], expandBorderOnce(l.hash, views, l.hash[0] & 1)[:]...)
						qr = append(qr, cl[j+1:]...)
						q.loops[0] = qr
						cl = qr
						goto reloop2
					}
				}
			}
		}
	}

	for k,loop := range q.loops {
		if k == 0 {
			continue
		}

		// check # of intersections of an ray from inner loop vertex in an optimal direction
		// that results in smaller error in intersection calculation

		for _,v := range loop {
			// selection direction
			points := make([]float64, 0, len(loop))
			var dir float64
			for _,l := range cl {
				if l.y <= v.y {
					continue
				}
				points = append(points, (l.x - v.x) / (l.y - v.y))
			}
			if len(points) == 0 {
				str := fmt.Sprintf("Border %s ouside counter clock-wise loops in polygon %s", v.hash.String(), p.Hash().String())
				return ruleError(1, str)
			}
			if len(points) == 1 {
				for i,l := range cl {
					if l.y <= v.y {
						continue
					}
					m := cl[(i+1) % len(cl)]
					dir = ((l.x - v.x) / (l.y - v.y) + (m.x - v.x) / (m.y - v.y)) / 2.0
				}
			} else {
				sort.Float64s(points)
				diff := float64(0.0)
				for i := 1; i < len(points); i++ {
					if diff < points[i] - points[i-1] {
						dir = (points[i] + points[i-1]) / 2
						diff = points[i] - points[i-1]
					}
				}
			}

			intersects := 0
			// the direction we choose is (dir, 1.0). now find out how many intersections there are
			// for a ray in this direction starting from current vertex with the ccw loop. If the number is
			// odd, it is inside. otherwise it is outseide of the ccw loop
			// remember that edges here are not bottom edges. so we first expand edges until their bounding
			// boxes are not intersecting or the edge is bottom
			// if the bouding boxes are not intersecting, we can use center of bouding box to represent all
			// vertices
			// the the bouding boxes are intersecting even when we have reached the bottom, we have to do it
			// conventional way

			vp := cl[len(cl) - 1]
			for _,l := range cl {
				if vp.y < v.y && l.y <= v.y {
					vp = l
					continue
				}
				if vp.x > v.x && l.x >= v.x {
					vp = l
					continue
				}
				if vp.x < v.x && l.x <= v.x {
					vp = l
					continue
				}
				if intersect(v, dir, vp, l) {
					intersects++
				}
				vp = l
			}
			if intersects > 0 && intersects & 1 == 0 {
				str := fmt.Sprintf("Vertex %f, %f is ouside polygon %s (%d loops)\n", v.x, v.y, p.Hash().String(), len(p.Loops))
				str += fmt.Sprintf("intersects = %d, dir = (%f, 1.0)", intersects, dir)
				return ruleError(1, str)
			}
		}
	}

	// 4. check that there is no intersection between edges
	for i,loop := range q.loops {
		vp := loop[len(loop) - 1]
		for j,l := range loop {
			for m := i; m < len(q.loops); m++ {
				loop2 := q.loops[m]
				if m == i {
					vp2 := loop2[j]
					for n := j; n <= len(loop2); n++ {
						l2 := loop2[n % len(loop2)]
						if intersect2(vp, l, vp2, l2) {
							str := fmt.Sprintf("Intersecting edges in polygon %s", p.Hash().String())
							return ruleError(1, str)
						}
						vp2 = l2
					}
				} else {
					vp2 := loop2[len(loop2) - 1]
					for _,l2 := range loop2 {
						if intersect2(vp, l, vp2, l2) {
							str := fmt.Sprintf("Intersecting edges in polygon %s", p.Hash().String())
							return ruleError(1, str)
						}
						vp2 = l2
					}
				}
			}
			vp = l
		}
	}

	return nil
}

func intersect2(a *edge, b *edge, c *edge, d *edge) bool {
	if disjoint(a, c) {
		return false
	}
	t := ((b.x - a.x) * (a.y - c.y) + (b.y-a.y) * (c.x - a.x)) / ((b.x - a.x) * (d.y - c.y) - (b.y - a.y) * (d.x - c.x))
	s := ((d.x - c.x) * (c.y - a.y) + (d.y-c.y) * (a.x - c.x)) / ((d.x - c.x) * (b.y - a.y) - (d.y - c.y) * (b.x - a.x))
	return t >= 0 && t < 1.0 && s >= 0 && s < 1.0
}

func intersect(v *edge, dir float64, vp *edge, l *edge) bool {
	t1 := v.x - vp.x + dir * (v.y - vp.y)
	t2 := l.x - vp.x + dir * (l.y - vp.y)

	if !(t1 * t2 >= 0 && math.Abs(t1) < math.Abs(t2)) {
		return false;
	}

	return v.y - (vp.y + (t1 / t2) * (l.y - vp.y)) > 0
}

func CheckGeometryIntegrity(tx *btcutil.Tx, views *viewpoint.ViewPointSet) bool {
	rset := parseRights(tx, views, false, 0)

	ancester := getAncester(rset, views)

	// Group geometries by their rights. map[right][in/out]polygon
	groups := make(map[tokenElement][2]map[chainhash.Hash]struct{})

	for _, txIn := range tx.MsgTx().TxIn {
		out := txIn.PreviousOutPoint
		x := views.Utxo.LookupEntry(out)
		emt := tokenElement{
			tokenType: x.TokenType,
		}
		y := tokenRights(views, x)

		for _, r := range y {
			for i, s := range (*ancester)[r] {
				f := 1
				if i == len((*ancester)[r]) - 1 {
					f = 0
					emt.right = s
				} else {
					emt.right = views.Rights.LookupEntry(s).(*viewpoint.RightEntry).Sibling()
				}
				if _,ok := groups[emt][f][x.Amount.(*token.HashToken).Hash]; ok {
					return false	// duplicated geometry
				} else {
					if _,ok := groups[emt]; !ok {
						groups[emt] = [2]map[chainhash.Hash]struct{}{
							make(map[chainhash.Hash]struct{}, 0),
							make(map[chainhash.Hash]struct{}, 0)}
					}
					groups[emt][f][x.Amount.(*token.HashToken).Hash] = struct{}{}
				}
			}
		}
	}

	for _, x := range tx.MsgTx().TxOut {
		emt := tokenElement{
			tokenType: x.TokenType,
		}
		y := tokenRights(views, x)

		for _, r := range y {
			for i, s := range (*ancester)[r] {
				emt.right = s
				f := 0
				if i == len((*ancester)[r]) - 1 {
					f = 1
					emt.right = s
				} else {
					emt.right = views.Rights.LookupEntry(s).(*viewpoint.RightEntry).Sibling()
				}
				if _,ok := groups[emt][f][x.Value.(*token.HashToken).Hash]; ok {
					return false	// duplicated geometry
				} else {
					groups[emt][f][x.Value.(*token.HashToken).Hash] = struct{}{}
				}
			}
		}
	}

	// for each group, check geometry integrity
	for i, g := range groups {
		if len(g[0]) == len(g[1]) {
			for in,_ := range g[0] {
				if _,ok := g[1][in]; ok {
					delete(groups[i][0], in)
					delete(groups[i][1], in)
				}
			}
		}

		g = groups[i]
		// quick checked all matches, skip this one
		if len(g[0]) == 0 && len(g[1]) == 0 {
			delete(groups, i)
			continue
		}

		if len(g[0]) == 0 || len(g[1]) == 0 {
			return false
		}

		wpolygon := make(map[chainhash.Hash][][]*edge, 0)

		// merge geometries
		ingeo := GeoMerge(g[0], views, &wpolygon)
		outgeo := GeoMerge(g[1], views, &wpolygon)

		// check if they are the same
		for in,s := range ingeo {
			for out,t := range outgeo {
				if geoSame(&s, &t) {
					ingeo = append(ingeo[:in], ingeo[in+1:]...)
					outgeo = append(outgeo[:out], outgeo[out+1:]...)
				}
			}
		}

		if len(ingeo) != 0 || len(outgeo) != 0 {
			return false
		}
	}

	return true
}

func tokenRights(views *viewpoint.ViewPointSet, x interface{}) []chainhash.Hash {
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

func GeoMerge(old map[chainhash.Hash]struct{}, views *viewpoint.ViewPointSet, realgeo * map[chainhash.Hash][][]*edge) [][][]*edge {
	polygons := make([][][]*edge, 0, len(old))

	for p,_ := range old {
		if q,ok := (*realgeo)[p]; ok {
			polygons = append(polygons, q)
		} else {
			q, _ := views.Polygon.FetchEntry(*views.Db, &p)
			polygons = append(polygons, *(expand(&token.PolygonDef{Loops: q.Loops}, views)))
		}
	}

	for i,p := range polygons {
		repeat := true
		for repeat {
			repeat = false
			for j := i + 1; j < len(polygons); j++ {
				if q := merge(&p, &polygons[j], views); q != nil {
					p = *q
					polygons[i] = p
					polygons = append(polygons[:j], polygons[j+1:]...)
					repeat = true
					break
				}
			}
		}
	}
	return polygons
}

func merge(p * [][]*edge, q * [][]*edge, views *viewpoint.ViewPointSet) *[][]*edge {
	merged := false
	edges := make(map[chainhash.Hash]byte)
	edgeData := make(map[chainhash.Hash]*edge)
	v2edge := make(map[chainhash.Hash][]*edge)

	qd := NewQuadtree()
	for i, loop := range *p {
		for _, l := range loop {
			qd.addEdge(0, i, l)
		}
	}

	for i, loop := range *q {
		qd.insert(views, 1, i, loop)
	}

	if !qd.travse(func (p int, i int , l * edge) bool {
		if e,ok := edges[l.hash]; ok {
			if e == l.rev {
				return false	// illegal, two edges with same dir
			} else {
				merged = true
				delete(edges, l.hash)
			}
		} else {
			edges[l.hash] = l.rev
			if _,ok = v2edge[l.begin]; !ok {
				v2edge[l.begin] = make([]*edge, 0)
			}
			v2edge[l.begin] = append(v2edge[l.begin], l)

			if _,ok = v2edge[l.end]; !ok {
				v2edge[l.end] = make([]*edge, 0)
			}
			v2edge[l.end] = append(v2edge[l.end], l)
		}
		l.hash[0] |= l.rev
		edgeData[l.hash] = l
		return true
	}) {
		return nil
	}

	if !merged {
		return nil
	}

	r := make([][]*edge, 0)

	cur := (*chainhash.Hash)(nil)
	lp := (*[]*edge)(nil)
	head := (*chainhash.Hash)(nil)
	next := (*chainhash.Hash)(nil)
	for len(edges) > 0 {
		if cur == nil {
			for key,e := range edges {
				delete(edges, key)
				key[0] |= e
				cur = &key
				break
			}
			if lp != nil {
				r = append(r, *lp)
			}
			pp := make([]*edge, 0)
			lp = &pp
			pp = append(pp, edgeData[*cur])
			if cur[0] & 1 == 1 {
				head = &edgeData[*cur].end
				next = &edgeData[*cur].begin
			} else {
				head = &edgeData[*cur].begin
				next = &edgeData[*cur].end
			}
		} else if next.IsEqual(head) {
			cur = nil
		} else {
			for i, e := range v2edge[*next] {
				if (e.rev == 1 && e.end.IsEqual(next)) || (e.rev == 0 && e.begin.IsEqual(next)) {
					v2edge[*next] = append(v2edge[*next][:i], v2edge[*next][i+1:]...)
					cur = &e.hash
					cur[0] &= 0xFE
					if e.rev == 1 && e.end.IsEqual(next) {
						next = &e.begin
					} else {
						next = &e.end
					}
					delete(edges, *cur)
					cur[0] |= e.rev
					goto out
				}
			}
			return nil
		}
out:
	}

	if lp != nil {
		r = append(r, *lp)
	}

	return &r
}

func expand(in * token.PolygonDef, views *viewpoint.ViewPointSet) *[][]*edge {
	p := make([][]*edge, len(in.Loops))
	for i,loop := range in.Loops {
		p[i] = make([]*edge, 0, len(loop))
		for _,l := range loop {
			rev := l[0] & 0x1
			l[0] &= 0xFE
			exp := expandBorder(l, views, rev)
			p[i] = append(p[i], exp[:]...)
		}
	}
	return &p
}

func geoSame(in * [][]*edge, out * [][]*edge, views *viewpoint.ViewPointSet) bool {
	if len(*in) != len(*out) {
		return false
	}

	qd := NewQuadtree()
	for _, loop := range *in {
		for _, l := range loop {
			qd.addEdge(0, 0, l)
		}
	}

	for _, loop := range *out {
		for _, l := range loop {
			if !qd.remove(views, l) {
				return false
			}
		}
	}

	return qd.empty()
}

func parseRights(tx *btcutil.Tx, views *viewpoint.ViewPointSet, checkPolygon bool, uncheck uint64) * map[chainhash.Hash]struct{} {
	neg := chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }

	// put all rights in input & output to rset
	rset := make(map[chainhash.Hash]struct{})
	rset[neg] = struct{}{}

	for _, txOut := range tx.MsgTx().TxOut {
		if !checkPolygon && txOut.TokenType & 1 == uncheck {
			continue
		}
		if txOut.TokenType & 3 == 1 {
			continue
		}

		if txOut.Rights != nil {
			p := views.Rights.LookupEntry(*txOut.Rights)
			if p == nil {
				views.Rights.FetchEntry(*views.Db, txOut.Rights)
				p = views.Rights.LookupEntry(*txOut.Rights)
			}

			switch p.(type) {
			case *viewpoint.RightSetEntry:
				for _, r := range p.(*viewpoint.RightSetEntry).Rights {
					if _, ok := rset[r]; !ok {
						rset[r] = struct{}{}
						views.Rights.FetchEntry(*views.Db, &r)
					}
				}
			}
		}
	}

	for _, txIn := range tx.MsgTx().TxIn {
		out := txIn.PreviousOutPoint
		x := views.Utxo.LookupEntry(out)
		if x == nil {
			r := make(map[wire.OutPoint]struct{})
			r[out] = struct{}{}
			x = views.Utxo.LookupEntry(out)
		}
		if x.TokenType & 1 == 0 {
			continue
		}
		if x.TokenType & 3 == 1 {
			continue
		}

		if x.Rights != nil {
			p := views.Rights.LookupEntry(*x.Rights)
			if p == nil {
				views.Rights.FetchEntry(*views.Db, x.Rights)
				p = views.Rights.LookupEntry(*x.Rights)
			}

			switch p.(type) {
			case *viewpoint.RightSetEntry:
				for _, r := range p.(*viewpoint.RightSetEntry).Rights {
					if _, ok := rset[r]; !ok {
						rset[r] = struct{}{}
						views.Rights.FetchEntry(views.Db, &r)
					}
				}
			}
		}
	}

	return &rset
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
	for _, txIn := range tx.MsgTx().TxIn {
		out := txIn.PreviousOutPoint
		x := views.Utxo.LookupEntry(out)
		emt := tokenElement{
			tokenType: x.TokenType,
		}
		if emt.tokenType & 1 == 1 {
			emt.polygon = x.Amount.(*token.HashToken).Hash
		}

		y := tokenRights(views, x)

		for _, r := range y {
			for i, s := range (*ancester)[r] {
				f := int64(-1)
				if i == len((*ancester)[r]) - 1 {
					f = 1
					emt.right = s
				} else {
					emt.right = views.Rights.LookupEntry(s).(*viewpoint.RightEntry).Sibling()
				}
				if emt.tokenType & 1 == 0 {
					f *= x.Amount.(*token.NumToken).Val
				}
				if _,ok := sumVals[emt]; ok {
					sumVals[emt] += f
				} else {
					sumVals[emt] = f
				}
			}
		}
	}

	for _, x := range tx.MsgTx().TxOut {
		emt := tokenElement{
			tokenType: x.TokenType,
		}
		if emt.tokenType & 1 == 1 {
			emt.polygon = x.Value.(*token.HashToken).Hash
		}
		y := tokenRights(views, x)
		for _, r := range y {
			for i, s := range (*ancester)[r] {
				emt.right = s
				f := int64(1)
				if i == len((*ancester)[r]) - 1 {
					f = -1
					emt.right = s
				} else {
					emt.right = views.Rights.LookupEntry(s).(*viewpoint.RightEntry).Sibling()
				}
				if emt.tokenType & 1 == 0 {
					f *= x.Value.(*token.NumToken).Val
				}
				if _,ok := sumVals[emt]; ok {
					sumVals[emt] += f
				} else {
					sumVals[emt] = f
				}
			}
		}
	}

	// is i/o balanced?
	for emt,v := range sumVals {
		if v != 0 && emt.tokenType & 0x1 == 0 {
			str := fmt.Sprintf("Tx %v input does not match output in rights.", tx.Hash())
			return false, ruleError(1, str)
		}
	}

	if checkPolygon {
		return false, nil
	}

	for _,v := range sumVals {
		if v != 0 {
			return false, nil
		}
	}

	return true, nil
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
