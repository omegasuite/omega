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
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/token"
	"github.com/omegasuite/omega/viewpoint"
)

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func online(r * token.VertexDef, begin * token.VertexDef, end * token.VertexDef, delim * token.VertexDef) bool {
	// determine whether point r is on the line segment of (begin, end) in that it
	// is the closest grid point to the line.
	rf := [2]int64{int64(r.Lng()), int64(r.Lat())}
	bf := [2]int64{int64(begin.Lng()), int64(begin.Lat())}
	ef := [2]int64{int64(end.Lng()), int64(end.Lat())}

	len := (ef[0] - bf[0]) * (ef[0] - bf[0]) + (ef[1] - bf[1]) * (ef[1] - bf[1])

	t := (rf[0] - bf[0]) * (ef[0] - bf[0]) + (rf[1] - bf[1]) * (ef[1] - bf[1])
	if t < 0 || t > len {	// outside begin & end point
		return false
	}

	d := (rf[0] - bf[0]) * (ef[1] - bf[1]) - (rf[1] - bf[1]) * (ef[0] - bf[0])
	mn1 := abs(ef[1] - bf[1])
	mn2 := abs(ef[0] - bf[0])
	if mn2 < mn1 {
		mn1 = mn2
	}
	mn1 /= 2
	if d > mn1 {
		return false
	}

	if delim != nil {
		// further restrict it to not beyond the range defined by delim
		df := [2]int64{int64(delim.Lng()), int64(delim.Lat())}
		if (df[0] - bf[0]) * (ef[0] - bf[0]) + (df[1] - bf[1]) * (ef[1] - bf[1]) >= t {
			return false
		}
	}
	return true
}

/*
type edge struct {
	begin token.VertexDef
	end token.VertexDef
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
			lat: lp.Lat(false),
			lng: lp.Lng(false),
		}
	} else {
		np = & edge{
			begin: lp.End,
			end: lp.Begin,
			rev: 1,
			lng: lp.Lng(true),
			lat: lp.Lat(true),
		}
	}
	np.rev = rev
	copy(np.hash[:], hash[:])
	np.hash[0] &= 0xFE
	np.children = lp.Children
	np.west,np.east,np.south,np.north = lp.West(),lp.East(),lp.South(),lp.North()
	np.x, np.y = float64(np.lng) / token.CoordPrecision, float64(np.lat) / token.CoordPrecision
	return np
}

type polygon struct {
	loops [][]*edge
}

 */

/*
func expandBorder(hash chainhash.Hash, views *viewpoint.ViewPointSet, rev byte) []*edge {
	lp, _ := views.FetchBorderEntry(&hash)
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
				t = append(res, t...)
			} else {
				t = append(t, res...)
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
				west: lp.West(),
				east: lp.East(),
				south: lp.South(),
				north: lp.North(),
			},
		}
	}
	return []*edge{&edge{
		begin:lp.Begin,
		end:lp.End,
		hash:hash,
		west: lp.West(),
		east: lp.East(),
		south: lp.South(),
		north: lp.North(),
		},
	}
}
 */

/*
func expandBorderOnce(hash chainhash.Hash, views *viewpoint.ViewPointSet, rev byte) []*edge {
	lp, _ := views.FetchBorderEntry(&hash)

	if lp.Children != nil && len(lp.Children) > 0 {
		t := make([]*edge, len(lp.Children))
		for i, c := range lp.Children {
			n := i
			if rev == 1 {
				n = len(lp.Children) - 1 - i
			}
			p, _ := views.FetchBorderEntry(&c)
			t[n] = NewEdge(rev, c, views, p)
		}
		return t
	}
	return nil
}
 */

/*
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
 */

/*
func fetchPolygon(p *token.PolygonDef, views *viewpoint.ViewPointSet) (*polygon, error) {
	q := &polygon{
		loops:make([][]*edge, 0),
	}
	loops := views.Flattern(p.Loops)

	for _,loop := range loops {
		t := make([]*edge, 0, len(loop))
		for _, l := range loop {
			lp, _ := views.FetchBorderEntry(&l)
			if lp == nil {
					return nil, ruleError(2, "Undefined border")
				}
			np := NewEdge(l[0]&0x1, l, views, lp)
			np.hash = l
			t = append(t, np)
		}

		vp := &t[len(t)-1].end
		for i, l := range t {
			q := &l.begin

			fmt.Printf("Vertex: %f, %f\n", l.x, l.y)

			if q.IsEqual(vp) {
				vp = &l.end
			} else {
				str := fmt.Sprintf("Unconnected %d-th borders %s,%s,%s in polygon %s", i, t[i-1].begin.Hash().String(), t[i-1].end.Hash().String(), t[i].begin.Hash().String(), p.Hash().String())
				return nil, ruleError(1, str)
			}
		}
		q.loops = append(q.loops, t)
	}
	return q, nil
}
 */

/*
func loopccw(cl []*edge) bool {
	sum := 0.0
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
	return sum > 0
}
 */

func commonEdge(p, q *token.LoopDef, views *viewpoint.ViewPointSet) bool {
	ploops := make([]token.LoopDef, 0)
	qloops := make([]token.LoopDef, 0)
	if len(*p) == 1 {
		plg, _ := views.FetchPolygonEntry(&(*p)[0])
		ploops = plg.Loops
	} else {
		ploops = append(ploops, *p)
	}
	if len(*q) == 1 {
		plg, _ := views.FetchPolygonEntry(&(*q)[0])
		qloops = plg.Loops
	} else {
		qloops = append(qloops, *q)
	}
	pboxes := make([]viewpoint.BoundingBox, len(ploops))
	qboxes := make([]viewpoint.BoundingBox, len(qloops))
	if len(ploops) > 1 || len(qloops) > 1 {
		for i,pb := range ploops {
			pboxes[i] = views.LoopBound(&pb)
		}
		for i,pb := range qloops {
			qboxes[i] = views.LoopBound(&pb)
		}
		for i, lp := range ploops {
			for j, lq := range qloops {
				if !pboxes[i].Intersects(&qboxes[j], false) {
					continue
				}
				if commonEdge(&lp, &lq, views) {
					return true
				}
			}
		}
		return false
	}

	return views.CommonEdge(p, q)
}

func sanePolygon(p *token.PolygonDef, views *viewpoint.ViewPointSet,
	ccwloops, cwloops Cs2Loop, inloops, unxloops MatchLoop) error {
	for _,q := range p.Loops {
		if len(q) == 1 {
			d, _ := views.FetchPolygonEntry(&q[0])
			if d.Depth >= 100 {
				return fmt.Errorf("Polygon definition is too deep")
			}
		}
	}

	// 1. check everything has been defined and loop is indeed a loop and
	// all loops except for the first are CW
	firstCW := false
	css := make([]string, len(p.Loops))
	boxes := make([]*viewpoint.BoundingBox, len(p.Loops))
	var ccw bool

	for i, lp := range p.Loops {
		css[i] = lp.CheckSum()
		if cwloops.Match(css[i], &lp) || (i == 0 && ccwloops.Match(css[i], &lp)) {
			continue
		}

		if len(lp) == 1 {
			plg, _ := views.FetchPolygonEntry(&lp[0])
			if plg == nil {
				str := fmt.Sprintf("Polygon %s contains invalid", p.Hash().String())
				return ruleError(1, str)
			}
			boxes[i] = &plg.Bound
			if i == 0 {
				firstCW = plg.FirstCW
			} else if !plg.FirstCW {
				str := fmt.Sprintf("Polygon %s contains invalid", p.Hash().String())
				return ruleError(1, str)
			}
		} else if !views.IsLoop(&lp) {
			str := fmt.Sprintf("Polygon %s contains invalid loop", p.Hash().String())
			return ruleError(1, str)
		} else if i != 0 {
			ccw, boxes[i] = views.LoopCCW(&lp)
			if ccw {
				str := fmt.Sprintf("Polygon %s contains invalid loop", p.Hash().String())
				return ruleError(1, str)
			}
		} else {
			firstCW, boxes[i] = views.LoopCCW(&lp)
			firstCW = !firstCW
		}
	}

	for i, lp := range p.Loops {
		exa := cwloops.Match(css[i], &lp) || (i == 0 && ccwloops.Match(css[i], &lp))
		for j := 0; j < i; j++ {
			lq := p.Loops[j]
			exb := cwloops.Match(css[j], &lq) || (j == 0 && ccwloops.Match(css[j], &lq))
			if exa && exb {
				continue
			}
			if !boxes[i].Intersects(boxes[j], false) {
				continue
			}
			if commonEdge(&lp, &lq, views) {
				str := fmt.Sprintf("Polygon %s contains invalid loop", p.Hash().String())
				return ruleError(1, str)
			}
		}
	}

	// 2. if first loop is ccw, check all other loops are completely inside it
	if !firstCW {
		for i := 1; i < len(p.Loops); i++ {
			if inloops.Match(css[0], css[i], &p.Loops[0], &p.Loops[i]) {
				continue
			}
			if !boxes[0].Contain(boxes[i]) {
				str := fmt.Sprintf("Polygon %s contains invalid loop", p.Hash().String())
				return ruleError(1, str)
			}
			if tb := views.Intersects(&p.Loops[0], &p.Loops[i], boxes[0], boxes[i], false); tb {
				str := fmt.Sprintf("Polygon %s contains self intersecting loop", p.Hash().String())
				return ruleError(1, str)
			}
			if !views.InOutCheck(&p.Loops[0], &p.Loops[i], boxes[i]) {
				str := fmt.Sprintf("Polygon %s contains invalid loop", p.Hash().String())
				return ruleError(1, str)
			}
		}
	}

	// 3. check that there is no intersection between edges in a loop
	for i, lp := range p.Loops {
		if len(lp) == 1 {
			continue
		}
		if cwloops.Match(css[i], &lp) || (i == 0 && ccwloops.Match(css[i], &lp)) {
			// known valid loop
			continue
		}
		if tb := views.Intersects(&p.Loops[i], &p.Loops[i], boxes[i], boxes[i], true); tb {
			str := fmt.Sprintf("Polygon %s contains self intersecting loop", p.Hash().String())
			return ruleError(1, str)
		}
	}

	// 4. check that there is no intersection between loops
	start := 1
	if firstCW {
		start = 0
	}
	for i := start; i < len(p.Loops); i++ {
		lp := &p.Loops[i]
		um := cwloops.Match(css[i], lp) || (i == 0 && ccwloops.Match(css[i], lp))
		for j := start; j < i; j++ {
			lq := &p.Loops[j]
			if unxloops.Match(css[i], css[j], lp, lq) {
				continue
			}
			if !boxes[i].Intersects(boxes[j], false) {
				continue
			}
			// pick the newly defined (if has one) as the main loop
			var major, minor * token.LoopDef
			var b1, b2 int
			if um {
				major, minor, b1, b2 = lp, lq, i, j
			} else {
				major, minor, b1, b2 = lq, lp, j, i
			}
			if tb := views.Intersects(major, minor, boxes[b1], boxes[b2], false); tb {
				str := fmt.Sprintf("Polygon %s contains intersecting loop", p.Hash().String())
				return ruleError(1, str)
			}

			if boxes[b1].Contain(boxes[b2]) && views.InOutCheck(major, minor, boxes[b2]) {
				str := fmt.Sprintf("Polygon %s contains invalid loop", p.Hash().String())
				return ruleError(1, str)
			}
		}
	}

	return nil
}
/*
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
 */

type quadtree struct {
	index uint64
	substrees map[uint64]*quadtree
	inedges map[chainhash.Hash]*viewpoint.BorderEntry
	outedges map[chainhash.Hash]*viewpoint.BorderEntry
}

func (t * quadtree) reset(x uint64) {
	t.index = x
	t.substrees = make(map[uint64]*quadtree)
	t.inedges = make(map[chainhash.Hash]*viewpoint.BorderEntry)
	t.outedges = make(map[chainhash.Hash]*viewpoint.BorderEntry)
}

func (t * quadtree) add(h chainhash.Hash, e *viewpoint.BorderEntry, x uint64, in bool) {
	if in {
		if _,ok := t.outedges[h]; ok {
			delete(t.outedges, h)
			return
		}
	} else {
		if _,ok := t.inedges[h]; ok {
			delete(t.inedges, h)
			return
		}
	}
	if t.index == x {
		if in {
			t.inedges[h] = e
		} else {
			t.outedges[h] = e
		}
		return
	}
	hi, n := uint64(1), 1
	for hi & t.index == 0 {
		hi, n = hi << 1, n + 1
	}
	mx := (t.index & 0xFFFFFFFF) >> n
	my := t.index >> (n + 32)
	if (x & 0xFFFFFFFF) > mx {
		mx += hi
	} else {
		mx -= hi
	}
	if (x >> 32) > my {
		my += hi
	} else {
		my -= hi
	}
	hi >>= 1
	ni := mx | hi | ((my | hi) << 32)
	if _,ok := t.substrees[ni]; !ok {
		t := &quadtree{}
		t.reset(ni)
		t.substrees[ni] = t
	}
	t.substrees[ni].add(h, e, x, in)
}

func (t * quadtree) expand(view *viewpoint.ViewPointSet) bool {
	check := true
	for check {
		check = false
		for h, e := range t.inedges {
			if len(e.Children) > 0 {
				c := viewpoint.ReorderChildren(e.Children, h[0]&1 == 1)
				delete(t.inedges, h)
				for _, p := range c {
					if _, ok := t.outedges[p]; ok {
						delete(t.outedges, p)
					} else {
						be, _ := view.FetchBorderEntry(&p)
						t.add(p, be, be.Boxindex(), true)
						check = true
					}
				}
			}
		}
	}

	check = true
	for check {
		check = false
		for h, e := range t.outedges {
			if len(e.Children) > 0 {
				c := viewpoint.ReorderChildren(e.Children, h[0]&1 == 1)
				delete(t.outedges, h)
				for _, p := range c {
					if _, ok := t.inedges[p]; ok {
						delete(t.inedges, p)
					} else {
						be, _ := view.FetchBorderEntry(&p)
						t.add(p, be, be.Boxindex(), false)
						check = true
					}
				}
			}
		}
	}

	if len(t.inedges) > 0 || len(t.outedges) > 0 {
		return false
	}

	for _, s := range t.substrees {
		if !s.expand(view) {
			return false
		}
	}

	return true
}

func CheckGeometryIntegrity(tx *btcutil.Tx, views *viewpoint.ViewPointSet) bool {
	rset := parseRights(tx, views, false, 0)	// monitored

	// basic right set
	basicRS := getBasicRightSet(*rset, views)

	// Group geometries by their rights. map[right][in/out]polygon
	groups := make(map[tokenElement][2]map[chainhash.Hash]struct{})
	tokens := ioTokens(tx, views)

	for io, tks := range tokens {
		for _, emt := range tks {
			if emt.tokenType != 3 {
				// ioTokens will include all types, here we are only interested in polygons
				continue
			}
			y := TokenRights(views, &emt)

			for s, _ := range basicRS {
				emt.right = s
				e, _ := views.FetchRightEntry(&s)
				v := e.(*viewpoint.RightEntry)
				isdecedent := false
decendent:
				for _, r := range y {
					if s.IsEqual(&r) {
						isdecedent = true
						break decendent
					}
					e, _ := views.FetchRightEntry(&r)
					u := e.(*viewpoint.RightEntry)

					if decentOf(v, &s, u, &r, views) {
						isdecedent = true
						break decendent
					}
				}

				if !isdecedent {
					continue
				}

				if _, ok := groups[emt.tokenElement]; !ok {
					groups[emt.tokenElement] = [2]map[chainhash.Hash]struct{}{
						make(map[chainhash.Hash]struct{}),
						make(map[chainhash.Hash]struct{})}
				}
				if _, ok := groups[emt.tokenElement][io][emt.value.(*token.HashToken).Hash]; !ok {
					groups[emt.tokenElement][io][emt.value.(*token.HashToken).Hash] = struct{}{}
				} else {
					return false // duplicated combination
				}
			}
		}
	}

	// for each group, check geometry integrity: since wu know all polygons are sane,
	// we only need to check after cancellation, in & out have the same set of borders
	for i, g := range groups {
		// polygon quick cancellation: if one polygon/right combination appears in both
		// sides, cancel them out
		for in,_ := range g[0] {
			if _,ok := g[1][in]; ok {
				delete(groups[i][0], in)
				delete(groups[i][1], in)
			}
		}

		g = groups[i]

		// quick checked all matches, skip this one
		if len(g[0]) == 0 && len(g[1]) == 0 {
			continue
		}

		// if only one side is empty, there is a mismatch, failed
		if len(g[0]) == 0 || len(g[1]) == 0 {
			return false
		}

		// map is always passed as reference in func calls
		ingeo := make(map[chainhash.Hash]struct{})
		outgeo := make(map[chainhash.Hash]struct{})

		Borders(g[0], views, ingeo)
		Borders(g[1], views, outgeo)

		for b, _ := range ingeo {
			if _, ok := outgeo[b]; ok {
				delete(outgeo, b)
				delete(ingeo, b)
			}
		}

		var root quadtree
		root.reset(0x8000000080000000)
		for b, _ := range ingeo {
			e,_ := views.FetchBorderEntry(&b)
			root.add(b, e, e.Boxindex(), true)
		}
		for b, _ := range outgeo {
			e,_ := views.FetchBorderEntry(&b)
			root.add(b, e, e.Boxindex(), false)
		}
		if !root.expand(views) {
			return false
		}
/*
		bentry := make(map[chainhash.Hash]*viewpoint.BorderEntry)
		for check := true; check; {
			if len(ingeo) == 0 && len(outgeo) == 0 {
				return true
			}

			check = false

			for b, _ := range ingeo {
				s := b
				s[0] &^= 1
				if _,ok := bentry[b]; !ok {
					e,_ := views.FetchBorderEntry(&s)
					bentry[s] = e
				}
				for d, _ := range outgeo {
					t := d
					t[0] &^= 1
					if _,ok := bentry[d]; !ok {
						e,_ := views.FetchBorderEntry(&t)
						bentry[t] = e
					}
					if bentry[s].Enclose(bentry[t]) && len(bentry[s].Children) > 0 {
						check = true
						BorderDeeper(&ingeo, b, &bentry, views)
					} else if bentry[t].Enclose(bentry[s]) && len(bentry[t].Children) > 0 {
						check = true
						BorderDeeper(&outgeo, d, &bentry, views)
					} else if bentry[s].Joint(bentry[t]) {
						if len(bentry[s].Children) > 0 {
							check = true
							BorderDeeper(&ingeo, b, &bentry, views)
						}
						if len(bentry[t].Children) > 0 {
							check = true
							BorderDeeper(&outgeo, d, &bentry, views)
						}
					}
				}
			}
		}

		if len(ingeo) != 0 || len(outgeo) != 0 {
			return false
		}
 */

 /*
				// now we have merge and compare
				wpolygon := make(map[chainhash.Hash][][]*edge, 0)
				// merge geometries
				ingeo := GeoMerge(g[0], views, &wpolygon)
				outgeo := GeoMerge(g[1], views, &wpolygon)

				// check if they are the same
				for in,s := range ingeo {
					for out,t := range outgeo {
						if geoSame(&s, &t, views) {
							ingeo = append(ingeo[:in], ingeo[in+1:]...)
							outgeo = append(outgeo[:out], outgeo[out+1:]...)
						}
					}
				}

				if len(ingeo) != 0 || len(outgeo) != 0 {
					return false
				}
		 */
	}

	return true
}

/*
func BorderDeeper(geo *map[chainhash.Hash]struct{}, b chainhash.Hash, bentry * map[chainhash.Hash]*viewpoint.BorderEntry, views *viewpoint.ViewPointSet) {
	s := b
	s[0] &^= 1
	delete(*bentry, s)
	delete(*geo, b)
	var rev byte
	if !s.IsEqual(&b) {
		rev = 1
	}
	for _,h := range (*bentry)[s].Children {
		h[0] |= rev
		r := h
		r[0] &^= 1
		if _,ok := (*geo)[r]; ok {
			delete(*geo, r)
			continue
		}
		(*geo)[h] = struct{}{}
	}
}
 */

func Borders(old map[chainhash.Hash]struct{}, views *viewpoint.ViewPointSet, borders map[chainhash.Hash]struct{}) {
	for p,_ := range old {
		q, _ := views.FetchPolygonEntry(&p)
		for _,l := range q.Loops {
			if len(l) == 1 {
				Borders(map[chainhash.Hash]struct{}{l[0]: {}}, views, borders)
			} else {
				for _, r := range l {
					t := r
					t[0] ^= 1
					if _, ok := borders[t]; ok {
						delete(borders, t)
					} else {
						borders[r] = struct{}{}
					}
				}
			}
		}
	}
}

/*
func GeoMerge(old map[chainhash.Hash]struct{}, views *viewpoint.ViewPointSet, realgeo * map[chainhash.Hash][][]*edge) [][][]*edge {
	polygons := make([][][]*edge, 0, len(old))

	for p,_ := range old {
		if q,ok := (*realgeo)[p]; ok {
			polygons = append(polygons, q)
		} else {
			q, _ := views.Polygon.FetchEntry(views.Db, &p)
			polygons = append(polygons, *(expand(q.ToToken(), views)))
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
		if len(loop) == 1 {
			// this is a polygon
			plg, _ := views.Polygon.FetchEntry(views.Db, &loop[0])
			xp := expand(plg.ToToken(), views)
			p = append(p, (*xp)...)
		} else {
			p[i] = make([]*edge, 0, len(loop))
			for _, l := range loop {
				rev := l[0] & 0x1
				l[0] &= 0xFE
				exp := expandBorder(l, views, rev)
				p[i] = append(p[i], exp[:]...)
			}
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
 */
