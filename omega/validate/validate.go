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
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/omega"
	"github.com/btcsuite/omega/viewpoint"
	"github.com/btcsuite/btcutil"
	"sort"
	"github.com/btcsuite/omega/token"
)

func saneVertex(v * token.VertexDef) bool {
	// it is a valid earth geo coord?
	x := float64(int32(v.Lng())) / token.CoordPrecision
	y := float64(int32(v.Lat())) / token.CoordPrecision
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
		f,_ := views.Border.FetchEntry(views.Db, &r.Father)
		if f == nil {
			return 2
		}
		r = token.NewBorderDef(f.Begin, f.End, f.Father)
	}

	return 2
}

const GeoError = float64(0.0001)	// allowed error relative to length of edge

func online(r * token.VertexDef, begin * token.VertexDef, end * token.VertexDef, delim * token.VertexDef) bool {
	// determine whether point r is on the line segment of (begin, end) relatively within GeoError
	rf := [2]float64{float64(int64(r.Lng())), float64(int64(r.Lat()))}
	bf := [2]float64{float64(int64(begin.Lng())), float64(int64(begin.Lat()))}
	ef := [2]float64{float64(int64(end.Lng())), float64(int64(end.Lat()))}

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
		// further restrict it to not beyond the range defined by delim
		df := [2]float64{float64(int64(delim.Lng())), float64(int64(delim.Lat()))}
		if (df[0] - bf[0]) * (ef[0] - bf[0]) + (df[1] - bf[1]) * (ef[1] - bf[1]) >= t {
			return false
		}
	}
	return true
}

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
	return np
}

type polygon struct {
	loops [][]*edge
}

func expandBorder(hash chainhash.Hash, views *viewpoint.ViewPointSet, rev byte) []*edge {
	var h chainhash.Hash

	h.SetBytes(hash.CloneBytes())
	h[0] &= 0xFE
	lp, _ := views.Border.FetchEntry(views.Db, &h)
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
	lp, _ := views.Border.FetchEntry(views.Db, &hash)

	if lp.Children != nil && len(lp.Children) > 0 {
		t := make([]*edge, len(lp.Children))
		for i, c := range lp.Children {
			n := i
			if rev == 1 {
				n = len(lp.Children) - 1 - i
			}
			p, _ := views.Border.FetchEntry(views.Db, &c)
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

func fetchPolygon(p *token.PolygonDef, views *viewpoint.ViewPointSet) (*polygon, error) {
	q := &polygon{
		loops:make([][]*edge, 0),
	}
	var err error
	for i,loop := range p.Loops {
		t := make([]*edge, 0, len(loop))
		if len(loop) == 1 {
			if i != 0 {
				return nil, ruleError(3, "Illegal loop len = 1, but not the first one.")
			}
			plg, _ := views.Polygon.FetchEntry(views.Db, &loop[0])
			if plg == nil {
				return nil, ruleError(3, "Polygon expected")
			}
			q, err = fetchPolygon(plg.ToToken(), views)
			if err != nil {
				return nil, err
			}
		}
		for _, l := range loop {
			lp, _ := views.Border.FetchEntry(views.Db, &l)
			if lp == nil {
				return nil, ruleError(2, "Undefined border")
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

func sanePolygon(p *token.PolygonDef, views *viewpoint.ViewPointSet) error {
	// 1. check everything has been defined and loop is indeed a loop
	q, err := fetchPolygon(p, views)
	if err != nil {
		return err
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
					lp,_ := views.Border.FetchEntry(views.Db, &v.hash)
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
					lp,_ := views.Border.FetchEntry(views.Db, &l.hash)
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
				e, _ := views.Rights.FetchEntry(views.Db, &s)
				v := e.(*viewpoint.RightEntry)
				isdecedent := false
decendent:
				for _, r := range y {
					if s.IsEqual(&r) {
						isdecedent = true
						break decendent
					}
					e, _ := views.Rights.FetchEntry(views.Db, &r)
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

	// for each group, check geometry integrity
	for i, g := range groups {
		// quick cancellation: if one polygon/right combination appears in both sides, cancel them out
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

		ingeo := Borders(g[0], views)
		outgeo := Borders(g[1], views)

		bentry := make(map[chainhash.Hash]*viewpoint.BorderEntry)
		for check := true; check; {
			for b, _ := range ingeo {
				if _, ok := outgeo[b]; ok {
					delete(outgeo, b)
					delete(ingeo, b)
				}
			}
			if len(ingeo) == 0 && len(outgeo) == 0 {
				return true
			}

			check = false

			for b, _ := range ingeo {
				s := b
				s[0] &^= 1
				if _,ok := bentry[b]; !ok {
					e,_ := views.Border.FetchEntry(views.Db, &s)
					bentry[s] = e
				}
				for d, _ := range outgeo {
					t := d
					t[0] &^= 1
					if _,ok := bentry[d]; !ok {
						e,_ := views.Border.FetchEntry(views.Db, &t)
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

func BorderDeeper(geo *map[chainhash.Hash]struct{}, b chainhash.Hash, bentry * map[chainhash.Hash]*viewpoint.BorderEntry, views *viewpoint.ViewPointSet) {
	s := b
	s[0] &^= 1
	delete(*bentry, s)
	delete(*geo, b)
	for _,h := range (*bentry)[s].Children {
		if !s.IsEqual(&b) {
			h[0] |= 1
		}
		r := h
		r[0] &^= 1
		if _,ok := (*geo)[r]; ok {
			delete(*geo, r)
			continue
		}
		(*geo)[h] = struct{}{}
	}
}

func Borders(old map[chainhash.Hash]struct{}, views *viewpoint.ViewPointSet) map[chainhash.Hash]struct{} {
	borders := make(map[chainhash.Hash]struct{})
	for p,_ := range old {
		q, _ := views.Polygon.FetchEntry(views.Db, &p)
		for len(q.Loops[0]) == 1 {
			q, _ = views.Polygon.FetchEntry(views.Db, &q.Loops[0][0])
		}

		for _, l := range q.Loops {
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
	return borders
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
