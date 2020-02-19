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
	"github.com/btcsuite/omega/viewpoint"
)

type qitem struct {
	e *edge		// pointer to edge
	index int	// loop it belongs to
}

type quadtree struct {		// a quad tree for sorting edges by their bounding boxes
	x uint32		// left top corner of this quad
	y uint32
	width byte		// width of cord. in the form of 2 ^ n
	edges map[int][]qitem
	subquads	*[4]quadtree	// subtree
}

func NewQuadtree() (*quadtree) {
	return &quadtree {
		x: 0,
		y: 0,
		width: 32,
		edges: make(map[int][]qitem, 0),
		subquads: nil,
	}
}

func (q *quadtree) joint(e * edge) bool {
	if q.coord(e.east) <= q.x || q.coord(e.north) <= q.y {
		return false
	}

	w := uint64(1) << q.width

	if uint64(q.coord(e.west)) <= (w + uint64(q.x)) || uint64(q.coord(e.south)) <= (w + uint64(q.y)) {
		return false
	}

	return true
}

func (q *quadtree) coord(x int32) uint32 {		// coordinate conversion
	return uint32(x + 0x7FFFFFFF)
}

func (q *quadtree) addEdge(p int, i int, e *edge) {
	if _, ok := q.edges[p]; !ok {
		q.edges[p] = make([]qitem, 0, 3)
	}
	q.edges[p] = append(q.edges[p],qitem{e, i})
}

func (q *quadtree) dropTest(e * edge) (byte, bool) {
	n := 0
	u := byte(0)
	for i, s := range q.subquads {
		if s.joint(e) {
			u = byte(i)
			n++
		}
	}
	return u, (n == 1)
}

func (q *quadtree) insert(views *viewpoint.ViewPointSet, p int, i int, el []*edge) {
	// add and split (when necessary) such that either all edges in the quad belongs to one polygon
	// or all edges in the quad are bottom edges

	if q.subquads != nil {
		for ; len(el) > 0; {
			te := make([]*edge, 0, len(el))
			for _, ee := range el {
				u, solo := q.dropTest(ee)
				if solo {
					q.subquads[u].insert(views, p, i, []*edge{ee})
				} else {
					es := expandBorderOnce(ee.hash, views, ee.rev)
					if es == nil {
						q.addEdge(p, i, ee)
					} else {
						te = append(te, es[:]...)
					}
				}
			}
			el = te
		}
		return
	}

	if _, ok := q.edges[p]; len(q.edges) == 0 || (len(q.edges) == 1 && ok) {
		for _, e := range el {
			q.addEdge(p, i, e)
		}
		return
	}

	ee := q.edges
	q.edges = make(map[int][]qitem, 0)

	q.subquads = &[4]quadtree{}
	(*q.subquads)[0] = quadtree{
		x: q.x, y: q.y, width:q.width - 1,
		edges: make(map[int][]qitem, 0),
		subquads: nil,
	}
	(*q.subquads)[1] = quadtree{
		x: q.x + (1 << (q.width - 1)), y: q.y, width:q.width - 1,
		edges: make(map[int][]qitem, 0),
		subquads: nil,
	}
	(*q.subquads)[2] = quadtree{
		x: q.x, y: q.y + (1 << (q.width - 1)), width:q.width - 1,
		edges: make(map[int][]qitem, 0),
		subquads: nil,
	}
	(*q.subquads)[3] = quadtree{
		x: q.x + (1 << (q.width - 1)), y: q.y + (1 << (q.width - 1)), width:q.width - 1,
		edges: make(map[int][]qitem, 0),
		subquads: nil,
	}

	for pp, elst := range ee {
		for _, e := range elst {
			q.insert(views, pp, e.index, []*edge{e.e})
		}
	}
	q.insert(views, p, i, el)
}

func (q *quadtree) remove(views *viewpoint.ViewPointSet, e *edge) bool {
	// add and split (when necessary) such that either all edges in the quad belongs to one polygon
	// or all edges in the quad are bottom edges

	for i, p := range q.edges {
		for j, s := range p {
			if e.hash.IsEqual(&s.e.hash) {
				q.edges[i] = append(p[:j], p[j+1:]...)
				return true
			}
		}
	}

	if q.subquads != nil {
		for el := []*edge{e}; len(el) > 0; {
			te := make([]*edge, 0, len(el))
			for _, ee := range el {
				u, solo := q.dropTest(ee)
				if solo {
					if q.subquads[u].remove(views, ee) {
						return true
					}
				} else {
					es := expandBorderOnce(ee.hash, views, ee.rev)
					if es == nil {
						for i, p := range q.edges {
							for j, s := range p {
								if e.hash.IsEqual(&s.e.hash) {
									q.edges[i] = append(p[:j], p[j+1:]...)
									return true
								}
							}
						}
						return false
					} else {
						te = append(te, es[:]...)
					}
				}
			}
			el = te
		}
		return false
	}

	ee := q.edges
	q.edges = make(map[int][]qitem, 0)

	q.subquads = &[4]quadtree{}
	(*q.subquads)[0] = quadtree{
		x: q.x, y: q.y, width:q.width - 1,
		edges: make(map[int][]qitem, 0),
		subquads: nil,
	}
	(*q.subquads)[1] = quadtree{
		x: q.x + (1 << (q.width - 1)), y: q.y, width:q.width - 1,
		edges: make(map[int][]qitem, 0),
		subquads: nil,
	}
	(*q.subquads)[2] = quadtree{
		x: q.x, y: q.y + (1 << (q.width - 1)), width:q.width - 1,
		edges: make(map[int][]qitem, 0),
		subquads: nil,
	}
	(*q.subquads)[3] = quadtree{
		x: q.x + (1 << (q.width - 1)), y: q.y + (1 << (q.width - 1)), width:q.width - 1,
		edges: make(map[int][]qitem, 0),
		subquads: nil,
	}

	for _, elst := range ee {
		for _, el := range elst {
			q.insert(views, 0, 0, []*edge{el.e})
		}
	}
	return q.remove(views, e)
}

type trvcb func(p int, i int, e * edge) bool

func (q *quadtree) travse(fn trvcb) bool {
	if len(q.edges) > 0 {
		for p,ee := range q.edges {
			for _, e := range ee {
				if !fn(p, e.index, e.e) {
					return false
				}
			}
		}
	}
	if q.subquads != nil {
		for _, sq := range q.subquads {
			if !sq.travse(fn) {
				return false
			}
		}
	}
	return true
}


func (q *quadtree) empty() bool {
	return q.travse(func(p int, i int, e * edge) bool {
		return false
	})
}
