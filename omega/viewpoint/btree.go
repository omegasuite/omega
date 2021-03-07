/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package viewpoint

import (
	"math/big"
	"github.com/omegasuite/btcutil/math"
	"os"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"encoding/binary"
)

// Functions in this file are not thread safe!!!

type btreenode struct {
	Val [2][20]byte		// numbers are big-endian, so it is consistent with big.Int
						// [0] - big.Int val of min in sub tree
						// [1] - big.Int val of max in sub tree
	Height int16
	Left int32
	Right int32
	Paid uint64			// fee paid
	D   [21]byte		// for non-leaf node, Val[1] of left + Val[0] of right. Not div by 2!
}

func sum(a, b []byte) []byte {
	var c [21]byte
	var x, y big.Int

	x.SetBytes(a)
	y.SetBytes(b)

	x = * (x.Add(&x, &y))

	xb := x.Bytes()
	for i:=0; i < 21-len(xb); i++ {
		c[i] = 0
	}
	copy(c[21-len(xb):], xb)
	return c[:]
}

type MinersViewpoint struct {
	bestHash chainhash.Hash
	datafile string
	added map[[20]byte]uint64
	removed map[[20]byte]struct{}
}

func NewMinersViewpoint() * MinersViewpoint {
	return &MinersViewpoint{}
}

func (m * MinersViewpoint) Find(entry []byte) uint64 {
	b := math.MustParseBig256(string(entry))
	b = b.Mul(b, big.NewInt(2))		// we use 2X value in searching!
	if file == nil {
		file, _ = os.Open(m.datafile) // self.Cfg.DataDir + "/miners.dat")
	}
	t := bTreeSearch(b, nil, file)

	if t == nil {
		return 0
	}
	return t.Paid
}

func (m * MinersViewpoint) Remove(s []byte) uint64 {
	if m.added == nil {
		m.added = make(map[[20]byte]uint64)
		m.removed = make(map[[20]byte]struct{})
	}

	var addr [20]byte
	copy(addr[:], s)

	if f,ok := m.added[addr]; ok {
		delete(m.added, addr)
		return f
	} else if _,ok := m.removed[addr]; ok{
		return 0
	} else {
		f := m.Find(s)
		if f != 0 {
			m.removed[addr] = struct{}{}
			return f
		}
		return 0
	}
}

func (m * MinersViewpoint) Insert(s []byte, amount uint64) bool {
	if m.added == nil {
		m.added = make(map[[20]byte]uint64)
		m.removed = make(map[[20]byte]struct{})
	}

	var addr [20]byte
	copy(addr[:], s)

	if _,ok := m.added[addr]; ok {
		return false
	}

	f := m.Find(s)
	if f != 0 {
		if _,ok := m.removed[addr]; !ok {
			return false
		}
	}

	m.added[addr] = amount
	return true
}

var garbbage = uint64(0)
var file = (*os.File)(nil)

func (m * MinersViewpoint) SetMinerDB(s string) {
	m.datafile = s			// self.Cfg.DataDir + "/miners.dat"
}

/*
func (m * MinersViewpoint) disconnectTransactions(block *btcutil.Block) {
	var zero, addr [20]byte
	for _,tx := range block.Height() {
		quits := make(map[[20]byte]int)
		for j, out := range tx.MsgTx().TxOut {
			if out.TokenType == 0xFFFFFFFFFFFFFFFF {
				break
			}
			if !isContract(out.PkScript[0]) {
				continue
			}
			if bytes.Compare(out.PkScript[1:21], zero[:]) != 0 {
				continue
			}
			switch out.PkScript[21] {
			case 0x20:	// ovm.OP_MINER_APPLY:
				m.Remove(out.PkScript[25:45])
			case 0x21:	//ovm.OP_MINRE_QUIT:
			copy(addr[:], out.PkScript[25:45])
				quits[addr] = j
			}
		}
		for i := len(tx.MsgTx().TxOut) - 1; i > 0 && len(quits) > 0; i-- {
			out := tx.MsgTx().TxOut[i]
			if out.TokenType == 0xFFFFFFFFFFFFFFFF {
				break
			}
			if out.PkScript[0] != chaincfg.ActiveNetParams.PubKeyHashAddrID {
				continue
			}
			if bytes.Compare(out.PkScript[21 : 25], []byte{0x41, 0, 0, 0}) != 0 {	// ovm.OP_PAY2PKH
				continue
			}
			// TBD: more secure approach
			for addr, j := range quits {
				if i > j && bytes.Compare(out.PkScript[1:21], addr[:]) == 0 {
					m.Insert(addr[:], uint64(out.Token.Value.(*token.NumToken).Val))
					delete(quits, addr)
					break
				}
			}
		}
	}
}
*/

func (m * MinersViewpoint) commit() {
	m.added = make(map[[20]byte]uint64)
	m.removed = make(map[[20]byte]struct{})
}

func DbPutMinersView(m * MinersViewpoint) error {
	if file == nil {
		file, _ = os.Open(m.datafile) // self.Cfg.DataDir + "/miners.dat")
	}

	for entry,_ := range m.added {
		b := math.MustParseBig256(string(entry[:]))
		b = b.Mul(b, big.NewInt(2))    // we use 2X value in searching!
		bTreeRemove(b, nil, file, 8)
	}

	for entry, amount := range m.added {
		b := math.MustParseBig256(string(entry[:]))
		b = b.Mul(b, big.NewInt(2))    // we use 2X value in searching!
		bTreeInsert(b, &entry, nil, file, amount, 8)
	}

	file.Close()
	file = nil

	m.added = make(map[[20]byte]uint64)
	m.removed = make(map[[20]byte]struct{})

	return nil
}

func bTreeRemove(h2 *big.Int, root *btreenode, file * os.File, pos int64) bool {
	var node btreenode
	data := make([]byte, 80)
	if root == nil {
		var gab [8]byte
		n, err := file.ReadAt(gab[:], 0)
		if n < 8 || err != nil {
			return false
		}
		garbbage = binary.LittleEndian.Uint64(gab[:])

		n, err = file.ReadAt(data, 8)
		if n < 80 || err != nil {
			return false
		}
		node.Load(data)
		root = &node
		return bTreeRemove(h2, root, file, 8)
	}

	if root.Left == 0 {		// so is Right
		file.Truncate(0)		// this only happens when we have one node and we delete it. so truncate the file.
		return false
	}

	var b big.Int
	isleft := 0
	d := root.Left

	b.SetBytes(root.D[:])
	if h2.Cmp(&b) >= 0 {
		d = root.Right
		isleft = 1
	}
	file.ReadAt(data, int64(d))
	node.Load(data)

	oppo := make([]byte, 80)
	var opponode btreenode

	if node.Left != 0 {		// node is not a leaf
		if !bTreeRemove(h2, &node, file, int64(d)) {
			// remove not happened
			return false
		}
		// remove happened in child branch, adjust range
		if isleft == 0 {
			file.ReadAt(oppo, int64(root.Right))
		} else {
			file.ReadAt(oppo, int64(root.Left))
		}
		opponode.Load(oppo)
		copy(root.D[:], sum(node.Val[1-isleft][:], opponode.Val[isleft][:]))
		copy(root.Val[isleft][:], node.Val[isleft][:])
		file.WriteAt(root.Store(), pos)
		return true
	}

	b.SetBytes(node.D[:])
	if h2.Cmp(&b) != 0 {		// no match at leaf
		return false
	}

	// remove leaf by copying sibling to parent
	if isleft == 0 {
		file.ReadAt(oppo, int64(root.Right))
	} else {
		file.ReadAt(oppo, int64(root.Left))
	}
	root.Load(oppo)
	file.WriteAt(root.Store(), pos)

	var gab [8]byte
	binary.LittleEndian.PutUint64(gab[:], garbbage)
	file.WriteAt(gab[:], int64(root.Left))
	binary.LittleEndian.PutUint64(gab[:], uint64(root.Left))
	file.WriteAt(gab[:], int64(root.Right))
	garbbage = uint64(root.Right)
	binary.LittleEndian.PutUint64(gab[:], garbbage)
	file.WriteAt(gab[:], 0)

	return true
}

func (node *btreenode) Load(data []byte)  {
	copy(node.Val[0][:], data[0:20])
	copy(node.Val[1][:], data[20:40])
	node.Height = int16(data[40]) | (int16(data[41]) << 8)
	node.Left = int32(data[45]) | (int32(data[44]) << 8) | (int32(data[43]) << 16) | (int32(data[42]) << 24)
	node.Right = int32(data[49]) | (int32(data[48]) << 8) | (int32(data[47]) << 16) | (int32(data[46]) << 24)
	node.Paid = binary.LittleEndian.Uint64(data[50:])
	copy(node.D[:], data[58:])
}

func (node *btreenode) Store() []byte {
	data := make([]byte, 80)
	copy(data[0:20], node.Val[0][:])
	copy(data[20:40], node.Val[1][:])
	data[44] = byte(node.Height & 0xFF)
	data[40] = byte((node.Height >> 8) & 0xFF)
	data[45] = byte(node.Left & 0xFF)
	data[44] = byte((node.Left >> 8) & 0xFF)
	data[43] = byte((node.Left >> 16) & 0xFF)
	data[42] = byte((node.Left >> 24) & 0xFF)
	data[49] = byte(node.Right & 0xFF)
	data[48] = byte((node.Right >> 8) & 0xFF)
	data[47] = byte((node.Right >> 16) & 0xFF)
	data[46] = byte((node.Right >> 24) & 0xFF)
	binary.LittleEndian.PutUint64(data[50:], node.Paid)
	copy(data[58:], node.D[:])
	return data[:]
}

func (node *btreenode) Leaf(addr *[20]byte) {
	nip := byte(0)
	for i := 0; i < 20; i++ {
		node.D[i] = (((*addr)[i] << 1) | nip)
		nip = ((*addr)[i] >> 7) & 1
	}
	node.D[20] = nip
//	h := btcutil.Hash160((*addr)[:])
	copy(node.Val[0][:], (*addr)[:])	// h)
	copy(node.Val[1][:], (*addr)[:])	// h)
	node.Height = 0
	node.Left = 0
	node.Right = 0
}

func bTreeSearch(h2 *big.Int, root *btreenode, file * os.File) *btreenode {
	var node btreenode
	data := make([]byte, 80)
	if root == nil {
		file.Read(data)
		node.Load(data)
		root = &node
	}
	if root.Left == 0 {		// so is Right
		return root
	}
	var b big.Int
	b.SetBytes(root.D[:])
	d := root.Left
	if h2.Cmp(&b) >= 0 {
		d = root.Right
	}
	file.ReadAt(data, int64(d))
	node.Load(data)
	return bTreeSearch(h2, &node, file)
}

func bTreeInsert(h2 *big.Int, addr *[20]byte, root *btreenode, file * os.File, amount uint64, pos int64) *btreenode {
	// h = 2 * hash160(addr)
	var node, left, right btreenode
	data := make([]byte, 80)
	if root == nil {
		var gab [8]byte

		_,err := file.ReadAt(gab[:], 0)
		if err != nil {
			file.WriteAt(gab[:], 0)
			garbbage = 0
		} else {
			garbbage = binary.LittleEndian.Uint64(gab[:])
		}

		_,err = file.ReadAt(data, 8)
		if err == nil {
			root = new(btreenode)
			root.Load(data)
		} else {
			node.Leaf(addr)
			file.WriteAt(node.Store(), 8)
			return &node
		}
	}

	if root.Left == 0 {
		node.Leaf(addr)

		var x, y big.Int
		x.SetBytes(root.Val[0][:])
		y.SetBytes(node.Val[0][:])

		if y.Cmp(&x) >= 0 {
			left = * root
			right = node
		} else {
			left = node
			right = * root
		}

		var p1, p2 int64

		if garbbage == 0 {
			p1, _ = file.Seek(0, -1)
			p2 = p1 + 80
		} else {
			p1 = int64(garbbage)

			var gab [8]byte
			file.ReadAt(gab[:], p1)
			p2 = int64(binary.LittleEndian.Uint64(gab[:]))

			if p2 == 0 {
				p2, _ = file.Seek(0, -1)
				garbbage = 0
			} else {
				file.ReadAt(gab[:], p2)
				garbbage = binary.LittleEndian.Uint64(gab[:])
			}
			binary.LittleEndian.PutUint64(gab[:], garbbage)
			file.WriteAt(gab[:], 0)
		}
		file.WriteAt(left.Store(), p1)
		file.WriteAt(right.Store(), p2)
		node = *root
		node.Left = int32(p1)
		node.Right = int32(p2)
		copy(node.Val[0][:], left.Val[0][:])
		copy(node.Val[1][:], right.Val[1][:])
		copy(node.D[:], sum(root.Val[0][:], node.Val[0][:]))
		node.Height++
		file.WriteAt(node.Store(), pos)
		return &node
	}

	file.ReadAt(data, int64(root.Left))
	left.Load(data)
	file.ReadAt(data, int64(root.Right))
	right.Load(data)

	var b * btreenode
	node = *root

	var x big.Int
	x = *x.SetBytes(node.D[:])

	if h2.Cmp(&x) >= 0 {
		b = bTreeInsert(h2, addr, &right, file, amount, int64(node.Right))
		if right.Val[0] == b.Val[0] && right.Val[1] == b.Val[1] {
			return &node
		}
		node.Val[1] = b.Val[1]
		if right.Val[0] == b.Val[0] {
			file.WriteAt(node.Store(), pos)
			return &node
		}
		node.Val[0] = b.Val[0]
		copy(node.D[:], sum(left.Val[1][:], b.Val[0][:]))
	} else {
		b = bTreeInsert(h2, addr, &left, file, amount, int64(node.Left))
		if left.Val[0] == b.Val[0] && left.Val[1] == b.Val[1] {
			return &node
		}
		node.Val[0] = b.Val[0]
		if left.Val[1] == b.Val[1] {
			file.WriteAt(node.Store(), pos)
			return &node
		}
		node.Val[1] = b.Val[1]
		copy(node.D[:], sum(right.Val[0][:], b.Val[1][:]))
	}

	file.WriteAt(node.Store(), pos)
	return &node
}
