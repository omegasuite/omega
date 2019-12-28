package consensus

import (
	"math/big"
	"os"
	"github.com/btcsuite/btcutil"
)

type btreenode struct {
	Val [2][20]byte		// numbers are big-endian, so it is consistent with big.Int
						// [0] - big.Int val of min in sub tree
						// [1] - big.Int val of max in sub tree
	Height int16
	Left int32
	Right int32
	D   [21]byte			// for non-leaf node, Val[2] of left + Val[0] of right
}

func (node *btreenode) Load(data []byte)  {
	copy(node.Val[0][:], data[0:20])
	copy(node.Val[1][:], data[20:40])
	node.Height = int16(data[40]) | (int16(data[41]) << 8)
	node.Left = int32(data[45]) | (int32(data[44]) << 8) | (int32(data[43]) << 16) | (int32(data[42]) << 24)
	node.Right = int32(data[49]) | (int32(data[48]) << 8) | (int32(data[47]) << 16) | (int32(data[46]) << 24)
	copy(node.D[:], data[50:71])
}

func (node *btreenode) Store() []byte {
	data := make([]byte, 70)
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
	copy(data[50:71], node.D[:])
	return data[:]
}
func (node *btreenode) Leaf(addr *[20]byte) {
	copy(node.D[1:21], (*addr)[0:20])
	node.D[0] = 0
	h := btcutil.Hash160((*addr)[:])
	copy(node.Val[0][:], h)
	copy(node.Val[1][:], h)
	node.Height = 0
	node.Left = 0
	node.Right = 0
}

func bTreeSearch(h2 *big.Int, root *btreenode, file * os.File) []byte {
	var node btreenode
	data := make([]byte, 71)
	if root == nil {
		file.Read(data)
		node.Load(data)
		root = &node
	}
	if root.Left == 0 {		// so is Right
		return root.D[1:21]
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

func bTreeInsert(h2 *big.Int, addr *[20]byte, root *btreenode, file * os.File, pos int64) *btreenode {
	// h = 2 * hash160(addr)
	var node, left, right btreenode
	data := make([]byte, 71)
	if root == nil {
		_,err := file.ReadAt(data, 0)
		if err == nil {
			node.Load(data)
			root = &node
		} else {
			node.Leaf(addr)
			file.WriteAt(node.Store(), 0)
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
		eof,_ := file.Seek(0, -1)
		file.WriteAt(left.Store(), eof)
		file.WriteAt(right.Store(), eof + 71)
		node = *root
		node.Left = int32(eof)
		node.Right = int32(eof+71)
		copy(node.Val[0][:], left.Val[0][:])
		copy(node.Val[1][:], right.Val[1][:])
		x = *x.Add(&x, &y)
		node.Height++
		xb := x.Bytes()
		for i:=0; i < 21-len(xb); i++ {
			node.D[i] = 0
		}
		copy(node.D[21-len(xb):], xb)
		file.WriteAt(node.Store(), pos)
		return &node
	}
	file.ReadAt(data, int64(root.Left))
	left.Load(data)
	file.ReadAt(data, int64(root.Right))
	right.Load(data)

	var b * btreenode
	node = *root

	var x, y big.Int
	x = *x.SetBytes(node.D[:])
	if h2.Cmp(&x) >= 0 {
		b = bTreeInsert(h2, addr, &right, file, int64(node.Right))
		if right.Val[0] == b.Val[0] && right.Val[1] == b.Val[1] {
			return &node
		}
		node.Val[1] = b.Val[1]
		if right.Val[0] == b.Val[0] {
			file.WriteAt(node.Store(), pos)
			return &node
		}
		node.Val[0] = b.Val[0]
		x.SetBytes(left.Val[1][:])
		y.SetBytes(b.Val[0][:])
	} else {
		b = bTreeInsert(h2, addr, &left, file, int64(node.Left))
		if left.Val[0] == b.Val[0] && left.Val[1] == b.Val[1] {
			return &node
		}
		node.Val[0] = b.Val[0]
		if left.Val[1] == b.Val[1] {
			file.WriteAt(node.Store(), pos)
			return &node
		}
		node.Val[1] = b.Val[1]
		x.SetBytes(right.Val[0][:])
		y.SetBytes(b.Val[1][:])
	}
	x = *x.Add(&x, &y)
	xb := x.Bytes()
	for i:=0; i < 21-len(xb); i++ {
		node.D[i] = 0
	}
	copy(node.D[21-len(xb):], xb)
	file.WriteAt(node.Store(), pos)
	return &node
}
