/* Copyright (C) 2019-2020 omega-chain.com - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
* You should have received a copy of the license with this file.
* If not, please visit: <https://omega-chain.com/license.html>
 */

package token

import (
//	"bytes"
	"fmt"
	"io"
//	"strconv"
	"regexp"
//	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"encoding/binary"
	"github.com/btcsuite/btcd/wire/common"
)

const MaxMessagePayload = (1024 * 1024 * 32)	// must be same as in wire.message.go

const (
	// definition related consts. to defined a new vertes, border, polygon, rightset, or a right
	DefTypeVertex = 0
	DefTypeBorder = 1
	DefTypePolygon = 2		// also a loop, canbe mixed
	//	DefTypePolyhedron = 3
	DefTypeRight = 4
	DefTypeRightSet = 5

	CoordPrecision = 0x400000		// we use 32-bit fixed point (23 decimal points) number fir gei coords
	MinDefinitionPayload = 68
	MaxDefinitionPerMessage = (MaxMessagePayload / MinDefinitionPayload) + 1
)

// right flag masks
const (
	NegativeRight	=		1		// define whether the desc is positive or nagative
	Unsplittable =		2		// whether this right may be aplitted futher
	Monitored	=			4		// whether token with this right is monitored, splitted subrights inherits this flag
	Monitor =				8		// this is for the monitoring token
	IsMonitorCall	 =		16		// whether desc defines a coontract call for monitoring
)

type Definition interface {
	DefType () uint8
	Hash () chainhash.Hash
	SerializeSize() int
	Size() int
	Read(io.Reader, uint32) error
	Write(io.Writer, uint32) error
	MemRead(io.Reader, uint32) error
	MemWrite(io.Writer, uint32) error
}

type VertexDef struct {
	hash *chainhash.Hash
	Lat int32
	Lng int32
	Alt int32
//	Desc []byte
}

func (t * VertexDef) DefType() uint8 {
	return DefTypeVertex
}

func (t * VertexDef) Hash() chainhash.Hash {
	if t.hash == nil {
//		buf := bytes.NewBuffer(make([]byte, 0, t.SerializeSize() - VarIntSerializeSize(uint64(len(t.Desc)))))
//		writeElements(buf, DefTypeVertex, t.Lat, t.Lng, t.Desc)
//		hash := chainhash.DoubleHashH(buf.Bytes())

		b := make([]byte, 12)	// + len(t.Desc))
		binary.LittleEndian.PutUint32(b[0:], uint32(t.Lat))
		binary.LittleEndian.PutUint32(b[4:], uint32(t.Lng))
		binary.LittleEndian.PutUint32(b[8:], uint32(t.Alt))
//		copy(b[8:], t.Desc)
		hash := chainhash.HashH(b)

		t.hash = &hash
	}
	return * t.hash
}

func (t * VertexDef) SerializeSize() int {
	return 1 + 4 + 4	// + common.VarIntSerializeSize(uint64(len(t.Desc))) + len(t.Desc)
}

func (t * VertexDef) Size() int {
	return 1 + 4 + 4	// + 4	+ len(t.Desc)
}

func NewVertexDef(lat, lng, alt int32) (* VertexDef) {
	t := VertexDef{}
//	t.Desc = make([]byte, len(desc))
//	copy(t.Desc, desc)
	t.Lat = lat
	t.Lng = lng
	t.Alt = alt

	return &t
}

func (msg * VertexDef) MemRead(r io.Reader, pver uint32) error {
	lat, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}
	msg.Lat = int32(lat)

	lng, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}
	msg.Lng = int32(lng)

	alt, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}
	msg.Alt = int32(alt)

//	count, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
//	if err != nil {
//		return err
//	}

//	msg.Desc = make([]byte, count, count)
//	if _, err = io.ReadFull(r, msg.Desc[:]); err != nil {
//		return err
//	}

	return nil
}

func (msg * VertexDef) Read(r io.Reader, pver uint32) error {
	lat, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}
	msg.Lat = int32(lat)

	lng, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}
	msg.Lng = int32(lng)

	alt, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}
	msg.Alt = int32(alt)

	//	count, err := common.ReadVarInt(r, pver)
//	if err != nil {
//		return err
//	}

//	msg.Desc = make([]byte, count, count)
//	if _, err = io.ReadFull(r, msg.Desc[:]); err != nil {
//		return err
//	}

	return nil
}

func (msg * VertexDef) Write(w io.Writer, pver uint32) error {
	err := common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(msg.Lat))
	if err != nil {
		return err
	}
	err = common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(msg.Lng))
	if err != nil {
		return err
	}

	err = common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(msg.Alt))
	if err != nil {
		return err
	}

	//	count := uint64(len(msg.Desc))
//	err = common.WriteVarInt(w, pver, count)
//	if err != nil {
//		return err
//	}
//	_, err = w.Write(msg.Desc)

	return err
}

func (msg * VertexDef) MemWrite(w io.Writer, pver uint32) error {
	err := common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(msg.Lat))
	if err != nil {
		return err
	}
	err = common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(msg.Lng))
	if err != nil {
		return err
	}

	err = common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(msg.Alt))
	if err != nil {
		return err
	}


//	count := uint64(len(msg.Desc))
//	err = common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(count))
//	if err != nil {
//		return err
//	}
//	_, err = w.Write(msg.Desc)

	return err
}

type BorderDef struct {
	hash * chainhash.Hash
	Father chainhash.Hash
	Begin chainhash.Hash
	End chainhash.Hash
}

func (t * BorderDef) DefType() uint8 {
	return DefTypeBorder
}

func (t * BorderDef) Hash() chainhash.Hash {
	if t.hash == nil {
		b := make([]byte, chainhash.HashSize * 3)
		copy(b[:], t.Father[:])
		copy(b[chainhash.HashSize:], t.Begin[:])
		copy(b[2 * chainhash.HashSize:], t.End[:])

		hash := chainhash.HashH(b)
		hash[0] &= 0xFE		// LSB always 0, reserved for indicating its direction when used in polygon
		t.hash = &hash
	}
	return *t.hash
}

func (t * BorderDef) SerializeSize() int {
	return chainhash.HashSize * 3
}

func (t * BorderDef) Size() int {
	return chainhash.HashSize * 3
}

func NewBorderDef(begin chainhash.Hash, end chainhash.Hash, father chainhash.Hash) (* BorderDef) {
	t := BorderDef{}
	t.Begin = begin
	t.Father = father
	t.End = end
	return &t
}

func (t * BorderDef) MemRead(r io.Reader, pver uint32) error {
	return t.Read(r, pver)
}

func (t * BorderDef) Read(r io.Reader, pver uint32) error {
	io.ReadFull(r, t.Father[:])
	io.ReadFull(r, t.Begin[:])
	io.ReadFull(r, t.End[:])

	return nil
}

func (t * BorderDef) MemWrite(w io.Writer, pver uint32) error {
	return t.Write(w, pver)
}

func (t * BorderDef) Write(w io.Writer, pver uint32) error {
	w.Write(t.Father[:])
	w.Write(t.Begin[:])
	w.Write(t.End[:])

	return nil
}

type LoopDef []chainhash.Hash		// if the loops has only one item, it is not a border, it is another polygon!!!

type PolygonDef struct {
	hash * chainhash.Hash
	Loops []LoopDef
}

func (t * PolygonDef) DefType() uint8 {
	return DefTypePolygon
}

func (t * PolygonDef) Hash() chainhash.Hash {
	if t.hash == nil {
		count := 0
		for _,loop := range t.Loops {
			count += chainhash.HashSize * len(loop)
		}
		b := make([]byte, count)
		p := 0
		for _,loop := range t.Loops {
			for _,border := range loop {
				copy(b[p:], border[:])
				p += chainhash.HashSize
			}
		}
		hash := chainhash.HashH(b)
		t.hash = &hash
	}
	return * t.hash
}

func (t * PolygonDef) SerializeSize() int {
	n := 1 + common.VarIntSerializeSize(uint64(len(t.Loops)))
	for _,loop := range t.Loops {
		n += common.VarIntSerializeSize(uint64(len(loop))) + len(loop) * chainhash.HashSize
	}

	return n
}

func (t * PolygonDef) Size() int {
	n := 1 + 4
	for _,loop := range t.Loops {
		n += 4 + len(loop) * chainhash.HashSize
	}

	return n
}

func NewPolygonDef(loops []LoopDef) (* PolygonDef) {
	t := PolygonDef{}
	t.Loops = loops

	return &t
}

func (t * PolygonDef) Read(r io.Reader, pver uint32) error {
	nloops, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	t.Loops = make([]LoopDef, 0, nloops)

	for nloops > 0 {
		borders, err := common.ReadVarInt(r, pver)
		if err != nil {
			return err
		}
		loop := make([]chainhash.Hash, 0, borders)
		for borders > 0 {
			b := chainhash.Hash{}
			io.ReadFull(r, b[:])
			loop = append(loop, b)
			borders--
		}
		t.Loops = append(t.Loops, loop)
		nloops--
	}

	return nil
}

func (t * PolygonDef) MemRead(r io.Reader, pver uint32) error {
	nloops, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}

	t.Loops = make([]LoopDef, 0, nloops)

	for nloops > 0 {
		borders, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
		if err != nil {
			return err
		}
		loop := make([]chainhash.Hash, 0, borders)
		for borders > 0 {
			b := chainhash.Hash{}
			io.ReadFull(r, b[:])
			loop = append(loop, b)
			borders--
		}
		t.Loops = append(t.Loops, loop)
		nloops--
	}

	return nil
}

func (t * PolygonDef) Write(w io.Writer, pver uint32) error {
	err := common.WriteVarInt(w, pver, uint64(len(t.Loops)))
	if err != nil {
		return err
	}

	i := 0
	for i < len(t.Loops) {
		err := common.WriteVarInt(w, pver, uint64(len(t.Loops[i])))
		if err != nil {
			return err
		}
		j := 0
		for j < len(t.Loops[i]) {
			w.Write(t.Loops[i][j][:])
			j++
		}
		i++
	}

	return nil
}

func (t * PolygonDef) MemWrite(w io.Writer, pver uint32) error {
	err := common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(len(t.Loops)))

	if err != nil {
		return err
	}

	i := 0
	for i < len(t.Loops) {
		err := common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(len(t.Loops[i])))
		if err != nil {
			return err
		}
		j := 0
		for j < len(t.Loops[i]) {
			w.Write(t.Loops[i][j][:])
			j++
		}
		i++
	}

	return nil
}

type RightDef struct {
	hash * chainhash.Hash
	Father chainhash.Hash
	Desc []byte
	Attrib uint8		// bit 0: whether it is affirmative, (0 = affirmative, 1 - negativr)
						// bit 1: whether it is splittable. ( 0 = splittable, 1 - not splittable)
						// bit 2: whether it is a monitored (only for polygon token). inherited always
						// bit 3: whether it is a monitor (only for polygon token)
						// bit 4: whether Desc is a contract call func.
}

func (t * RightDef) DefType() uint8 {
	return DefTypeRight
}

func (t * RightDef) Hash() chainhash.Hash {
	if t.hash == nil {
		b := make([]byte, 33 + len(t.Desc))
		copy(b[:], t.Father[:])
		copy(b[chainhash.HashSize:], t.Desc)
		b[chainhash.HashSize + len(t.Desc)] = t.Attrib

		hash := chainhash.HashH(b)
		t.hash = &hash
	}
	return * t.hash
}

func (t * RightDef) SerializeSize() int {
	return 1 + chainhash.HashSize  + 1 + common.VarIntSerializeSize(uint64(len(t.Desc))) + len(t.Desc)
}

func (t * RightDef) Size() int {
	return 1 + chainhash.HashSize  + 1 + 4 + len(t.Desc)
}

func NewRightDef(father chainhash.Hash, desc []byte, attrib uint8) (* RightDef) {
	t := RightDef{}
	t.Father = father
	t.Desc = desc
	t.Attrib = attrib

	return &t
}

func (t * RightDef) Read(r io.Reader, pver uint32) error {
	io.ReadFull(r, t.Father[:])

	n, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	t.Desc = make([]byte, n)
	io.ReadFull(r, t.Desc[:])
	t.Attrib, _ = common.BinarySerializer.Uint8(r)

	return nil
}

func (t * RightDef) MemRead(r io.Reader, pver uint32) error {
	io.ReadFull(r, t.Father[:])

	n, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}

	t.Desc = make([]byte, n)
	io.ReadFull(r, t.Desc[:])
	t.Attrib, _ = common.BinarySerializer.Uint8(r)

	return nil
}

func (t * RightDef) Write(w io.Writer, pver uint32) error {
	w.Write(t.Father[:])
	err := common.WriteVarInt(w, pver, uint64(len(t.Desc)))
	if err != nil {
		return err
	}
	w.Write(t.Desc[:])

	err = common.BinarySerializer.PutUint8(w, t.Attrib)
	if err != nil {
		return err
	}

	return nil
}

func (t * RightDef) MemWrite(w io.Writer, pver uint32) error {
	w.Write(t.Father[:])
	err :=  common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(len(t.Desc)))
	if err != nil {
		return err
	}
	w.Write(t.Desc[:])

	err = common.BinarySerializer.PutUint8(w, t.Attrib)
	if err != nil {
		return err
	}

	return nil
}

type RightSetDef struct {
	hash * chainhash.Hash
	Rights []chainhash.Hash
}

func (t * RightSetDef) DefType() uint8 {
	return DefTypeRightSet
}

func (t * RightSetDef) Hash() chainhash.Hash {
	if t.hash == nil {
		b := make([]byte, 32 * len(t.Rights))
		for i, r := range t.Rights {
			copy(b[i * 32 : i * 32 + 32], r[:])
		}

		hash := chainhash.HashH(b)
		t.hash = &hash
	}
	return * t.hash
}

func (t * RightSetDef) SerializeSize() int {
	return common.VarIntSerializeSize(uint64(len(t.Rights))) + 32 * len(t.Rights)
}

func (t * RightSetDef) Size() int {
	return 4 + 32 * len(t.Rights)
}

func NewRightSetDef(rights []chainhash.Hash) (* RightSetDef) {
	t := RightSetDef{}
	t.Rights = rights

	return &t
}

func (t * RightSetDef) Read(r io.Reader, pver uint32) error {
	n, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	t.Rights = make([]chainhash.Hash, n)
	for i := 0; i < int(n); i++ {
		io.ReadFull(r, t.Rights[i][:])
	}

	return nil
}

func (t * RightSetDef) MemRead(r io.Reader, pver uint32) error {
	n, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}

	t.Rights = make([]chainhash.Hash, n)
	for i := 0; i < int(n); i++ {
		io.ReadFull(r, t.Rights[i][:])
	}

	return nil
}

func (t * RightSetDef) Write(w io.Writer, pver uint32) error {
	err := common.WriteVarInt(w, pver, uint64(len(t.Rights)))
	if err != nil {
		return err
	}

	for _, r := range t.Rights {
		w.Write(r[:])
	}

	return nil
}

func (t * RightSetDef) MemWrite(w io.Writer, pver uint32) error {
	err :=  common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(len(t.Rights)))
	if err != nil {
		return err
	}

	for _, r := range t.Rights {
		w.Write(r[:])
	}

	return nil
}

type TokenValue interface {	// a union of:
				// Hash  chainhash.Hash
				//  Value int64
	IsNumeric () bool
	Value()  (* chainhash.Hash, int64)
}

type HashToken struct {
	Hash chainhash.Hash
}

type NumToken struct {
	Val int64
}

func (t *HashToken) IsNumeric () bool {
	return false
}
func (t *HashToken) Value() (* chainhash.Hash, int64) {
	return &t.Hash, 0
}

func (t *NumToken) IsNumeric () bool {
	return true
}
func (t *NumToken) Value() (* chainhash.Hash, int64) {
	return nil, t.Val
}

type Token struct {
	TokenType	uint64		// bit 0: 0 -- numeric alue, 1 -- hash value
	// bit 1: 0 -- w/o rights, 1 -- w/ rights
	// special value, 3 = polygon token, 0 = omega coin
	Value     TokenValue
	Rights * chainhash.Hash
}

func (t *Token) IsNumeric () bool {
	return t.TokenType & 1 == 0
}

func (t *Token) HasRight () bool {
	return t.TokenType & 2 == 0
}

func (t *Token) Diff(s *Token) bool {
	if t.TokenType != s.TokenType {
		return true
	}
	if t.TokenType & 1 != 0 {
		if !t.Value.(*HashToken).Hash.IsEqual(&s.Value.(*HashToken).Hash) {
			return true
		}
	} else if t.Value.(*NumToken).Val != s.Value.(*NumToken).Val {
		return true
	}

	if t.TokenType & 2 != 0 {
		return !t.Rights.IsEqual(s.Rights)
	}
	return false
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
func (t *Token) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of PkScript +
	// PkScript bytes.
	n := common.VarIntSerializeSize(t.TokenType)
	if (t.TokenType & 1) != 0 {
		n += chainhash.HashSize
	} else {
		n += 8
	}
	if (t.TokenType & 2) != 0 {
		n += chainhash.HashSize
	}
	return n
}

func (t *Token) Size() int {
	// Value 8 bytes + serialized varint size for the length of PkScript +
	// PkScript bytes.
	n := 8
	if (t.TokenType & 1) != 0 {
		n += chainhash.HashSize
	} else {
		n += 8
	}
	if (t.TokenType & 2) != 0 {
		n += chainhash.HashSize
	}
	return n
}

func RemapDef(txDef []Definition, to Definition) Definition {
	switch to.DefType() {
	case DefTypeBorder:
		b := to.(*BorderDef)
		if r := NeedRemap(b.Father[:]); len(r) > 0 {
			b.Father = txDef[Bytetoint(r[1])].Hash()
		}
		if r := NeedRemap(b.Begin[:]); len(r) > 0 {
			b.Begin = txDef[Bytetoint(r[1])].Hash()
		}
		if r := NeedRemap(b.End[:]); len(r) > 0 {
			b.End = txDef[Bytetoint(r[1])].Hash()
		}
		return b
		break
	case DefTypePolygon:
		p := to.(*PolygonDef)
		for i,loop := range p.Loops {
			for j,l := range loop {
				if r := NeedRemap(l[:]); len(r) > 0 {
					t := txDef[Bytetoint(r[1])].Hash()
					if r,_ := regexp.Match(`^\[[0-9]+\]R`, l[:]); r {
						t[0] |= 1
					}
					p.Loops[i][j] = t
				}
			}
		}
		return p
		break
	case DefTypeRight:
		r := to.(*RightDef)
		if t := NeedRemap(r.Father[:]); len(t) > 0 {
			r.Father = txDef[Bytetoint(t[1])].Hash()
		}
		return r
		break
	case DefTypeRightSet:
		r := to.(*RightSetDef)
		for i,s := range r.Rights {
			if t := NeedRemap(s[:]); len(t) > 0 {
				r.Rights[i] = txDef[Bytetoint(t[1])].Hash()
			}
		}
		return r
		break
	}
	return to
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func CopyDefinitions(defs []Definition) []Definition {
	txdef := make([]Definition, 0, len(defs))
	// Deep copy the old Defnition data.
	for _, oldDefinitions := range defs {
		switch oldDefinitions.DefType() {
			case DefTypeVertex:
				c := oldDefinitions.(*VertexDef)
				newDefinitions := VertexDef{
					Lat: c.Lat,
					Lng: c.Lng,
					}
//				newDefinitions.Desc = make([]byte, len(c.Desc))
//				copy(newDefinitions.Desc, c.Desc)
				txdef = append(txdef, &newDefinitions)
				break;
			case DefTypeBorder:
				c := oldDefinitions.(*BorderDef)
				newDefinitions := BorderDef{}
				newDefinitions.Father.SetBytes(c.Father[:])
				newDefinitions.Begin.SetBytes(c.Begin[:])
				newDefinitions.End.SetBytes(c.End[:])
				txdef = append(txdef, &newDefinitions)
				break;
			case DefTypePolygon:
				c := oldDefinitions.(*PolygonDef)
				newDefinitions := PolygonDef{}
				newDefinitions.Loops = make([]LoopDef, 0, len(c.Loops))
				for _,loop := range c.Loops {
					nl := make([]chainhash.Hash, 0, len(loop))
					for _,l := range loop {
						nh := chainhash.Hash{}
						nh.SetBytes(l[:])
						nl = append(nl, nh)
					}
					newDefinitions.Loops = append(newDefinitions.Loops, nl)
				}
				txdef = append(txdef, &newDefinitions)
				break;
			case DefTypeRight:
				c := oldDefinitions.(*RightDef)
				newDefinitions := RightDef{
					Attrib: c.Attrib,
				}
				newDefinitions.Father.SetBytes(c.Father[:])
				newDefinitions.Desc = make([]byte, len(c.Desc))
				copy(newDefinitions.Desc, c.Desc)
				txdef = append(txdef, &newDefinitions)
				break;
			case DefTypeRightSet:
				c := oldDefinitions.(*RightSetDef)
				newDefinitions := RightSetDef{
					Rights: make([]chainhash.Hash, len(c.Rights)),
				}
				for i,r := range c.Rights {
					copy(newDefinitions.Rights[i][:], r[:])
				}
				txdef = append(txdef, &newDefinitions)
				break;
		}
	}

	return txdef
}

// ReadDefinition reads the next sequence of bytes from r as a transaction definitions
// (Definition).
func ReadDefinition(r io.Reader, pver uint32, version int32) (Definition, error) {
	var t uint8

	err := common.ReadElement(r, &t)
	if err != nil {
		return nil,err
	}

	switch t {
	case DefTypeVertex:
		c := VertexDef{}
		err = c.Read(r, pver)
		return &c, err
		break;
	case DefTypeBorder:
		c := BorderDef{}
		err = c.Read(r, pver)
		return &c, err
		break;
	case DefTypePolygon:
		c := PolygonDef{}
		err = c.Read(r, pver)
		return &c, err
		break;
	case DefTypeRight:
		c := RightDef{}
		err = c.Read(r, pver)
		return &c, err
		break;
	case DefTypeRightSet:
		c := RightDef{}
		err = c.Read(r, pver)
		return &c, err
		break;
	}

	str := fmt.Sprintf("Unrecognized definition type %d", t)
	return nil, common.NewMessageError("readScript", str)
}

// WriteDefinition encodes ti to the bitcoin protocol encoding for a definition (Definition) to w.
func WriteDefinition(w io.Writer, pver uint32, version int32, ti Definition) error {
	err := common.BinarySerializer.PutUint8(w, uint8(ti.DefType()))

	switch ti.DefType() {
	case DefTypeVertex:
		c := ti.(*VertexDef)
		err = c.Write(w, pver)
		break;
	case DefTypeBorder:
		c := ti.(*BorderDef)
		err = c.Write(w, pver)
		break;
	case DefTypePolygon:
		c := ti.(*PolygonDef)
		err = c.Write(w, pver)
		break;
	case DefTypeRight:
		c := ti.(*RightDef)
		err = c.Write(w, pver)
		break;
	case DefTypeRightSet:
		c := ti.(*RightSetDef)
		err = c.Write(w, pver)
		break;
	}

	return err
}

func (to *Token) Type() string {
	return fmt.Sprintf("%d", to.TokenType)
/*
	for _,r := range to.Rights {
		s += ":" + r.String()
	}
	return s
*/
}

func (to *Token) ReadTxOut(r io.Reader, pver uint32, version uint32) error {
	t, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	to.TokenType = t

	if t == 0xFFFFFFFFFFFFFFFF {
		// this is a separator
		return nil
	}

	if (t & 1) == 1 {
		h := HashToken{}
		err = common.ReadElement(r, &h.Hash)
		to.Value = &h
	} else {
		n := NumToken{}
		err = common.ReadElement(r, &n.Val)
		to.Value = &n
	}

	if err != nil {
		return err
	}

	if (to.TokenType & 2) != 0 {
		to.Rights = &chainhash.Hash{}
		err = common.ReadElement(r, to.Rights)
		if err != nil {
			return err
		}
	}

	return err
}

func (to * Token) WriteTxOut(w io.Writer, pver uint32, version int32) error {
	err := common.WriteVarInt(w, pver, to.TokenType)
	if err != nil {
		return err
	}

	if to.TokenType == 0xFFFFFFFFFFFFFFFF {
		// this is a separator
		return nil
	}

	h, v := to.Value.Value()
	if to.Value.IsNumeric() {
		err = common.BinarySerializer.PutUint64(w, common.LittleEndian, uint64(v))
	} else {
		_,err = w.Write(h[:])
	}
	if err != nil {
		return err
	}

	if (to.TokenType & 2) != 0 {
		if to.Rights == nil {
			to.Rights = & chainhash.Hash{}
		}
		_, err = w.Write((*to.Rights)[:])
		if err != nil {
			return err
		}
	}

	return nil
}

func (to * Token) Read(r io.Reader, pver uint32, version int32) error {
	t, err := common.BinarySerializer.Uint64(r, common.LittleEndian)
	if err != nil {
		return err
	}
	to.TokenType = t

	if (t & 1) == 1 {
		h := HashToken{}
		err = common.ReadElement(r, &h.Hash)
		to.Value = &h
	} else {
		n := NumToken{}
		err = common.ReadElement(r, &n.Val)
		to.Value = &n
	}

	if err != nil {
		return err
	}

	if (to.TokenType & 2) != 0 {
		to.Rights = &chainhash.Hash{}
		err = common.ReadElement(r, &to.Rights)
		if err != nil {
			return err
		}
	}

	return err
}

func (to * Token) Write(w io.Writer, pver uint32, version int32) error {
	common.BinarySerializer.PutUint64(w, common.LittleEndian, to.TokenType)

	h, v := to.Value.Value()
	var err error
	if to.Value.IsNumeric() {
		err = common.BinarySerializer.PutUint64(w, common.LittleEndian, uint64(v))
	} else {
		_,err = w.Write(h[:])
	}
	if err != nil {
		return err
	}

	if (to.TokenType & 2) != 0 {
		_,err = w.Write((*to.Rights)[:])
		if err != nil {
			return err
		}
	}

	return nil
}

func (to * Token) Copy(s * Token) {
	s.TokenType = to.TokenType
	if to.Rights != nil {
		s.Rights, _ = chainhash.NewHash((*to.Rights)[:])
	}
	switch to.Value.(type) {
	case *NumToken:
		s.Value = &NumToken{to.Value.(*NumToken).Val}
	case *HashToken:
		h, _ := chainhash.NewHash(to.Value.(*HashToken).Hash[:])
		s.Value = &HashToken{*h}
	}
}

func NeedRemap(h []byte) [][]byte {
	reg, _ := regexp.Compile(`^\[([0-9]+)\]`)
	return reg.FindSubmatch(h)
}

func Bytetoint(h []byte) int {
	var n int
	fmt.Sscanf(string(h),"%d", &n)
	return n
}
