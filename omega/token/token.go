/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package token

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	//	"strconv"
	"regexp"
	//	"math"

	"encoding/binary"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire/common"
)

const MaxMessagePayload = (1024 * 1024 * 400)	// must be same as in wire.message.go

const (
	// definition related consts. to defined a new vertes, border, polygon, rightset, or a right
	DefTypeVertex = 0
	DefTypeBorder = 1
	DefTypePolygon = 2		// also a loop, can be mixed
	//	DefTypePolyhedron = 3
	DefTypeRight = 4
	DefTypeRightSet = 5

	DefTypeSeparator = 0xFC			// fd ~ ff are var int coding

	CoordPrecision = 0x200000		// we use 32-bit fixed point (22 decimal points) number for alt/lng coords
	AltPrecision = 0x400			// we use 32-bit fixed point (10 decimal points) number for alt coords (meter)
									// if the value is between 0 & 100, it is considered as 0 and the coord is a nonce
									// to change edge hash
	MinDefinitionPayload = 68
	MaxDefinitionPerMessage = (MaxMessagePayload / MinDefinitionPayload) + 1
)

// right flag masks
const (
	NegativeRight	=		1		// define whether the desc is positive or nagative
	Unsplittable =			2		// whether this right may be aplitted futher
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
	IsSeparator() bool
	Match(Definition) bool
	Dup() Definition
}

type VertexDef struct {
	lat int32
	lng int32
	alt int32
}

func (s VertexDef) Lat() int32 {
	return s.lat
}
func (s VertexDef) Lng() int32 {
	return s.lng
}
func (s VertexDef) Alt() int32 {
	return s.alt
}

func (s * VertexDef) SetLat(x int32) {
	s.lat = x
}
func (s * VertexDef) SetLng(x int32) {
	s.lng = x
}
func (s * VertexDef) SetAlt(x int32) {
	s.alt = x
}

func (s * VertexDef) Serialize() []byte {
	var r [12]byte
	binary.LittleEndian.PutUint32(r[:], uint32(s.lat))
	binary.LittleEndian.PutUint32(r[4:], uint32(s.lng))
	binary.LittleEndian.PutUint32(r[8:], uint32(s.alt))
	return r[:]
}

func (s * VertexDef) Deserialize(r []byte) {
	s.lat = int32(binary.LittleEndian.Uint32(r))
	s.lng = int32(binary.LittleEndian.Uint32(r[4:]))
	s.alt = int32(binary.LittleEndian.Uint32(r[8:]))
}

func (s * VertexDef) IsEqual(t * VertexDef) bool {
	return s.Lng() == t.Lng() && s.Lat() == t.Lat()
}

func (s * VertexDef) Match(p Definition) bool {
	switch p.(type) {
	case * VertexDef:
		t := p.(* VertexDef)
		return s.Lng() == t.Lng() && s.Alt() == t.Alt() && s.Lat() == t.Lat()
	default:
		return false
	}
}

func (t * VertexDef) DefType() uint8 {
	return DefTypeVertex
}

func (t * VertexDef) IsSeparator() bool {
	return false
}

func (t * VertexDef) Hash() chainhash.Hash {
	h := chainhash.Hash{}
	copy(h[:], t.Serialize()[:8])
	return h
}

func (t * VertexDef) SerializeSize() int {
	return 12
}

func (t * VertexDef) Size() int {
	return 12
}

func NewVertexDef(lat, lng, alt int32) (* VertexDef) {
	t := VertexDef{}

	t.SetLat(lat)
	t.SetLng(lng)
	t.SetAlt(alt)

	return &t
}

func (msg * VertexDef) MemRead(r io.Reader, pver uint32) error {
	return msg.Read(r, pver)
}

func (msg * VertexDef) Read(r io.Reader, pver uint32) error {
	var b [12]byte
	_, err := r.Read(b[:])
	msg.Deserialize(b[:])

	return err
}

func (msg * VertexDef) Write(w io.Writer, pver uint32) error {
	_, err := w.Write(msg.Serialize())
	return err
}

func (msg * VertexDef) MemWrite(w io.Writer, pver uint32) error {
	return msg.Write(w, pver)
}

type BorderDef struct {
	hash * chainhash.Hash
	Father chainhash.Hash
	Begin VertexDef
	End VertexDef
}

func (s * BorderDef) Match(p Definition) bool {
	switch p.(type) {
	case * BorderDef:
		t := p.(* BorderDef)
		return s.Father.IsEqual(&t.Father) && s.Begin.IsEqual(&t.Begin) && s.End.IsEqual(&t.End)
	default:
		return false
	}
}

func (t * BorderDef) DefType() uint8 {
	return DefTypeBorder
}

func (t * BorderDef) IsSeparator() bool {
	return false
}

func (t * BorderDef) Hash() chainhash.Hash {
	if t.hash == nil {
		b := make([]byte, chainhash.HashSize + 24)
		copy(b[:], t.Father[:])
		copy(b[chainhash.HashSize:], t.Begin.Serialize())
		copy(b[12 + chainhash.HashSize:], t.End.Serialize())

		hash := chainhash.HashH(b)
		hash[0] &= 0xFE		// LSB always 0, reserved for indicating its direction when used in polygon
		t.hash = &hash
	}
	return *t.hash
}

func (t * BorderDef) SerializeSize() int {
	return chainhash.HashSize + 24
}

func (t * BorderDef) Size() int {
	return chainhash.HashSize + 24
}

func NewBorderDef(begin, end VertexDef, father chainhash.Hash) (* BorderDef) {
	if begin.IsEqual(&end) {
		return nil
	}
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

	var b [12]byte
	io.ReadFull(r, b[:])
	t.Begin.Deserialize(b[:])

	io.ReadFull(r, b[:])
	t.End.Deserialize(b[:])

	return nil
}

func (t * BorderDef) MemWrite(w io.Writer, pver uint32) error {
	return t.Write(w, pver)
}

func (t * BorderDef) Write(w io.Writer, pver uint32) error {
	w.Write(t.Father[:])
	w.Write(t.Begin.Serialize())
	w.Write(t.End.Serialize())

	return nil
}

type LoopDef []chainhash.Hash		// if the loops has only one item, it is not a border, it is another polygon!!!

func (s * LoopDef) CheckSum() string {
	if len(*s) == 1 {
		return string((*s)[0][:])
	}
	var r chainhash.Hash
	for _,p := range *s {
		for i := 0; i < chainhash.HashSize; i++ {
			r[i] ^= p[i]
		}
	}
	return string(r[:])
}

func (s * LoopDef) Equal(t * LoopDef) bool {
	if len(*s) != len(*t) {
		return false
	}
	for i,p := range *s {
		if !p.IsEqual(&(*t)[i]) {
			return false
		}
	}
	return true
}

type PolygonDef struct {
	hash * chainhash.Hash
	Loops []LoopDef
}

func (s * PolygonDef) Match(p Definition) bool {
	switch p.(type) {
	case * PolygonDef:
		t := p.(* PolygonDef)
		if len(s.Loops) != len(t.Loops) {
			return false
		}
		for i,l := range s.Loops {
			for j,b := range l {
				if !b.IsEqual(&t.Loops[i][j]) {
					return false
				}
			}
		}
		return true
	default:
		return false
	}
}

func (t * PolygonDef) DefType() uint8 {
	return DefTypePolygon
}

func (t * PolygonDef) IsSeparator() bool {
	return false
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
						// bit 7: 1. To force a non-0 value
}

func (s * RightDef) Match(p Definition) bool {
	switch p.(type) {
	case * RightDef:
		t := p.(* RightDef)
		if s.Attrib != t.Attrib || !s.Father.IsEqual(&t.Father) {
			return false
		}
		return bytes.Compare(s.Desc, t.Desc) == 0
	default:
		return false
	}
}

func (t * RightDef) DefType() uint8 {
	return DefTypeRight
}

func (t * RightDef) IsSeparator() bool {
	return false
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
	t.Attrib = attrib | 0x80

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
	sorted int
}

func (s * RightSetDef) less(i, j int) bool {
	for k := 0; k < chainhash.HashSize; k++ {
		if s.Rights[i][k] < s.Rights[j][k] {
			return true
		}
		if s.Rights[i][k] > s.Rights[j][k] {
			return false
		}
	}
	return i < j
}

func (s * RightSetDef) sort() {
	if s.sorted == len(s.Rights) {
		return
	}
	sort.Slice(s.Rights, s.less)
}

func (s * RightSetDef) Match(p Definition) bool {
	switch p.(type) {
	case * RightSetDef:
		t := p.(* RightSetDef)
		if len(s.Rights) != len(t.Rights) {
			return false
		}
		for i,d := range s.Rights {
			if !d.IsEqual(&t.Rights[i]) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (t * RightSetDef) DefType() uint8 {
	return DefTypeRightSet
}

func (t * RightSetDef) IsSeparator() bool {
	return false
}

func (t * RightSetDef) Hash() chainhash.Hash {
	if t.sorted != len(t.Rights) {
		t.hash = nil
	}
	t.sort()
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
	t.sort()
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
	t.sort()
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
	return t.TokenType & 2 != 0
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
		return b

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

	case DefTypeRight:
		r := to.(*RightDef)
		if t := NeedRemap(r.Father[:]); len(t) > 0 {
			r.Father = txDef[Bytetoint(t[1])].Hash()
		}
		return r

	case DefTypeRightSet:
		r := to.(*RightSetDef)
		for i,s := range r.Rights {
			if t := NeedRemap(s[:]); len(t) > 0 {
				r.Rights[i] = txDef[Bytetoint(t[1])].Hash()
			}
		}
		return r
	}
	return to
}

func (d *VertexDef) Dup() Definition {
	t := VertexDef{ }
	t = *d
	return &t
}

func (c *BorderDef) Dup() Definition {
	newDefinitions := BorderDef{}
	newDefinitions.Father.SetBytes(c.Father[:])
	newDefinitions.Begin = c.Begin
	newDefinitions.End = c.End
	return &newDefinitions
}

func (c *PolygonDef) Dup() Definition {
	newDefinitions := PolygonDef{}
	newDefinitions.Loops = make([]LoopDef, 0, len(c.Loops))
	for _, loop := range c.Loops {
		nl := make([]chainhash.Hash, 0, len(loop))
		for _, l := range loop {
			nh := chainhash.Hash{}
			nh.SetBytes(l[:])
			nl = append(nl, nh)
		}
		newDefinitions.Loops = append(newDefinitions.Loops, nl)
	}
	return &newDefinitions
}

func (c *RightDef) Dup() Definition {
	newDefinitions := RightDef{
		Attrib: c.Attrib,
	}
	newDefinitions.Father.SetBytes(c.Father[:])
	newDefinitions.Desc = make([]byte, len(c.Desc))
	copy(newDefinitions.Desc, c.Desc)
	return &newDefinitions
}

func (c *RightSetDef) Dup() Definition {
	newDefinitions := RightSetDef{
		Rights: make([]chainhash.Hash, len(c.Rights)),
	}
	for i, r := range c.Rights {
		copy(newDefinitions.Rights[i][:], r[:])
	}
	return &newDefinitions
}

func (c *SeparatorDef) Dup() Definition {
	return &SeparatorDef{ }
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func CopyDefinitions(defs []Definition) []Definition {
	txdef := make([]Definition, 0, len(defs))
	// Deep copy the old Defnition data.
	for _, oldDefinitions := range defs {
		txdef = append(txdef, oldDefinitions.Dup())
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

	case DefTypeBorder:
		c := BorderDef{}
		err = c.Read(r, pver)
		return &c, err

	case DefTypePolygon:
		c := PolygonDef{}
		err = c.Read(r, pver)
		return &c, err

	case DefTypeRight:
		c := RightDef{}
		err = c.Read(r, pver)
		return &c, err

	case DefTypeRightSet:
		c := RightSetDef{}
		err = c.Read(r, pver)
		return &c, err

	case DefTypeSeparator:
		c := SeparatorDef{}
		return &c, nil
	}

	str := fmt.Sprintf("Unrecognized definition type %d", t)
	return nil, common.NewMessageError("readScript", str)
}

// WriteDefinition encodes ti to the bitcoin protocol encoding for a definition (Definition) to w.
func WriteDefinition(w io.Writer, pver uint32, version int32, ti Definition) error {
	err := common.BinarySerializer.PutUint8(w, uint8(ti.DefType()))
	if err != nil {
		return err
	}

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
	case DefTypeSeparator:
		break;
	}

	return err
}

func (to *Token) Type() string {
	return fmt.Sprintf("%d", to.TokenType)
}

func (to *Token) ReadTxOut(r io.Reader, pver uint32, version uint32) error {
	t, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	to.TokenType = t

	if t == DefTypeSeparator {
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

	if to.TokenType == DefTypeSeparator {
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

	if t == DefTypeSeparator {
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

func (to * Token) Write(w io.Writer, pver uint32, version int32) error {
	common.BinarySerializer.PutUint64(w, common.LittleEndian, to.TokenType)

	if to.TokenType == DefTypeSeparator {
		return nil
	}

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

	if to.TokenType == DefTypeSeparator {
		return
	}
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

type SeparatorDef struct {}

func (t * SeparatorDef) DefType () uint8 {
	return DefTypeSeparator
}
func (t * SeparatorDef) IsSeparator() bool {
	return true
}
func (t * SeparatorDef) Hash () chainhash.Hash {
	return chainhash.Hash{}
}
func (t * SeparatorDef) SerializeSize() int {
	return 1
}
func (t * SeparatorDef) Size() int {
	return 1
}
func (t * SeparatorDef) Read(r io.Reader, v uint32) error {
	return nil
}
func (t * SeparatorDef) Write(io.Writer, uint32) error {
	return nil
}
func (t * SeparatorDef) MemRead(io.Reader, uint32) error {
	return nil
}
func (t * SeparatorDef) MemWrite(io.Writer, uint32) error {
	return nil
}

func (s * SeparatorDef) Match(p Definition) bool {
	switch p.(type) {
	case * SeparatorDef:
		return true
	default:
		return false
	}
}
