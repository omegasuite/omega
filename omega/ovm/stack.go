/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import (
	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/omega"
	"math/big"
)

type frame struct {
	space []byte
	inlib [20]byte
	gbase int32
	pc int
	pure byte		// access Control:
					// bit 0 - forbid store,
					// bit 1 - forbid spend,
					// bit 2 - forbid output,
					// bit 3 - forbid load
					// bit 4 - forbid mint
}

func newFrame() * frame {
	return &frame{
		space: make([]byte, 0, 4096),
	}
}

type pointer uint64

type Stack struct {
	callTop int32
	libTop int32
	data map[int32]*frame
}

var outofmemory = omega.ScriptError(omega.ErrInternal,"Out of memory")
var outofstack = omega.ScriptError(omega.ErrInternal,"Out of stack")

func (s *Stack) malloc(n int) (pointer, int) {
	t := s.data[s.libTop].gbase
	p := pointer(uint64(len(s.data[t].space)) | (uint64(t) << 32))
	if n == 0 {
		return p, 0
	}
	m := (n + 63) &^ 63
	s.data[t].space = append(s.data[t].space, make([]byte, m)...)
	return p, m
}

func (s *Stack) alloc(n int) (pointer, int) {
	top := s.callTop
	p := pointer((uint64(top) << 32) | uint64(len(s.data[top].space)))
	if n == 0 {
		return p, 0
	}
	m := (n + 63) &^ 63
	s.data[top].space = append(s.data[top].space, make([]byte, m)...)
	return p, m
}

func (s *Stack) shrink(n int) {	// it is only used by sig engine and there is no stack
	if n == 0 {
		return
	}
	s.data[0].space = s.data[0].space[:len(s.data[0].space) - n]
}

func (s *Stack) toBig(p * pointer) (* big.Int, omega.Err) {
	// Note: little-endian to big-endian
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)
	if _,ok := s.data[area]; !ok {
		return nil, outofstack
	}
	if offset < 0 || (offset + 32) > len(s.data[area].space) {
		return nil, outofstack
	}

	var h chainhash.Hash

	copy(h[:], s.data[area].space[offset:offset+32])
	i, n := 31, 0
	for ; i >= 0 && h[i] == 0; i-- { }
	n = i + 1
	for i = 0; i < n / 2; i++ {
		s, t := h[i], h[n - 1 - i]
		h[i], h[n - 1 - i] = t, s
	}

	num := big.Int{}
	num.SetBytes(h[:n])
/*
	for j := int(31); j >= 0; j-- {
		tmp := uint8(s.data[area].space[offset + j])
		num = *num.Add(num.Mul(&num, big.NewInt(256)), big.NewInt(int64(tmp)))
	}
 */

	return &num, nil
}

func (s *Stack) toPointer(p * pointer) (pointer, omega.Err) {
	d,err := s.toInt64(p)
	return pointer(d), err
}

func (s *Stack) toByte(p * pointer) (byte, omega.Err) {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return 0, outofstack
	}

	if offset < len(s.data[area].space) {
		return s.data[area].space[offset], nil
	}
	return 0, outofmemory
}

func (s *Stack) toBytesLen(p * pointer, n int) ([]byte, omega.Err) {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return nil, outofstack
	}
	if offset + n < len(s.data[area].space) {
		return s.data[area].space[offset:offset + n], nil
	}
	return nil, outofmemory
}

func (s *Stack) toBytes(p * pointer) ([]byte, omega.Err) {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return nil, outofstack
	}
	if offset < len(s.data[area].space) {
		return s.data[area].space[offset:], nil
	}
	return nil, outofmemory
}

func (s *Stack) toInt16(p * pointer) (int16, omega.Err) {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return 0, outofstack
	}
	if offset + 1 < len(s.data[area].space) {
		return (int16(s.data[area].space[offset])) | ((int16(s.data[area].space[offset + 1])) << 8), nil
	}
	return 0, outofmemory
}

func (s *Stack) toInt32(p * pointer) (int32, omega.Err) {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return 0, outofstack
	}
	if offset + 3 < len(s.data[area].space) {
		return (int32(s.data[area].space[offset])) |
			((int32(s.data[area].space[offset + 1])) << 8) |
			((int32(s.data[area].space[offset + 2])) << 16) |
			((int32(s.data[area].space[offset + 3])) << 24), nil
	}
	return 0, outofmemory
}

func (s *Stack) toInt64(p * pointer) (int64, omega.Err) {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return 0, outofstack
	}
	if offset + 7 < len(s.data[area].space) {
		return (int64(s.data[area].space[offset])) |
			((int64(s.data[area].space[offset + 1])) << 8) |
			((int64(s.data[area].space[offset + 2])) << 16) |
			((int64(s.data[area].space[offset + 3])) << 24) |
			((int64(s.data[area].space[offset + 4])) << 32) |
			((int64(s.data[area].space[offset + 5])) << 40) |
			((int64(s.data[area].space[offset + 6])) << 48) |
			((int64(s.data[area].space[offset + 7])) << 56), nil
	}
	return 0, outofmemory
}

func (s *Stack) toHash(p * pointer) (chainhash.Hash, omega.Err) {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return chainhash.Hash{}, outofstack
	}
	if offset + 31 < len(s.data[area].space) {
		h,_ := chainhash.NewHash(s.data[area].space[offset:offset + 32])
		return *h, nil
	}
	return chainhash.Hash{}, outofmemory
}

func (s *Stack) savePointer(p * pointer, d pointer) omega.Err {
	return s.saveInt64(p, int64(d))
}

func (s *Stack) saveByte(p * pointer, b byte) omega.Err {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return outofstack
	}
	if offset < len(s.data[area].space) {
		s.data[area].space[offset] = b
		return nil
	}
	return outofmemory
}

func (s *Stack) saveBytes(p * pointer, b []byte) omega.Err {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return outofstack
	}
	if offset < len(s.data[area].space) {
		copy(s.data[area].space[offset:], b)
		return nil
	}
	return outofmemory
}

func (s *Stack) saveInt16(p * pointer, b int16) omega.Err {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return outofstack
	}
	if offset + 1 < len(s.data[area].space) {
		s.data[area].space[offset] = byte(b)
		s.data[area].space[offset + 1] = byte(b >> 8)
		return nil
	}
	return outofmemory
}

func (s *Stack) saveInt32(p * pointer, b int32) omega.Err {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return outofstack
	}
	if offset + 3 < len(s.data[area].space) {
		for i := 0; i < 4; i++ {
			s.data[area].space[offset + i] = byte(b >> (8 * i))
		}
		return nil
	}
	return outofmemory
}

func (s *Stack) saveInt64(p * pointer, b int64) omega.Err {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return outofstack
	}
	if offset + 7 < len(s.data[area].space) {
		for i := 0; i < 8; i++ {
			s.data[area].space[offset + i] = byte(b >> (8 * i))
		}
		return nil
	}
	return outofmemory
}

func (s *Stack) saveHash(p * pointer, h chainhash.Hash) omega.Err {
	offset := int(*p & 0xFFFFFFFF)
	area := int32(*p >> 32)

	if _,ok := s.data[area]; !ok {
		return outofstack
	}
	if offset + 31 < len(s.data[area].space) {
		copy(s.data[area].space[offset:], h[:])
		return nil
	}
	return outofmemory
}

func Newstack() *Stack {
	s := &Stack{data: make(map[int32]*frame)}
	s.callTop = 0
	s.libTop = 0
	s.data[0] = newFrame()
	s.data[0].space = make([]byte, 4, 1024)
	return s
}

func (st *Stack) Print() {
	fmt.Println("### stack ###")
	if len(st.data) > 0 {
		for i, val := range st.data {
			fmt.Printf("%-3d  %v\n", i, val)
		}
	} else {
		fmt.Println("-- empty --")
	}
	fmt.Println("#############")
}
