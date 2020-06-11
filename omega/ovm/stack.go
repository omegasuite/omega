// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import (
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type frame struct {
	space []byte
	inlib [20]byte
	gbase int32
	pc int
	pure bool
}

func newFrame() * frame {
	return &frame{
		space: make([]byte, 0, 4096),
	}
}

type pointer uint64

type Stack struct {
	data []*frame
}

var outofmemory = fmt.Errorf("Out of memory")

func (s *Stack) malloc(n int) (pointer, int) {
	p := pointer(uint64(len(s.data[0].space)))
	if n == 0 {
		return p, 0
	}
	m := (n + 63) &^ 63
	s.data[0].space = append(s.data[0].space, make([]byte, m)...)
	return p, m
}

func (s *Stack) alloc(n int) (pointer, int) {
	top := len(s.data) - 1
	p := pointer((uint64(top) << 32) | uint64(len(s.data[top].space)))
	if n == 0 {
		return p, 0
	}
	m := (n + 63) &^ 63
	s.data[top].space = append(s.data[top].space, make([]byte, m)...)
	return p, m
}

func (s *Stack) shrink(n int) {
	if n == 0 {
		return
	}
	s.data[0].space = s.data[0].space[:len(s.data[0].space) - n]
}

func (s *Stack) toPointer(p * pointer) (pointer, error) {
	d,err := s.toInt64(p)
	return pointer(d), err
}

func (s *Stack) toByte(p * pointer) (byte, error) {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset < len(s.data[area].space) {
		return s.data[area].space[offset], nil
	}
	return 0, outofmemory
}

func (s *Stack) toBytes(p * pointer) ([]byte, error) {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset < len(s.data[area].space) {
		return s.data[area].space[offset:], nil
	}
	return nil, outofmemory
}

func (s *Stack) toInt16(p * pointer) (int16, error) {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset + 1 < len(s.data[area].space) {
		return (int16(s.data[area].space[offset])) | ((int16(s.data[area].space[offset + 1])) << 8), nil
	}
	return 0, outofmemory
}

func (s *Stack) toInt32(p * pointer) (int32, error) {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset + 3 < len(s.data[area].space) {
		return (int32(s.data[area].space[offset])) |
			((int32(s.data[area].space[offset + 1])) << 8) |
			((int32(s.data[area].space[offset + 2])) << 16) |
			((int32(s.data[area].space[offset + 3])) << 24), nil
	}
	return 0, outofmemory
}

func (s *Stack) toInt64(p * pointer) (int64, error) {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset + 7 < len(s.data[area].space) {
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

func (s *Stack) toHash(p * pointer) (chainhash.Hash, error) {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset + 255 < len(s.data[area].space) {
		h,_ := chainhash.NewHash(s.data[area].space[offset:offset + 32])
		return *h, nil
	}
	return chainhash.Hash{}, outofmemory
}

func (s *Stack) savePointer(p * pointer, d pointer) error {
	return s.saveInt64(p, int64(d))
}

func (s *Stack) saveByte(p * pointer, b byte) error {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset < len(s.data[area].space) {
		s.data[area].space[offset] = b
		return nil
	}
	return outofmemory
}

func (s *Stack) saveBytes(p * pointer, b []byte) error {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset < len(s.data[area].space) {
		copy(s.data[area].space[offset:], b)
		return nil
	}
	return outofmemory
}

func (s *Stack) saveInt16(p * pointer, b int16) error {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset + 1 < len(s.data[area].space) {
		s.data[area].space[offset] = byte(b)
		s.data[area].space[offset + 1] = byte(b >> 8)
		return nil
	}
	return outofmemory
}

func (s *Stack) saveInt32(p * pointer, b int32) error {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset + 3 < len(s.data[area].space) {
		for i := 0; i < 4; i++ {
			s.data[area].space[offset + i] = byte(b >> (8 * i))
		}
		return nil
	}
	return outofmemory
}

func (s *Stack) saveInt64(p * pointer, b int64) error {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset + 7 < len(s.data[area].space) {
		for i := 0; i < 8; i++ {
			s.data[area].space[offset + i] = byte(b >> (8 * i))
		}
		return nil
	}
	return outofmemory
}

func (s *Stack) saveHash(p * pointer, h chainhash.Hash) error {
	offset := int(*p & 0xFFFFFFFF)
	area := int(*p >> 32)
	if area < len(s.data) && offset + 255 < len(s.data[area].space) {
		copy(s.data[area].space[offset:], h[:])
		return nil
	}
	return outofmemory
}

func Newstack() *Stack {
	s := &Stack{data: make([]*frame, 1)}
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
