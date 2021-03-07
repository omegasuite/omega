/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import (
	"encoding/binary"
//	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
)

const (
	// defaultScriptAlloc is the default size used for the backing array
	// for a script being built by the ScriptBuilder.  The array will
	// dynamically grow as needed, but this figure is intended to provide
	// enough space for vast majority of scripts without needing to grow the
	// backing array multiple times.
	defaultScriptAlloc = 500
)

// ErrScriptNotCanonical identifies a non-canonical script.  The caller can use
// a type assertion to detect this error type.
type ErrScriptNotCanonical string

// Error implements the error interface.
func (e ErrScriptNotCanonical) Error() string {
	return string(e)
}

// ScriptBuilder provides a facility for building custom scripts.  It allows
// you to push opcodes, ints, and Data while respecting canonical encoding.  In
// general it does not ensure the script will execute correctly, however any
// Data pushes which would exceed the maximum allowed script engine limits and
// are therefore guaranteed not to execute will not be pushed and will result in
// the Script function returning an error.
//
// For example, the following would build a 2-of-3 multisig script for usage in
// a pay-to-script-hash (although in this situation MultiSigScript() would be a
// better choice to generate the script):
// 	builder := txscript.NewScriptBuilder()
// 	builder.AddOp(txscript.OP_2).AddData(pubKey1).AddData(pubKey2)
// 	builder.AddData(pubKey3).AddOp(txscript.OP_3)
// 	builder.AddOp(txscript.OP_CHECKMULTISIG)
// 	script, err := builder.Script()
// 	if err != nil {
// 		// Handle the error.
// 		return
// 	}
// 	fmt.Printf("Final multi-sig script: %x\n", script)
type ScriptBuilder struct {
	script []inst
}

func NewScriptBuilder() *ScriptBuilder {
	return &ScriptBuilder{ script: make([]inst, 0) }
}

func (s * ScriptBuilder) AddScript(t []inst) * ScriptBuilder {
	s.script = append(s.script, t[:]...)
	return s
}

func (s * ScriptBuilder) AddInt64(t int64) * ScriptBuilder {
	var h [8]byte
	binary.LittleEndian.PutUint64(h[:], uint64(t))
	s.script[len(s.script) - 1].param = append(s.script[len(s.script) - 1].param, h[:]...)
	return s
}

func (s * ScriptBuilder) AddInt32(t int32) * ScriptBuilder {
	var h [4]byte
	binary.LittleEndian.PutUint32(h[:], uint32(t))
	s.script[len(s.script) - 1].param = append(s.script[len(s.script) - 1].param, h[:]...)
	return s
}

func (s * ScriptBuilder) AddInt16(t int16) * ScriptBuilder {
	var h [2]byte
	binary.LittleEndian.PutUint16(h[:], uint16(t))
	s.script[len(s.script) - 1].param = append(s.script[len(s.script) - 1].param, h[:]...)
	return s
}

func (s * ScriptBuilder) AddByte(t byte) * ScriptBuilder {
	s.script[len(s.script) - 1].param = append(s.script[len(s.script) - 1].param, t)
	return s
}

func (s * ScriptBuilder) AddHash(t chainhash.Hash) * ScriptBuilder {
	s.script[len(s.script) - 1].param = append(s.script[len(s.script) - 1].param, t[:]...)
	return s
}

func (s * ScriptBuilder) AddBytes(t []byte) * ScriptBuilder {
	s.script[len(s.script) - 1].param = append(s.script[len(s.script) - 1].param, t[:]...)
	return s
}

func (s * ScriptBuilder) AddOp(t OpCode, data []byte) * ScriptBuilder {
	s.script = append(s.script, inst{op: t, param: data})
	return s
}

func (s * ScriptBuilder) Script() []byte {
	n := 0
	for i, c := range s.script {
		if c.op == PUSH {
			s.script[i].param[0] = byte(len(s.script[i].param) - 1)
		} else if c.op == SIGNTEXT {
			s.script[i].param = s.script[i].param[:1]
		}
		n += len(s.script[i].param) + 1
	}
	r := make([]byte, n)
	n = 0
	for _, c := range s.script {
		r[n] = byte(c.op)
		copy(r[n+1:], c.param)
		n += len(c.param) + 1
	}
	return r
}

func PushedData(s []byte) [][]byte {
	res := make([][]byte, 0, 2)
	for p := 0; p < len(s); {
		switch OpCode(s[p]) {
		case PUSH:
			res = append(res, s[p+2:p+2+int(s[p+1])])
			p += 2 + int(s[p+1])

		case SIGNTEXT:
			p += 2
		}
	}
	return res
}