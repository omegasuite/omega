// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

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
// you to push opcodes, ints, and data while respecting canonical encoding.  In
// general it does not ensure the script will execute correctly, however any
// data pushes which would exceed the maximum allowed script engine limits and
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
	script []byte
}

func NewScriptBuilder() *ScriptBuilder {
	return &ScriptBuilder{ script: make([]byte, 0) }
}

/*
func (s * ScriptBuilder) AddScript(t []byte) * ScriptBuilder {
	s.script = append(s.script, t[:]...)
	return s
}

func (s * ScriptBuilder) AddInt(t int) * ScriptBuilder {
	var u [4]byte
	s.script = append(s.script, byte(ovm.PUSH4))
	binary.LittleEndian.PutUint32(u[:], uint32(t))
	s.script = append(s.script, u[:]...)
	return s
}

func (s * ScriptBuilder) AddData(t []byte) * ScriptBuilder {
	p,n := 0,len(t)
	for ; n >= 32; n -= 32 {
		s.script = append(s.script, byte(ovm.PUSH32))
		s.script = append(s.script, t[p : p + 32]...)
		p += 32
	}
	if n != 0 {
		s.script = append(s.script, byte(int(ovm.PUSH1) + n - 1))
		s.script = append(s.script, t[p:]...)
	}

	return s
}

func (s * ScriptBuilder) AddOp(t byte, data []byte) * ScriptBuilder {
	s.script = append(s.script, byte(ovm.ADDSIGNTEXT))
	s.script = append(s.script, t)
	if t > 4 {		// would cause panic
		return nil
	}
	switch t {
	case 2, 3, 4: // matching outpoint // matching input // script
		if len(data) >= 256 {
			return nil
		}
		s.script = append(s.script, byte(len(data)))
		s.script = append(s.script, data...)
	}
	return s
}

func (s * ScriptBuilder) Script() []byte {
	return s.script
}
*/