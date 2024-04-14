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
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega"
	"sync/atomic"

	"bytes"
	"encoding/binary"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
)

type vunit struct {
	data, text []byte
	mode       SigHashType
}

// PrecompiledContract is the basic interface for native Go contracts.
type PrecompiledContract interface {
	Run(input []byte, vunits []vunit) ([]byte, omega.Err) // Run runs the precompiled contract
}

// Create creates a new contract
type create struct {
	ovm      *OVM
	contract *Contract
}

type meta struct {
	ovm      *OVM
	contract *Contract
}

type codebytes struct {
	ovm      *OVM
	contract *Contract
}

const (
	OP_CREATE    = 0
	OP_META      = 1
	OP_CODEBYTES = 2
	OP_OWNER     = 0x10 // User supplied standard func. returns address of contract owner
	OP_INIT      = 1    // User supplied standard func. for lib initialization. it's ok to
	// hasve the same value as op meta because init is called automatically
	// by lib load as a function of contract, while meta is called by user
	// and intercepted by vm as a system call

	OP_PUBLIC = 0x20 // codes below are public func callable by anyone

	PAYFUNC_MIN = 0x41
	PAYFUNC_MAX = 0x46

	OP_PAY2PKH     = 0x41
	OP_PAY2SCRIPTH = 0x42
	OP_PAYMULTISIG = 0x43
	//	OP_PAY2MULTIPKH			= 0x43
	//	OP_PAY2MULTISCRIPTH		= 0x44
	OP_PAY2NONE = 0x45
	OP_PAY2ANY  = 0x46
)

// PrecompiledContracts contains the default set of pre-compiled contracts
var PrecompiledContracts = map[[4]byte]func(evm *OVM, contract *Contract) PrecompiledContract{
	([4]byte{OP_CREATE, 0, 0, 0}): func(evm *OVM, contract *Contract) PrecompiledContract {
		return &create{evm, contract}
	}, // create a contract
	([4]byte{OP_META, 0, 0, 0}): func(evm *OVM, contract *Contract) PrecompiledContract {
		contract.Code = nil
		return &meta{evm, contract}
	}, // meta
	([4]byte{OP_CODEBYTES, 0, 0, 0}): func(evm *OVM, contract *Contract) PrecompiledContract {
		contract.Code = nil
		return &codebytes{evm, contract}
	}, // OP_CODEBYTES
	// pk script functions
	([4]byte{OP_PAY2PKH, 0, 0, 0}): func(evm *OVM, contract *Contract) PrecompiledContract {
		return &pay2pkh{}
	}, // pay to pubkey hash script
	([4]byte{OP_PAY2SCRIPTH, 0, 0, 0}): func(evm *OVM, contract *Contract) PrecompiledContract {
		return &pay2scripth{}
	}, // pay to script hash script
	([4]byte{OP_PAYMULTISIG, 0, 0, 0}): func(evm *OVM, contract *Contract) PrecompiledContract {
		return &pay2multisig{evm, contract}
	}, // pay to multi-sig script
	//	([4]byte{OP_PAY2MULTIPKH, 0, 0, 0}): &pay2pkhs{},		// pay to pubkey hash script, multi-sig
	//	([4]byte{OP_PAY2MULTISCRIPTH, 0, 0, 0}): &pay2scripths{},		// pay to no one and spend it
	([4]byte{OP_PAY2NONE, 0, 0, 0}): func(evm *OVM, contract *Contract) PrecompiledContract {
		return &payreturn{}
	}, // pay to no one and burn it
	([4]byte{OP_PAY2ANY, 0, 0, 0}): func(evm *OVM, contract *Contract) PrecompiledContract {
		return &payanyone{}
	}, // pay to anyone
}

type payanyone struct{}

func (p *payanyone) Run(input []byte, vunits []vunit) ([]byte, omega.Err) {
	return []byte{1}, nil
}

type payreturn struct{}

func (p *payreturn) Run(input []byte, vunits []vunit) ([]byte, omega.Err) {
	// spend it !!!
	return []byte{0}, nil
}

type pay2multisig struct {
	ovm      *OVM
	contract *Contract
}

// multiple address multiple key
func (p *pay2multisig) Run(input []byte, vunits []vunit) ([]byte, omega.Err) {
	_, b, hash, e := p.run(vunits)
	//	m := common.LittleEndian.Uint16(input[20:])

	if e != nil {
		return []byte{0}, e
	}
	if !b || bytes.Compare(input[:20], hash) != 0 {
		return []byte{0}, nil
	}
	return []byte{1}, e
}

func (p *pay2multisig) run(vunits []vunit) (int, bool, []byte, omega.Err) {
	// input - hash of multi-sig descriptor (20-byte value)
	// vunits[0].Data: multi-sig descriptor
	//			 bytes 0 - 1: M - number of scripts
	//			 bytes 2 - 3: N - number of signatures required
	// vunits[1:].Data: lock script, or P2SH script + script text, or public key + signature
	// vunits[1:].text - text to be signed (in chucks of 0-padded 32-bytes units)

	// in forfeit mode, all contract calls will pass
	genericerr := omega.ScriptError(omega.ErrInternal, "Multisignature format error")

	if len(vunits[0].data) != 4 {
		return 0, false, nil, genericerr
	}
	m := int(common.LittleEndian.Uint16(vunits[0].data[:2]))
	n := int(common.LittleEndian.Uint16(vunits[0].data[2:]))

	b, x, y, z := p.hashval(m, n, vunits[1:])
	return x, b, y, z
}

func (p *pay2multisig) hashval(m int, n int, vunits []vunit) (bool, int, []byte, omega.Err) {
	sigcnt := 0
	h := make([]byte, 0, 21*m+5)
	h = append(h, byte(PUSH))
	h = append(h, 4)

	var d [4]byte
	common.LittleEndian.PutUint16(d[:], uint16(m))
	common.LittleEndian.PutUint16(d[2:], uint16(n))

	h = append(h, d[:]...)
	h = append(h, []byte{byte(SIGNTEXT), 0}...)

	genericerr := omega.ScriptError(omega.ErrInternal, "Multisignature format error")

	i := 0

	for ; i < len(vunits) && m > 0; i++ {
		v := vunits[i]
		if len(v.data) == 0 {
			continue
		}
		m--
		if len(v.data) == 1 && v.data[0] == p.ovm.chainConfig.MultiSigAddrXID {
			// redeem script for recursive multisig
			x, b, hash, err := p.run(vunits[i+1:])
			if err != nil {
				return false, 0, nil, err
			}

			if b {
				sigcnt++
			}
			h = append(h, []byte{byte(PUSH), 21}...)
			h = append(h, p.ovm.chainConfig.MultiSigAddrID)
			h = append(h, hash...)
			h = append(h, []byte{byte(SIGNTEXT), 0}...)
			i += x
			continue
		} else if len(v.data) == 21 && (v.data[0] == p.ovm.chainConfig.MultiSigAddrID || v.data[0] == p.ovm.chainConfig.PubKeyHashAddrID ||
			v.data[0] == p.ovm.chainConfig.ScriptHashAddrID) {
			// recursive multisig
			h = append(h, []byte{byte(PUSH), 21}...)
			h = append(h, v.data...)
			h = append(h, []byte{byte(SIGNTEXT), 0}...)
			continue
		} else if v.data[0] == 0 && v.data[3] == p.ovm.chainConfig.ScriptAddrID {
			h = append(h, []byte{byte(PUSH), 21}...)
			m := int(common.LittleEndian.Uint16(v.data[1:3]))

			hash := chainhash.HashB(v.data[4 : m+3])
			ph := btcutil.Hash160(hash)
			h = append(h, p.ovm.chainConfig.ScriptHashAddrID)
			h = append(h, ph...)
			h = append(h, []byte{byte(SIGNTEXT), 0}...)
			sigcnt++ // assume a match, if not, it will result in a mismatch in final hash/address
			continue
		}

		// if not any case above, it must be a pubkey hash signature script
		inlen := len(v.data)

		kpos := int(v.data[0]) + 1
		pkBytes := v.data[1:kpos]

		siglen := v.data[kpos]
		kpos++

		if siglen == 0 {
			return false, 0, nil, genericerr
		}

		if inlen < kpos+int(siglen) {
			return false, 0, nil, genericerr
		}

		sigBytes := v.data[kpos : kpos+int(siglen)]

		pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
		if err != nil {
			return false, 0, nil, omega.ScriptError(omega.ErrInternal, err.Error())
		}

		var signature *btcec.Signature

		signature, err = btcec.ParseSignature(sigBytes, btcec.S256())

		if err != nil {
			return false, 0, nil, omega.ScriptError(omega.ErrInternal, err.Error())
		}

		hash := chainhash.DoubleHashB(v.text)
		valid := signature.Verify(hash, pubKey)

		if valid {
			sigcnt++
		}

		h = append(h, []byte{byte(PUSH), 21}...)

		ph := btcutil.Hash160(pkBytes)
		h = append(h, p.ovm.chainConfig.PubKeyHashAddrID)
		h = append(h, ph...)
		h = append(h, []byte{byte(SIGNTEXT), 0}...)
	}
	//	h = append(h, []byte{byte(SIGNTEXT), byte(SigMultiSigMark)}...)

	hash := btcutil.Hash160(h)

	return sigcnt >= n, i, hash, nil
}

type pay2scripth struct{}

func (p *pay2scripth) Run(input []byte, _ []vunit) ([]byte, omega.Err) {
	// All input fields are 32-byte padded
	// input: pkh - script hash (32-bytes)
	//	      text - script

	pkh := input[:20]

	l := binary.LittleEndian.Uint32(input[20:])
	text := input[24 : 24+l]

	hash := btcutil.Hash160(text)
	//	hash := Hash160(text)

	if bytes.Compare(hash[:], pkh[:]) == 0 {
		return []byte{1}, nil
	}
	return []byte{0}, nil
}

// bit coin pkscripts
// P2PKH pay_to_public_key_hash: OP_DUP OP_HASH160 hash(pubkey) OP_EQUALVERIFY OP_CHECKSIG
// P2SH pay_to_script_hash: OP_HASH160 hash(Redeem script) OP_EQUAL
// P2PK pay_to_public_key: <pubkey> OP_CHECKSIG
// P2WPKH pay_to_witness_public_key_hash: 0 HASH160(public key)
// P2WSH pay_to_witness_script_hash: 0 SHA256(redeem script)
// 签名放在 Tx 的SignatureScripts中,因此sign-all签名应该是对hash(Version,LockTime, outpoint of current TxIn,all TxOut)) 进行签名

type pay2pkh struct{}

func (p *pay2pkh) Run(input []byte, vunits []vunit) ([]byte, omega.Err) {
	// vunits: input - public key hash (20-byte value)
	//		  publick key
	//		  signature
	//	      text - text to be signed (in chucks of 0-padded 32-bytes units)
	if len(input) < 20 {
		return []byte{0}, nil
	}

	pkh := input[:20]

	//		  publick key
	pos := vunits[0].data[0] + 1
	pkBytes := vunits[0].data[1:pos]

	pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
	if err != nil {
		return []byte{0}, nil
	}

	ph := btcutil.Hash160(pkBytes)
	//	ph := Hash160(pkBytes)

	if bytes.Compare(ph[:], pkh[:]) != 0 {
		return []byte{0}, nil
	}

	//		  signature
	siglen := vunits[0].data[pos]
	sigBytes := vunits[0].data[pos+1 : pos+siglen+1]

	//	pos += siglen + 1

	// Generate the signature hash based on the signature hash type.
	hash := chainhash.DoubleHashB(vunits[0].text)

	var signature *btcec.Signature

	signature, err = btcec.ParseSignature(sigBytes, btcec.S256())

	if err != nil {
		return []byte{0}, nil
	}

	valid := signature.Verify(hash, pubKey)

	if valid {
		return []byte{1}, nil
	}
	return []byte{0}, nil
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
func (in *Interpreter) RunPrecompiledContract(p PrecompiledContract, input []byte, contract *Contract) (ret []byte, err omega.Err) {
	var (
		op    OpCode       // current opcode
		stack = Newstack() // local stack
		pc    = int(0)     // program counter
	)

	vuints := make([]vunit, 0) // verification unit, generated for each SIGNTEXT inst

	if len(contract.Code) != 0 {
		// Reset the previous call's return Data. It's unimportant to preserve the old buffer
		// as every returning call will return new Data anyway.
		var res []byte

	ret:
		for atomic.LoadInt32(&in.evm.abort) == 0 {
			// Get the operation from the jump table and validate the stack to ensure there are
			// enough stack items available to perform the operation.
			op = contract.GetOp(pc)
			operation := in.JumpTable[op]
			if !operation.valid {
				return nil, omega.ScriptError(omega.ErrInternal, fmt.Sprintf("invalid opcode 0x%x", int(op)))
			}

			if operation.writes {
				return nil, omega.ScriptError(omega.ErrInternal, "State modification is not allowed")
			}
			if operation.jumps {
				return nil, omega.ScriptError(omega.ErrInternal, fmt.Sprintf("invalid opcode 0x%x", int(op)))
			}

			// execute the operation
			v := vunit{}
			if op == SIGNTEXT {
				// prev op is SIGNTEXT
				ln := binary.LittleEndian.Uint32(stack.data[0].space)

				if ln > 0 {
					v.data = make([]byte, ln)
					copy(v.data, stack.data[0].space[4:ln+4])
				} else {
					v.data = make([]byte, 0)
				}
				v.mode = SigHashType(contract.GetOp(pc + 1))

				stack.data[0].space = stack.data[0].space[:4]
				copy(stack.data[0].space, []byte{0, 0, 0, 0})
			}

			err := operation.execute(&pc, in.evm, contract, stack)

			if op == SIGNTEXT {
				// current op is SIGNTEXT
				ln := binary.LittleEndian.Uint32(stack.data[0].space)

				if ln > 0 {
					v.text = make([]byte, ln)
					copy(v.text, stack.data[0].space[4:ln+4])
				} else {
					v.text = make([]byte, 0)
				}

				vuints = append(vuints, v)

				stack.data[0].space = stack.data[0].space[:4]
				copy(stack.data[0].space, []byte{0, 0, 0, 0})
			}

			switch {
			case err != nil:
				return nil, err
			case operation.halts:
				break ret
			default:
				pc++
			}
		}

		ln := binary.LittleEndian.Uint32(stack.data[0].space)

		if ln > 0 {
			res = stack.data[0].space[4 : ln+4]
		} else {
			res = stack.data[0].space[4:]
		}

		input = append(input, res...)
	}
	return p.Run(input, vuints)
}

func (c *create) Run(input []byte, _ []vunit) ([]byte, omega.Err) {
	return c.ovm.Create(input[4:], c.contract)
}

func (c *meta) Run(input []byte, _ []vunit) ([]byte, omega.Err) {
	return c.ovm.GetMeta(c.contract.self.Address(), string(input[4:])), nil
}

func (c *codebytes) Run(input []byte, _ []vunit) ([]byte, omega.Err) {
	return c.ovm.GetCode(c.contract.self.Address()), nil
}
