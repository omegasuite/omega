package ovm

import (
	"fmt"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/btcutil"
	"sync/atomic"

	"bytes"
	"encoding/binary"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	//	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/omega/token"
)

type vunit struct {
	data, text []byte
}

// PrecompiledContract is the basic interface for native Go contracts.
type PrecompiledContract interface {
	Run(input []byte, vunits []vunit) ([]byte, error) // Run runs the precompiled contract
}

// Create creates a new contract
type create struct {
	ovm * OVM
	contract *Contract
}

type meta struct {
	ovm * OVM
	contract *Contract
}

const (
	OP_CREATE				= 0
	OP_META					= 1
//	OP_MINT					= 0x40

	PAYFUNC_MIN				= 0x41
	PAYFUNC_MAX				= 0x46

	OP_PAY2PKH				= 0x41
	OP_PAY2SCRIPTH			= 0x42
	OP_PAYMULTISIG			= 0x43
//	OP_PAY2MULTIPKH			= 0x43
//	OP_PAY2MULTISCRIPTH		= 0x44
	OP_PAY2NONE				= 0x45
	OP_PAY2ANY				= 0x46
)

// PrecompiledContracts contains the default set of pre-compiled contracts
var PrecompiledContracts = map[[4]byte]func(evm * OVM, contract *Contract) PrecompiledContract {
	([4]byte{OP_CREATE, 0, 0, 0}): func(evm * OVM, contract *Contract) PrecompiledContract {
		return &create{evm, contract}
	},			// create a contract
	([4]byte{OP_META, 0, 0, 0}): func(evm * OVM, contract *Contract) PrecompiledContract {
		return &meta{evm, contract}
	},			// meta
	// pk script functions
	([4]byte{OP_PAY2PKH, 0, 0, 0}): func(evm * OVM, contract *Contract) PrecompiledContract {
		return &pay2pkh{}
	}, 			// pay to pubkey hash script
	([4]byte{OP_PAY2SCRIPTH, 0, 0, 0}): func(evm * OVM, contract *Contract) PrecompiledContract {
		return &pay2scripth{}
	},			// pay to script hash script
	([4]byte{OP_PAYMULTISIG, 0, 0, 0}): func(evm * OVM, contract *Contract) PrecompiledContract {
		return &pay2multisig{evm, contract}
	},			// pay to script hash script
//	([4]byte{OP_PAY2MULTIPKH, 0, 0, 0}): &pay2pkhs{},		// pay to pubkey hash script, multi-sig
//	([4]byte{OP_PAY2MULTISCRIPTH, 0, 0, 0}): &pay2scripths{},		// pay to no one and spend it
	([4]byte{OP_PAY2NONE, 0, 0, 0}): func(evm * OVM, contract *Contract) PrecompiledContract {
		return &payreturn{}
	},			// pay to no one and burn it
	([4]byte{OP_PAY2ANY, 0, 0, 0}): func(evm * OVM, contract *Contract) PrecompiledContract {
		return &payanyone{}
	},			// pay to anyone
}

type payanyone struct {}

func (p *payanyone) Run(input []byte, vunits []vunit) ([]byte, error) {
	return []byte{1}, nil
}

type payreturn struct {}

func (p *payreturn) Run(input []byte, vunits []vunit) ([]byte, error) {
	// spend it !!!
	return []byte{0}, nil
}

type pay2multisig struct {
	ovm * OVM
	contract *Contract
}

// multiple address multiple key
func (p *pay2multisig) Run(input []byte, vunits []vunit) ([]byte, error) {
	// input: pkh - multi-sig descriptor (2 + 4M-byte value)
	//		     byte 0 - M - 1 (max 18)
	//			 byte 1 - N - 1 (N <= M)
	//			 bytes 2 - 2+4M: 32-bit ints for length of a script
	//		  M public key hash address (each 25-byte value) or contract calls (var length)
	// vunits: vunit from sig script
	//		  data: public key-signature pairs
	//	      text: text to be signed

	pks := make([][]byte, 0)
	contracts := make([][]byte, 0)

	m := int(input[0])
	n := int(input[1])
	if m > 18 || len(input) < 21 * m + 2 + 4 * m {
		return []byte{0}, nil	// never. should have been verified in tx validity
	}

	scriptlens := make([]uint32, m)
	for i := 0; i < m; i++ {
		scriptlens[i] = common.LittleEndian.Uint32(input[2 + 4 * i:])
	}

	sigcnt := 0

	pos := 2 + 4 * m
	for i := 1; i < m; i++ {
		if input[pos] == p.ovm.chainConfig.PubKeyHashAddrID {
			if scriptlens[i] != 21 {
				return []byte{0}, nil	// never. should have been verified in tx validity
			}
			var k [20]byte
			copy(k[:], input[pos + 1:])
			pks = append(pks, k[:])
			pos += 21
		} else if input[pos] == p.ovm.chainConfig.ContractAddrID {
			contracts = append(contracts, input[pos:pos + int(scriptlens[i])])
			pos += int(scriptlens[i])
		} else if input[pos] == p.ovm.chainConfig.MultiSigAddrID {
			k := pos + 1
			mm := int(input[k])
			for j := 0; j < mm; j++ {
				k += int(common.LittleEndian.Uint32(input[k + 2 + 4*j:]))
			}
			r,_ := p.Run(input[pos + 1:k], vunits)
			if r[0] == 1 {
				sigcnt++
			}
			pos = k
		}
	}

	for _,v := range vunits {
		inlen := len(v.data)

		kpos := int(v.data[0]) + 1
		pkBytes := v.data[1:kpos]

		siglen := v.data[kpos]
		kpos++

		if siglen == 0 {
			continue
		}

		if inlen < kpos + int(siglen) {
			return []byte{0}, nil
		}

		sigBytes := v.data[kpos : kpos+int(siglen)]

		pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
		if err != nil {
			return []byte{0}, nil
		}

		ph := Hash160(pkBytes)
		matched := false
		for i, k := range pks {
			if bytes.Compare(ph[:], k) == 0 {
				pks = append(pks[:i], pks[i+1:]...)
				matched = true
				break
			}
		}

		if !matched {
			continue
		}

		var signature *btcec.Signature

		signature, err = btcec.ParseSignature(sigBytes, btcec.S256())

		if err != nil {
			return []byte{0}, nil
		}

		hash := chainhash.DoubleHashB(v.text)
		valid := signature.Verify(hash, pubKey)

		if valid {
			sigcnt++
		}
	}

	if sigcnt >= n {
		return []byte{1}, nil
	}

	if len(contracts) < n - sigcnt {
		return []byte{0}, nil
	}

	// run smart contracts
	vm := NewOVM(p.ovm.chainConfig)
	vm.writeback = false

	vm.GetCoinBase = func () * btcutil.Tx { return nil }
	vm.GetTx = func () * btcutil.Tx { return nil }
	vm.AddTxOutput = func(t wire.TxOut) int { return -1 }
	vm.Spend = func(t wire.OutPoint) bool {	return false }
	vm.AddRight = func(t token.Definition, coinbase bool) chainhash.Hash {
		return chainhash.Hash{}
	}
	vm.GetUtxo = func(hash chainhash.Hash, seq uint64) *wire.TxOut { return nil	}
	vm.BlockNumber = func() uint64 { return 0 }
	vm.BlockTime = func() uint32 { return 0 }
	vm.GetCurrentOutput = func() wire.OutPoint { return wire.OutPoint{} }
	vm.AddCoinBase = func(wire.TxOut) wire.OutPoint { return wire.OutPoint{} }
	vm.GasLimit    = 100000
	vm.Block 	= func() * btcutil.Block { return nil }

	vm.NoLoop = false
	vm.interpreter.readOnly = false

	for _,c := range contracts {
		t := token.Token{}
		var a Address
		copy(a[:], c[1:21])
		t.TokenType = 0
		t.Value = &token.NumToken{Val: -1}
		r, err := vm.Call(a, c[21:25], &t, c[25:])
		if err != nil || r == nil || r[0] == 0 {
			continue
		}
		sigcnt++
		if sigcnt >= n {
			return []byte{1}, nil
		}
	}

	return []byte{0}, nil
}

/*
type pay2pkhs struct {}
type pay2scripths struct {}

// single address multiple key
func (p *pay2scripths) Run(input []byte, vunits []vunit) ([]byte, error) {
	// input: pkh - public key hash (20-byte value)
	//		  N:M - bytes 0-4 = M, bytes 4-8 = N (M >= N)
	// vunits: M vunit
	//		  data: publick key-signature pairs
	//	      text: text to be signed

	pkh := make([]byte, 0)
	
	m := int(binary.LittleEndian.Uint32(input[20:]))
	n := int(binary.LittleEndian.Uint32(input[24:]))
	
	if len(vunits) != m {
		return []byte{0}, nil
	}

	sigcnt := 0

	for _,v := range vunits {
		inlen := len(v.data)

		kpos := int(v.data[0]) + 1
		pkBytes := v.data[1:kpos]

		pkh = append(pkh, pkBytes...)

		siglen := input[kpos]
		kpos++

		if siglen == 0 {
			continue
		}

		if inlen < kpos + int(siglen) {
			return []byte{0}, nil
		}

		sigBytes := input[kpos : kpos+int(siglen)]

		pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
		if err != nil {
			return []byte{0}, nil
		}

		var signature *btcec.Signature

		signature, err = btcec.ParseSignature(sigBytes, btcec.S256())

		if err != nil {
			return []byte{0}, nil
		}

		hash := chainhash.DoubleHashB(v.text)
		valid := signature.Verify(hash, pubKey)

		if valid {
			sigcnt++
		}
	}

	if sigcnt < n {
		return []byte{0}, nil
	}

	ph := Hash160(pkh)
	if bytes.Compare(ph[:], input[:20]) != 0 {
		return []byte{0}, nil
	}

	return []byte{1}, nil
}

// multiple address multiple key
func (p *pay2pkhs) Run(input []byte, vunits []vunit) ([]byte, error) {
	// input: pkh - public key hash (20-byte value)
	//		  N:M - bytes 0-4 = M, bytes 4-8 = N (M >= N)
	//		  (M - 1) public key hashes (each 30-byte value)
	// vunits: M vunit
	//		  data: publick key-signature pairs
	//	      text: text to be signed

	pks := [][]byte{input[:20]}

	m := int(binary.LittleEndian.Uint32(input[20:]))
	n := int(binary.LittleEndian.Uint32(input[24:]))
	
	if len(input) < 8 + 20 * m {
		return []byte{0}, nil
	}

	pos := 28
	for i := 1; i < m; i++ {
		var k [20]byte
		copy(k[:], input[pos:])
		pks = append(pks, k[:])
		pos += 20
	}

	sigcnt := 0

	for _,v := range vunits {
		inlen := len(v.data)

		kpos := int(v.data[0]) + 1
		pkBytes := v.data[1:kpos]
		
		siglen := input[kpos]
		kpos++

		if siglen == 0 {
			continue
		}

		if inlen < kpos + int(siglen) {
			return []byte{0}, nil
		}

		sigBytes := input[kpos : kpos+int(siglen)]
		
		pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
		if err != nil {
			return []byte{0}, nil
		}
		
		ph := Hash160(pkBytes)
		matched := false
		for i, k := range pks {
			if bytes.Compare(ph[:], k) == 0 {
				pks = append(pks[:i], pks[i+1:]...)
				matched = true
				break
			}
		}
		
		if !matched {
			continue
		}

		var signature *btcec.Signature

		signature, err = btcec.ParseSignature(sigBytes, btcec.S256())

		if err != nil {
			return []byte{0}, nil
		}
		
		hash := chainhash.DoubleHashB(v.text)
		valid := signature.Verify(hash, pubKey)

		if valid {
			sigcnt++
		}
	}

	if sigcnt < n {
		return []byte{0}, nil
	}

	return []byte{1}, nil
}
 */

type pay2scripth struct {}

func (p *pay2scripth) Run(input []byte, _ []vunit) ([]byte, error) {
	// All input fields are 32-byte padded
	// input: pkh - script hash (32-bytes)
	//	      text - script

	pkh := input[:20]

	l := binary.LittleEndian.Uint32(input[20:])
	text := input[24:24+l]

	hash := Hash160(text)

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

type pay2pkh struct {}

func (p *pay2pkh) Run(input []byte, vunits []vunit) ([]byte, error) {
	// vunits: pkh - public key hash (20-byte value)
	//		  publick key
	//		  signature
	//	      text - text to be signed (in chucks of 0-padded 32-bytes units)

	pkh := input[:20]

	pos := vunits[0].data[0] + 1
	pkBytes := vunits[0].data[1:pos]

	pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
	if err != nil {
		return []byte{0}, nil
	}

	ph := Hash160(pkBytes)

	if bytes.Compare(ph[:], pkh[:]) != 0 {
		return []byte{0}, nil
	}

	siglen := vunits[0].data[pos]

	sigBytes := vunits[0].data[pos + 1:pos + siglen + 1]

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
func (in *Interpreter) RunPrecompiledContract(p PrecompiledContract, input []byte, contract *Contract) (ret []byte, err error) {
	var (
		op    OpCode        // current opcode
		stack = Newstack()  // local stack
		pc   = int(0) // program counter
	)

	vuints := make([]vunit, 0)	// verification unit, generated for each SIGNTEXT inst
	
	if len(contract.Code) != 0 {
		// Reset the previous call's return data. It's unimportant to preserve the old buffer
		// as every returning call will return new data anyway.
		var res []byte

	ret:
		for atomic.LoadInt32(&in.evm.abort) == 0 {
			// Get the operation from the jump table and validate the stack to ensure there are
			// enough stack items available to perform the operation.
			op = contract.GetOp(pc)
			operation := in.JumpTable[op]
			if !operation.valid {
				return nil, fmt.Errorf("invalid opcode 0x%x", int(op))
			}

			if operation.writes {
				return nil, fmt.Errorf("State modification is not allowed")
			}
			if operation.jumps {
				return nil, fmt.Errorf("invalid opcode 0x%x", int(op))
			}

			// execute the operation
			v := vunit{}
			if op == SIGNTEXT {
				ln := binary.LittleEndian.Uint32(stack.data[0].space)

				if ln > 0 {
					v.data = make([]byte, ln)
					copy(v.data, stack.data[0].space[4:ln + 4])
				} else {
					v.data = make([]byte, 0)
				}

				stack.data[0].space = stack.data[0].space[:4]
				copy(stack.data[0].space, []byte{0,0,0,0})
			}

			err := operation.execute(&pc, in.evm, contract, stack)

			if op == SIGNTEXT {
				ln := binary.LittleEndian.Uint32(stack.data[0].space)

				if ln > 0 {
					v.text = make([]byte, ln)
					copy(v.text, stack.data[0].space[4:ln + 4])
				} else {
					v.text = make([]byte, 0)
				}

				vuints = append(vuints, v)

				stack.data[0].space = stack.data[0].space[:4]
				copy(stack.data[0].space, []byte{0,0,0,0})
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
			res = stack.data[0].space[4:ln + 4]
		} else {
			res = stack.data[0].space[4:]
		}

		input = append(input, res...)
	}
	return p.Run(input, vuints)
}

func (c *create) Run(input []byte, _ []vunit) ([]byte, error) {
	return c.ovm.Create(input[4:], c.contract)
}

func (c *meta) Run(input []byte, _ []vunit) ([]byte, error) {
	return c.ovm.getMeta(c.contract.self.Address(), string(input)), nil
}
