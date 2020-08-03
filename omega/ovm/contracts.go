package ovm

import (
	"fmt"
	"sync/atomic"

	"bytes"
	"encoding/binary"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
//	"github.com/omegasuite/btcd/database"
//	"github.com/omegasuite/omega/token"
)

// PrecompiledContract is the basic interface for native Go contracts.
type PrecompiledContract interface {
	Run(input []byte) ([]byte, error) // Run runs the precompiled contract
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
	OP_PAY2MULTIPKH			= 0x43
	OP_PAY2MULTISCRIPTH		= 0x44
	OP_PAY2NONE				= 0x45
	OP_PAY2ANY				= 0x46
)

// PrecompiledContracts contains the default set of pre-compiled contracts
var PrecompiledContracts = map[[4]byte]PrecompiledContract{
	([4]byte{OP_CREATE, 0, 0, 0}): &create{},			// create a contract
	([4]byte{OP_META, 0, 0, 0}): &meta{},			// create a contract

	// pk script functions
	([4]byte{OP_PAY2PKH, 0, 0, 0}): &pay2pkh{},			// pay to pubkey hash script
	([4]byte{OP_PAY2SCRIPTH, 0, 0, 0}): &pay2scripth{},		// pay to script hash script
	([4]byte{OP_PAY2MULTIPKH, 0, 0, 0}): &pay2pkhs{},			// pay to pubkey hash script, multi-sig
	([4]byte{OP_PAY2MULTISCRIPTH, 0, 0, 0}): &pay2scripths{},		// pay to script hash script, multi-sig
	([4]byte{OP_PAY2NONE, 0, 0, 0}): &payreturn{},			// pay to no one and spend it
	([4]byte{OP_PAY2ANY, 0, 0, 0}): &payanyone{},			// pay to anyone
}

type payanyone struct {}

func (p *payanyone) Run(input []byte) ([]byte, error) {
	return []byte{1}, nil
}

type payreturn struct {}

func (p *payreturn) Run(input []byte) ([]byte, error) {
	// spend it !!!
	return []byte{0}, nil
}

type pay2scripths struct {}

func (p *pay2scripths) Run(input []byte) ([]byte, error) {
	// All input fields are 20-byte padded
	// input: pkh - script hash (20-bytes)
	//		  N:M - bytes 0-4 = M, bytes 4-8 = N (M >= N)
	//		  (M - 1) script hash (20-bytes)
	//		  upto M text
	//	      text - script

	pkh := make([][20]byte, 1)
	copy(pkh[0][:], input[:20])

	m := binary.LittleEndian.Uint32(input[20:])
	n := int(binary.LittleEndian.Uint32(input[24:]))

	pos := 28
	for i := uint32(1); i < m; i++ {
		var k [20]byte
		copy(k[:], input[pos:])
		pkh = append(pkh, k)
		pos += 20
	}

	for pos < len(input) {
		l := binary.LittleEndian.Uint32(input[pos:])
		text := input[pos + 32:pos + 32 + int(l)]
		pos = pos + 32 + int((l + 31) &^ 0x1F)

		hash := Hash160(text)

		for i := uint32(0); i < m; i++ {
			if bytes.Compare(hash[:], pkh[i][:]) == 0 {
				pkh[i] = [20]byte{}
				n--
				if n == 0 {
					return []byte{1}, nil
				}
			}
		}
	}
	return []byte{0}, nil
}

type pay2pkhs struct {}

func (p *pay2pkhs) Run(input []byte) ([]byte, error) {
	// All input fields are 32-byte padded except for public key hashes, M, N
	// input: pkh - public key hash (20-byte value, not padded)
	//		  N:M - bytes 0-4 = M, bytes 4-8 = N (M >= N)
	//		  (M - 1) public key hashws (each 30-byte value)
	//	      text - text to be signed (in chucks of 0-padded 32-bytes units)
	//		  upto M publick key-signature pairs
	//		  publick key
	//		  signature

	pkh := make([][20]byte, 1)
	copy(pkh[0][:], input[:20])

	m := binary.LittleEndian.Uint32(input[20:])
	n := int(binary.LittleEndian.Uint32(input[24:]))

	pos := 28
	for i := uint32(1); i < m; i++ {
		var k [20]byte
		copy(k[:], input[pos:])
		pkh = append(pkh, k)
		pos += 20
	}

	l := binary.LittleEndian.Uint32(input[pos:])
	pos += 32
	text := input[pos:pos + int(l)]
	pos += int(((l + 31) &^ 0x1F))

	hash := chainhash.DoubleHashB(text)

	for pos < len(input) {
		var pkBytes []byte

		if input[pos] == 0x02 || input[pos] == 0x03 {
			pkBytes = input[pos : pos+33]
			pos += 64
		} else if input[pos] == 0x04 {
			pkBytes = input[pos : pos+65]
			pos += 96
		}

		siglen := binary.LittleEndian.Uint32(input[pos:])
		sigBytes := input[pos+32 : pos+32+int(siglen)]

		pos = (pos+32+int(siglen)+31) &^ 0x1F

		pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
		if err != nil {
			return []byte{0}, nil
		}

		var signature *btcec.Signature

		signature, err = btcec.ParseSignature(sigBytes, btcec.S256())

		if err != nil {
			return []byte{0}, nil
		}

		valid := signature.Verify(hash, pubKey)

		if valid {
			ph := Hash160(pubKey.SerializeUncompressed())
			for i := uint32(0); i < m; i++ {
				if bytes.Compare(ph[:], pkh[i][:]) == 0 {
					n--
					if n == 0 {
						return []byte{1}, nil
					}
					copy(pkh[i][:], (*(&chainhash.Hash{}))[:])
				}
			}
		}
	}

	return []byte{0}, nil
}

type pay2scripth struct {}

func (p *pay2scripth) Run(input []byte) ([]byte, error) {
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

func reformatData(input[] byte) ([]byte, uint32) {
	ln := binary.LittleEndian.Uint32(input[0:32])
	r := make([]byte, ln)
	p, q := int(((ln + 31) & 0xE0) - 32), uint32(0)
	for ; p >= 0; p -= 32 {
		copy(r[q:], input[p + 32:])
		q += 32
	}
	return r, q + 32
}

func (p *pay2pkh) Run(input []byte) ([]byte, error) {
	// All input fields are 32-byte padded
	// input: pkh - public key hash (20-byte value)
	//		  publick key
	//		  signature
	//	      text - text to be signed (in chucks of 0-padded 32-bytes units)

	pkh := input[:20]

	pkBytes := input[21:21 + input[20]]
	pos := 21 + input[20]
	
	pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
	if err != nil {
		return []byte{0}, nil
	}

	ph := Hash160(pkBytes)

	if bytes.Compare(ph[:], pkh[:]) != 0 {
		return []byte{0}, nil
	}

	siglen := input[pos]

	sigBytes := input[pos + 1:pos + siglen + 1]

//	binary.LittleEndian.Uint32(input[pos:])
//	sigBytes := input[pos : pos + siglen]

	pos += siglen + 1

	// Generate the signature hash based on the signature hash type.
	var hash []byte

	text := input[pos:]

//	textlen := binary.LittleEndian.Uint32(input[pos:])
	hash = chainhash.DoubleHashB(text)

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
			err := operation.execute(&pc, in.evm, contract, stack)

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
	return p.Run(input)
}

func (c *create) Run(input []byte) ([]byte, error) {
	return c.ovm.Create(input[4:], c.contract)
}

func (c *meta) Run(input []byte) ([]byte, error) {
	return c.ovm.getMeta(c.contract.self.Address(), string(input)), nil
}
