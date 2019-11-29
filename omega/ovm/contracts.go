// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ovm

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"golang.org/x/crypto/ripemd160"
	"github.com/btcsuite/omega/token"
	"encoding/binary"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/btcec"
	"bytes"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	Run(input []byte) ([]byte, error) // Run runs the precompiled contract
}

// Create creates a new contract
type create struct {
	ovm * OVM
	contract *Contract
}

const (
	OP_CREATE		= 0
	OP_MINT		= 0x40

	PAYFUNC_MIN	= 0x41
	PAYFUNC_MAX	= 0x46

	OP_PAY2PKH		= 0x41
	OP_PAY2SCRIPTH	= 0x42
	OP_PAY2MULTIPKH		= 0x43
	OP_PAY2MULTISCRIPTH		= 0x44
	OP_PAY2NONE		= 0x45
	OP_PAY2ANY			= 0x46
)

// PrecompiledContracts contains the default set of pre-compiled contracts
var PrecompiledContracts = map[[4]byte]PrecompiledContract{
	([4]byte{OP_CREATE, 0, 0, 0}): &create{},				// create a contract
	([4]byte{OP_MINT, 0, 0, 0}): &mint{},				// mint a coin

	// pk script functions
	([4]byte{OP_PAY2PKH, 0, 0, 0}): &pay2pkh{},			// pay to pubkey hash script
	([4]byte{OP_PAY2SCRIPTH, 0, 0, 0}): &pay2scripth{},		// pay to script hash script
	([4]byte{OP_PAY2MULTIPKH, 0, 0, 0}): &pay2pkhs{},			// pay to pubkey hash script, multi-sig
	([4]byte{OP_PAY2MULTISCRIPTH, 0, 0, 0}): &pay2scripths{},		// pay to script hash script, multi-sig
	([4]byte{OP_PAY2NONE, 0, 0, 0}): &payreturn{},			// pay to no one and spend it
	([4]byte{OP_PAY2ANY, 0, 0, 0}): &payanyone{},			// pay to anyone

	// other callable public functions
	([4]byte{1, 0, 0, 0}): &ecrecover{},
	([4]byte{2, 0, 0, 0}): &sha256hash{},
	([4]byte{3, 0, 0, 0}): &ripemd160hash{},
	([4]byte{4, 0, 0, 0}): &dataCopy{},
	([4]byte{5, 0, 0, 0}): &bigModExp{},
	([4]byte{6, 0, 0, 0}): &bn256Add{},
	([4]byte{7, 0, 0, 0}): &bn256ScalarMul{},
	([4]byte{8, 0, 0, 0}): &bn256Pairing{},
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
		pos = pos + 32 + int((l + 31) ^ 0x1F)

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
	pos += int(((l + 31) ^ 0x1F))

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

		pos = (pos+32+int(siglen)+31) ^ 0x1F

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

	pkBytes, pos := reformatData(input[20:])
	pos += 20
	pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
	if err != nil {
		return []byte{0}, nil
	}

	ph := Hash160(pkBytes)

	if bytes.Compare(ph[:], pkh[:]) != 0 {
		return []byte{0}, nil
	}

	sigBytes, siglen := reformatData(input[pos:])

//	binary.LittleEndian.Uint32(input[pos:])
//	sigBytes := input[pos : pos + siglen]

	pos += siglen

	// Generate the signature hash based on the signature hash type.
	var hash []byte

	text, _ := reformatData(input[pos:])

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

type mint struct{
	ovm * OVM
	contract *Contract
}

func (m * mint) Run(input []byte) ([]byte, error) {
	// mint coins. it must has been verified that the cal is authorized
	// do contract deployment
	contract := m.contract.self.Address()

	tokentype := input[0]
	var h chainhash.Hash
	var r chainhash.Hash
	var val uint64
	var md uint64

	p := 0
	if tokentype&1 == 1 {
		copy(h[:], input[1:33])
		md = 1
		p = 33
	} else {
		val = binary.LittleEndian.Uint64(input[1:])
		md = val
		p = 9
	}
	if tokentype&2 == 2 {
		copy(r[:], input[p:])
	}

	mtype, issue := m.ovm.StateDB[contract].GetMint()

	if mtype == 0 {
		// mint for the first time, assign a new tokentype. This is instant, doesnot defer to commitmenyment even
		// the call fails eventually. In that case, we waste a tokentype code.

		err := m.ovm.StateDB[contract].DB.Update(func(dbTx database.Tx) error {
			defaultVersion := uint64(0x100) | uint64(tokentype&3)
			var key []byte

			if tokentype&2 == 0 {
				key = []byte("availNonRightTokenType")
			} else {
				key = []byte("availRightTokenType")
			}

			// the tokentype value for numtoken available
			version := uint64(DbFetchVersion(dbTx, key))
			if version == 0 {
				version = defaultVersion
			}

			mtype, issue = version, 0

			return DbPutVersion(dbTx, key, (version+4)^3)
		})

		m.ovm.StateDB[contract].SetMint(mtype, md)

		if err != nil {
			return nil, err
		}
	} else {
		m.ovm.StateDB[contract].SetMint(mtype, md)
	}

	issued := token.Token{
		TokenType: mtype,
	}
	if mtype&1 == 0 {
		issued.Value = &token.NumToken{int64(val) }
	} else {
		issued.Value = &token.HashToken{h }
	}
	if mtype&2 == 2 {
		issued.Rights = &r
	}

	m.ovm.StateDB[contract].Credit(issued)

	return nil, nil
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
func RunPrecompiledContract(p PrecompiledContract, input []byte, contract *Contract) (ret []byte, err error) {
	return p.Run(input)
}

func (c *create) Run(input []byte) ([]byte, error) {
	return c.ovm.Create(input[4:], c.contract)
}

// ECRECOVER implemented as a native contract.
type ecrecover struct{}

func (c *ecrecover) Run(input []byte) ([]byte, error) {
	const ecRecoverInputLength = 128

	input = common.RightPadBytes(input, ecRecoverInputLength)
	// "input" is (hash, v, r, s), each 32 bytes
	// but for ecrecover we want (r, s, v)

	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])
	v := input[63] - 27

	// tighter sig s values input homestead only apply to tx sigs
	if !allZero(input[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		return nil, nil
	}
	// v needs to be at the end for libsecp256k1
	pubKey, err := crypto.Ecrecover(input[:32], append(input[64:128], v))
	// make sure the public key is a valid one
	if err != nil {
		return nil, nil
	}

	// the first byte of pubkey is bitcoin heritage
	return common.LeftPadBytes(crypto.Keccak256(pubKey[1:])[12:], 32), nil
}

// SHA256 implemented as a native contract.
type sha256hash struct{}

func (c *sha256hash) Run(input []byte) ([]byte, error) {
	h := sha256.Sum256(input)
	return h[:], nil
}

// RIPMED160 implemented as a native contract.
type ripemd160hash struct{}

func (c *ripemd160hash) Run(input []byte) ([]byte, error) {
	ripemd := ripemd160.New()
	ripemd.Write(input)
	return common.LeftPadBytes(ripemd.Sum(nil), 32), nil
}

// data copy implemented as a native contract.
type dataCopy struct{}

func (c *dataCopy) Run(in []byte) ([]byte, error) {
	return in, nil
}

// bigModExp implements a native big integer exponential modular operation.
type bigModExp struct{}

var (
	big1      = big.NewInt(1)
	big4      = big.NewInt(4)
	big8      = big.NewInt(8)
	big16     = big.NewInt(16)
	big32     = big.NewInt(32)
	big64     = big.NewInt(64)
	big96     = big.NewInt(96)
	big480    = big.NewInt(480)
	big1024   = big.NewInt(1024)
	big3072   = big.NewInt(3072)
	big199680 = big.NewInt(199680)
)

func (c *bigModExp) Run(input []byte) ([]byte, error) {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Handle a special case when both the base and mod length is zero
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	// Retrieve the operands and execute the exponentiation
	var (
		base = new(big.Int).SetBytes(getData(input, 0, baseLen))
		exp  = new(big.Int).SetBytes(getData(input, baseLen, expLen))
		mod  = new(big.Int).SetBytes(getData(input, baseLen+expLen, modLen))
	)
	if mod.BitLen() == 0 {
		// Modulo 0 is undefined, return zero
		return common.LeftPadBytes([]byte{}, int(modLen)), nil
	}
	return common.LeftPadBytes(base.Exp(base, exp, mod).Bytes(), int(modLen)), nil
}

// newCurvePoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newCurvePoint(blob []byte) (*bn256.G1, error) {
	p := new(bn256.G1)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// newTwistPoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newTwistPoint(blob []byte) (*bn256.G2, error) {
	p := new(bn256.G2)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// bn256Add implements a native elliptic curve point addition.
type bn256Add struct{}

func (c *bn256Add) Run(input []byte) ([]byte, error) {
	x, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	y, err := newCurvePoint(getData(input, 64, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.Add(x, y)
	return res.Marshal(), nil
}

// bn256ScalarMul implements a native elliptic curve scalar multiplication.
type bn256ScalarMul struct{}

func (c *bn256ScalarMul) Run(input []byte) ([]byte, error) {
	p, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.ScalarMult(p, new(big.Int).SetBytes(getData(input, 64, 32)))
	return res.Marshal(), nil
}

var (
	// true32Byte is returned if the bn256 pairing check succeeds.
	true32Byte = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	// false32Byte is returned if the bn256 pairing check fails.
	false32Byte = make([]byte, 32)

	// errBadPairingInput is returned if the bn256 pairing input is invalid.
	errBadPairingInput = errors.New("bad elliptic curve pairing size")
)

// bn256Pairing implements a pairing pre-compile for the bn256 curve
type bn256Pairing struct{}

func (c *bn256Pairing) Run(input []byte) ([]byte, error) {
	// Handle some corner cases cheaply
	if len(input)%192 > 0 {
		return nil, errBadPairingInput
	}
	// Convert the input into a set of coordinates
	var (
		cs []*bn256.G1
		ts []*bn256.G2
	)
	for i := 0; i < len(input); i += 192 {
		c, err := newCurvePoint(input[i : i+64])
		if err != nil {
			return nil, err
		}
		t, err := newTwistPoint(input[i+64 : i+192])
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
		ts = append(ts, t)
	}
	// Execute the pairing checks and return the results
	if bn256.PairingCheck(cs, ts) {
		return true32Byte, nil
	}
	return false32Byte, nil
}
