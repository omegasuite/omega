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
	"math/big"

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
	OP_CREATE					= 0
	OP_MINT					= 0x40

	PAYFUNC_MIN				= 0x41
	PAYFUNC_MAX				= 0x46

	OP_PAY2PKH					= 0x41
	OP_PAY2SCRIPTH			= 0x42
	OP_PAY2MULTIPKH			= 0x43
	OP_PAY2MULTISCRIPTH		= 0x44
	OP_PAY2NONE				= 0x45
	OP_PAY2ANY					= 0x46

	// Miner selection
	OP_MINER_APPLY			= 0x20		// pay & apply to become a miner
	OP_MINRE_QUIT				= 0x21		// quit & withdraw

	MINER_FEE_CAP				= 500		// miner fee cap. in omegas: 500 omegas
	MINER_RORATE_FREQ			= 50		// const: rotate frequency. How many blocks between rotation
	MAX_WITNESS				= 5			// max number of witnesses in a block
	COMMITTEE_DEF_SIZE		= 5			// default committee size
)

// PrecompiledContracts contains the default set of pre-compiled contracts
var PrecompiledContracts = map[[4]byte]PrecompiledContract{
	([4]byte{OP_CREATE, 0, 0, 0}): &create{},			// create a contract
	([4]byte{OP_MINT, 0, 0, 0}): &mint{},				// mint a coin

	// miner selection contract
//	([4]byte{OP_MINER_APPLY, 0, 0, 0}): &addminer{},
//	([4]byte{OP_MINRE_QUIT, 0, 0, 0}): &quitminer{},

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
}

/*
type addminer struct {
	ovm * OVM
	contract *Contract
}

type quitminer struct {
	ovm * OVM
	contract *Contract
}

func (p *addminer) Run(input []byte) ([]byte, error) {
	var d Address
	if _,ok := p.ovm.StateDB[d]; !ok {
		p.ovm.StateDB[d] = &stateDB{
			DB:       p.ovm.views.Db,
			contract: d,
			data:     make(map[chainhash.Hash]entry),
			wallet:	  make([]WalletItem, 0),
			meta:make(map[string]struct{
				data []byte
				back []byte
				flag status }),
		}

		p.ovm.StateDB[d].LoadWallet()
	}

	if p.contract.value.TokenType != 0 {
		return nil, fmt.Errorf("Only omegas are accepted as payment.")
	}

	if p.contract.value.Value.(*token.NumToken).Val != int64(MinerFeeRate(p.ovm.BlockNumber())) {
		return nil, fmt.Errorf("Payment must be exactly %d satoshi.", MinerFeeRate(p.ovm.BlockNumber()))
	}

//	if !p.ovm.views.Miners.Insert(input, uint64(p.contract.value.Value.(*token.NumToken).Val)) {
//		return nil, fmt.Errorf("Miner already exists.")
//	}

	p.ovm.StateDB[d].Credit(*p.contract.value)

	return nil, nil
}

func (p *quitminer) Run(input []byte) ([]byte, error) {
	var d Address
	if _,ok := p.ovm.StateDB[d]; !ok {
		p.ovm.StateDB[d] = &stateDB{
			DB:       p.ovm.views.Db,
			contract: d,
			data:     make(map[chainhash.Hash]entry),
			wallet:	  make([]WalletItem, 0),
			meta:make(map[string]struct{
				data []byte
				back []byte
				flag status }),
		}

		p.ovm.StateDB[d].LoadWallet()
	}

//	f := p.ovm.views.Miners.Remove(input)
//	if f == 0 {
		return nil, fmt.Errorf("Miner does not exists.")
	}

	t := token.Token{ TokenType: 0, }
	t.Value = &token.NumToken{Val:int64(f)}
	p.ovm.Spend(t)

	newScript := make([]byte, 25)
	newScript[0] = p.ovm.chainConfig.PubKeyHashAddrID
	copy(newScript[1:21], input)
	newScript[21] = OP_PAY2PKH

	newTxOut := wire.TxOut{}
	newTxOut.TokenType = 0
	newTxOut.Value = &token.NumToken{Val:int64(f)}
	newTxOut.PkScript = newScript

	p.ovm.AddTxOutput(newTxOut)

	return nil, nil
}

func MinerFeeRate(height uint64) uint64 {       // miner application fee rate in satoshi at height
	rate := uint64(100000000)					// initial rate is 1 omega

	for height /= 100000; height > 0 && rate < 50000000000; height-- {// rate adjusted every 100K blocks
		rate += rate / height
	}

	if rate > 50000000000 {
		rate = 50000000000
	}
	return rate
}

func MinerAward(height uint64) uint64 { // miner award in satoshi at height
	// miner award in satoshi/block. award adjusted every 10M blocks to
	// 1/2, 1/3, 1/4, ..,, 1/10 then the award is set such that total new
	// coins made each year is 3% of total outstanding coins at the end of
	// the previous year (1 year = 10M blocks)

	award := uint64(500000000) // initially 5 omegas/block = 500000000 satoshi
	height /= 10000000
	height++
	if height <= 10 {
		return award / height
	} else {
		s := uint64(50000000) // coins generated in the first year: 50M omegas
		for i := 20; i < 110; i += 10 {
			s += award / uint64(i)
		}
		height -= 10
		for ; height > 0; height-- {
			s += uint64(float64(s) * 0.03)
		}
		award = uint64(float64(s) * 0.03 * 10) // 3% and convert to satoshi/block 100000000 / 10000000
		return award
	}
}
 */

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

			return DbPutVersion(dbTx, key, (version+4)&^3)
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
	// input is: pub key, signature, signature hash.
	// returns pubkey hash160 padded to 32 bytes if the signature verifies
	pkBytes, pos := reformatData(input[0:])

	pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
	if err != nil {
		return nil, err
	}

	sigBytes, siglen := reformatData(input[pos:])
	pos += siglen

	hash := input[pos:pos + 32]

	var signature *btcec.Signature

	signature, err = btcec.ParseSignature(sigBytes, btcec.S256())

	if err != nil {
		return nil, err
	}

	valid := signature.Verify(hash, pubKey)

	if valid {
		ph := Hash160(pkBytes)
		return LeftPadBytes(ph, 32), nil
	}
	return nil, err
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
	return LeftPadBytes(ripemd.Sum(nil), 32), nil
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
		return LeftPadBytes([]byte{}, int(modLen)), nil
	}
	return LeftPadBytes(base.Exp(base, exp, mod).Bytes(), int(modLen)), nil
}
