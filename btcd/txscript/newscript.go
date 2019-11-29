package txscript

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/txscript/txsparser"
	"github.com/btcsuite/btcd/blockchain/indexers"
	"github.com/btcsuite/omega/ovm"
)

const (
	// minPubKeyHashSigScriptLen is the minimum length of a signature script
	// that spends a P2PKH output. The length is composed of the following:
	//   Signature length (1 byte)
	//   Signature (min 8 bytes)
	//   Signature hash type (1 byte)
	//   Public key length (1 byte)
	//   Public key (33 byte)
	minPubKeyHashSigScriptLen = 1 + btcec.MinSigLen + 1 + 1 + 33

	// maxPubKeyHashSigScriptLen is the maximum length of a signature script
	// that spends a P2PKH output. The length is composed of the following:
	//   Signature length (1 byte)
	//   Signature (max 72 bytes)
	//   Signature hash type (1 byte)
	//   Public key length (1 byte)
	//   Public key (33 byte)
	maxPubKeyHashSigScriptLen = 1 + 72 + 1 + 1 + 33

	// compressedPubKeyLen is the length in bytes of a compressed public
	// key.
	compressedPubKeyLen = 33

	// pubKeyHashLen is the length of a P2PKH script.
	pubKeyHashLen = 25

	// pubKeyHashLen is the length of a P2PKH script.
	contractLen = 21

	// witnessV0PubKeyHashLen is the length of a P2WPKH script.
	witnessV0PubKeyHashLen = 22

	// scriptHashLen is the length of a P2SH script.
	scriptHashLen = 23

	// witnessV0ScriptHashLen is the length of a P2WSH script.
	witnessV0ScriptHashLen = 34

	// maxLen is the maximum script length supported by ParsePkScript.
	maxLen = witnessV0ScriptHashLen
)

var (
	// ErrUnsupportedScriptType is an error returned when we attempt to
	// parse/re-compute an output script into a PkScript struct.
	ErrUnsupportedScriptType = errors.New("unsupported script type")
)

// PkScript is a wrapper struct around a byte array, allowing it to be used
// as a map index.
type PkScript struct {
	// class is the type of the script encoded within the byte array. This
	// is used to determine the correct length of the script within the byte
	// array.
	class txsparser.ScriptClass

	// script is the script contained within a byte array. If the script is
	// smaller than the length of the byte array, it will be padded with 0s
	// at the end.
	script [maxLen]byte
}

// ParsePkScript parses an output script into the PkScript struct.
// ErrUnsupportedScriptType is returned when attempting to parse an unsupported
// script type.
func ParsePkScript(pkScript []byte) (PkScript, error) {
	var outputScript PkScript
	outputScript.class = 0
	copy(outputScript.script[:], pkScript)

	return outputScript, nil
}

// isSupportedScriptType determines whether the script type is supported by the
// PkScript struct.
func isSupportedScriptType(class txsparser.ScriptClass) bool {
	return true
}

// Class returns the script type.
func (s PkScript) Class() txsparser.ScriptClass {
	return s.class
}

// Script returns the script as a byte slice without any padding.
func (s PkScript) Script() []byte {
	return s.script[:]
}

// Address encodes the script into an address for the given chain.
func (s PkScript) Address(chainParams *chaincfg.Params) (btcutil.Address, error) {
	addrs, _, err := indexers.ExtractPkScriptAddrs(s.Script(), chainParams)
	if err != nil {
		return nil, fmt.Errorf("unable to parse address: %v", err)
	}

	return addrs[0], nil
}

// String returns a hex-encoded string representation of the script.
func (s PkScript) String() string {
	str, _ := DisasmString(s.Script())
	return str
}

// ComputePkScript computes the script of an output by looking at the spending
// input's signature script or witness.
//
// NOTE: Only P2PKH, P2SH, redeem scripts are supported.
func ComputePkScript(sigScript []byte, chainParams *chaincfg.Params) (PkScript, error) {
	pkScript := PkScript{}

	p, sigstart, textadded := 0, false, false
	for p < len(sigScript) && !sigstart {
		if sigScript[p] >= byte(ovm.PUSH1) && sigScript[p] <= byte(ovm.PUSH32) {
			if textadded {
				sigstart = true
			} else {
				p += 1 + int(sigScript[p])
			}
		} else {
			switch sigScript[p] {
			case byte(ovm.ADDSIGNTEXT):
				p++
				textadded = true
				switch sigScript[p] {
				case 0, 1: // specific matching outpoint // specific matching input // specific script
					p++
				case 2, 3, 4: // specific matching outpoint // specific matching input // specific script
					p += 2 + int(sigScript[p + 1])
				default:
					return pkScript, txsparser.ScriptError(txsparser.ErrNotPushOnly,
						"sigscript is not valid")
				}
			}
		}
	}

	if !sigstart {
		return pkScript, txsparser.ScriptError(txsparser.ErrNotPushOnly,
			"sigscript is not valid")
	}

	if sigScript[p] >= byte(ovm.PUSH1) && sigScript[p] <= byte(ovm.PUSH32) {
		p++
		format := int(sigScript[p])
		var s []byte
		if format == 0x2 {	// btcec.pubkeyCompressed
			s = append(sigScript[p + 1 : p + 33], sigScript[p + 34])
			p += 35
		} else if format == 0x4 {	// btcec.pubkeyUncompressed
			s = append(append(sigScript[p + 1 : p + 33], sigScript[p + 34 : p + 66]...), sigScript[p+67])
			p += 68
		} else if format == 0x6 {	// btcec.pubkeyHybappend(rid
			s = append(append(sigScript[p + 1 : p + 33], sigScript[p + 34 : p + 66]...), sigScript[p+67])
			p += 68
		} else {
			// assume it is a script
			s := make([]byte, 0)
			for format >= 32 {
				s = append(s, sigScript[p + 1 : p + 33]...)
				format -= 32
				p += 33
			}
			if format > 0 {
				s = append(s, sigScript[p + 1 : p + format + 1]...)
			}
			addr, _ := btcutil.NewAddressScriptHash(s, chainParams)
			copy(pkScript.script[:], addr.ScriptNetAddress())
			pkScript.class = txsparser.ScriptHashTy
			pkScript.script[21] = ovm.OP_PAY2SCRIPTH
			return pkScript, nil
		}
		addr, _ := btcutil.NewAddressPubKey(s, chainParams)
		pkh := addr.AddressPubKeyHash()
		copy(pkScript.script[:], pkh.ScriptNetAddress())
		pkScript.class = txsparser.PubKeyHashTy
		pkScript.script[21] = ovm.OP_PAY2PKH
		return pkScript, nil
	}

	return pkScript, txsparser.ScriptError(txsparser.ErrNotPushOnly,
		"sigscript is not valid")
}
