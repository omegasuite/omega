// Copyright (c) 2014-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcutil/base58"
	"os"
)

var detail = int(4)

func atype(netID byte) (itype string, convto []byte) {
	switch netID {
	case 0x00:	// mainnet PubKeyHashAddrID
		itype = "mainnet PubKeyHashAddr"
		convto = []byte{0x6f, 0x3f}
	case 0x05:	// mainnet ScriptHashAddrID
		itype = "mainnet ScriptHashAddr"
		convto = []byte{0xc4, 0x7b}
	case 0x88:	// ContractAddrID
		itype = "ContractAddr"
		convto = []byte{0x88, 0x88}
	case 0x80:	// mainnet PrivateKeyID
		itype = "mainnet PrivateKey"
		convto = []byte{0xef, 0x64}

	case 0x6f:	// testnet PubKeyHashAddrID
		itype = "testnet PubKeyHashAddr"
		convto = []byte{0x00, 0x3f}
	case 0xc4:	// testnet ScriptHashAddrID
		itype = "testnet ScriptHashAddr"
		convto = []byte{0x05, 0x7b}
	case 0xef:	// testnet PrivateKeyID
		itype = "testnet PrivateKey"
		convto = []byte{0x80, 0x64}

	case 0x3f:	// simnet PubKeyHashAddrID
		itype = "simnet PubKeyHashAddr"
		convto = []byte{0x6f, 0x00}
	case 0x7b:	// simnet ScriptHashAddrID
		itype = "simnet ScriptHashAddr"
		convto = []byte{0xc4, 0x05}
	case 0x64:	// simnet PrivateKeyID
		itype = "simnet PrivateKey"
		convto = []byte{0xef, 0x80}
	}
	return itype, convto
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("This program converts public/private keys between different nets (mainnet, test, simnet). Enter a key and see its versions in other nets.\n")

	for {
		fmt.Print("-> ")
		wif, _ := reader.ReadString('\n')
		wb := []byte(wif)
		decodedLen := len(wb)
		for wb[decodedLen - 1] == '\n' || wb[decodedLen - 1] == '\r' {
			decodedLen--
		}

		var wifdecoded []byte
		var netID byte

		if decodedLen == 42 {
			// bytes,
			var dec [25]byte
			hex.Decode(dec[:], wb[:decodedLen])
			wifdecoded = dec[:]
		} else {
			wif = string(wb[:decodedLen])
			wifdecoded = base58.Decode(wif)
		}

		netID = wifdecoded[0]
		decodedLen = len(wifdecoded)

		itype, convto := atype(netID)
		fmt.Printf("Key is %s\nBytes: %x\n", itype, wifdecoded[1:decodedLen-4])

		if convto != nil {
			for _, t := range convto {
				wifdecoded[0] = t

				cksum := chainhash.DoubleHashB(wifdecoded[:decodedLen-4])[:4]
				copy(wifdecoded[decodedLen-4:], cksum)

				w := base58.Encode(wifdecoded)
				itype, _ := atype(t)
				fmt.Printf("Convert to %s = %s\n", itype, w)
			}
		}
	}
}
