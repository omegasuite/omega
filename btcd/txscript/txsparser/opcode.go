// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txsparser

// Classes of script payment known about in the blockchain.
const (
	NonStandardTy         ScriptClass = iota // None of the recognized forms.
	PubKeyHashTy                             // Pay pubkey hash.
	ScriptHashTy                             // Pay to script hash.
	MultiSigTy                               // Multi signature.
//	MultiScriptTy								// multi script
	ContractHashTy                            // ContractHash.
	PaytoAnyoneTy            	                // pay to anyone.
	NullDataTy                               // Empty data-only (provably prunable).
)

// scriptClassToName houses the human-readable strings which describe each
// script class.
var ScriptClassToName = []string{
	NonStandardTy:         "nonstandard",
	PubKeyHashTy:          "pubkeyhash",
	ScriptHashTy:          "scripthash",
	MultiSigTy:            "multisig",
//	MultiScriptTy:        "multiscript",
	ContractHashTy:		"contracthash",
	PaytoAnyoneTy:	"anyone",            	                // pay to anyone.
	NullDataTy:            "nulldata",
}
