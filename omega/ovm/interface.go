// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btclog"
	"math/big"
)

// StateDB is an EVM database for full state querying.
type StateDB interface {
	CreateAccount(Address)

	SubBalance(Address, *big.Int)
	AddBalance(Address, *big.Int)
	GetBalance(Address) *big.Int

	GetNonce(Address) uint64
	SetNonce(Address, uint64)

	GetCodeHash(Address) chainhash.Hash
	GetCode(Address) []byte
	SetCode(Address, []byte)
	GetCodeSize(Address) int

	AddRefund(uint64)
	GetRefund() uint64

	GetState(Address, chainhash.Hash) chainhash.Hash
	SetState(Address, chainhash.Hash, chainhash.Hash)

	Suicide(Address) bool
	HasSuicided(Address) bool

	// Exist reports whether the given account exists in state.
	// Notably this should also return true for suicided accounts.
	Exist(Address) bool
	// Empty returns whether the given account is empty. Empty
	// is defined according to EIP161 (balance = nonce = code = 0).
	Empty(Address) bool

	RevertToSnapshot(int)
	Snapshot() int

	AddLog(*btclog.Logger)
	AddPreimage(chainhash.Hash, []byte)

	ForEachStorage(Address, func(chainhash.Hash, chainhash.Hash) bool)
}

// CallContext provides a basic interface for the EVM calling conventions. The EVM EVM
// depends on this context being implemented for doing subcalls and initialising new EVM contracts.
type CallContext interface {
	// Call another contract
	Call(env *OVM, me ContractRef, addr Address, data []byte, gas, value *big.Int) ([]byte, error)
	// Take another's contract code and execute within our own context
	CallCode(env *OVM, me ContractRef, addr Address, data []byte, gas, value *big.Int) ([]byte, error)
	// Same as CallCode except sender and value is propagated from parent to child scope
	DelegateCall(env *OVM, me ContractRef, addr Address, data []byte, gas *big.Int) ([]byte, error)
	// Create a new contract
	Create(env *OVM, me ContractRef, data []byte, gas, value *big.Int) ([]byte, Address, error)
}
