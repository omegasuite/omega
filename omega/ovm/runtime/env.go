// Copyright 2015 The go-ethereum Authors
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

package runtime

import (
	"github.com/omegasuite"
	"github.com/omegasuite/ovm"
)

func NewEnv(cfg *Config) *vm.EVM {
	context := vm.Context{
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		TxTemplate:  wire.MsgTx{},

		Origin:      cfg.Origin,
		Coinbase:    cfg.Coinbase,
		BlockNumber: cfg.BlockNumber,
		Time:        cfg.Time,
		Difficulty:  cfg.Difficulty,
		GasLimit:    cfg.GasLimit,
		GasPrice:    cfg.GasPrice,
	}

	vm.GetTxTemplate = func() wire.MsgTx {
		return vm.GetTxTemplate()
	}
	vm.Spend = func(t token.Token) bool {
		return vm.Spend(t)
	}
	vm.AddTxOutput = func(wire.TxOut) bool {
		return vm.AddTxOutput(t)
	}
	vm.AddTxDef = func(token.Definition) bool {
		return vm.AddTxDef(t)
	}
	vm.SubmitTx = func() common.Hash {
		return vm.SubmitTx()
	}

	return vm.NewEVM(context, cfg.State, cfg.ChainConfig, cfg.EVMConfig)
}

func (context *vm.Context) GetTxTemplate() wire.MsgTx {
	return context.TxTemplate
}
func (context *vm.Context) Spend() bool {
	if true {	// check out UTXO to see if we have enough tockens, add those same kind as t to TxIn
		context.TxTemplate.TxIn[] = wire.TxIn{}
		return true
	}
	return false
}
func (context *vm.Context) AddTxOutput(wire.TxOut) bool {
	context.TxTemplate.TxOut[] = wire.TxOut{}
	return true
}
func (context *vm.Context) AddTxDef(token.Definition) bool {
	context.TxTemplate.TxDef[] = wire.Definition{}
	return true
}
func (context *vm.Context) SubmitTx() common.Hash {
}
