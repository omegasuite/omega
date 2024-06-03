/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import "github.com/omegasuite/famofchains/omega"

type executionFunc func(pc *int, env *OVM, contract *Contract, stack *Stack) omega.Err

type operation struct {
	// op is the operation function
	execute executionFunc

	halts   bool // indicates whether the operation should halt further execution
	jumps   bool // indicates whether the program counter should not increment
	writes  bool // determines whether this a state modifying operation
	valid   bool // indication whether the retrieved operation is valid and known
	reverts bool // determines whether the operation reverts state (implicitly halts)
	returns bool // determines whether the operations sets the return Data content
}

// NewSignVMInstSet returns the signature VM instructions.
func NewSignVMInstSet() [256]operation {
	// instructions that can be executed during the byzantium phase.
	return [256]operation{
		SIGNTEXT: operation{
			execute: opAddSignText,
			valid:   true,
		},
		PUSH: operation{
			execute: opPush,
			valid:   true,
		},
		STOP: {
			execute: opStop,
			halts:   true,
			returns: true,
			valid:   true,
		},
	}
}
