// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import "errors"

var (
	ErrDepth                    = errors.New("max call depth exceeded")
	ErrTraceLimitReached        = errors.New("the number of logs reached the specified limit")
	ErrContractAddressCollision = errors.New("contract address collision")
)
