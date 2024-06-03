/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import (
	"github.com/omegasuite/omega"
)

var (
	ErrDepth                    = omega.ScriptError(omega.ErrInternal,"max call depth exceeded")
	ErrTraceLimitReached        = omega.ScriptError(omega.ErrInternal,"the number of logs reached the specified limit")
	ErrContractAddressCollision = omega.ScriptError(omega.ErrInternal,"contract address collision")
)
