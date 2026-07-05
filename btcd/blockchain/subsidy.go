// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"btcd/chaincfg"
	"btcutil"
)

const (
	// BaseSubsidy is the starting subsidy amount for mined blocks.  This
	// value is halved every SubsidyHalvingInterval blocks.
	BaseSubsidy = 6 * btcutil.HaoPerBitcoin
)

// CalcBlockSubsidy returns the subsidy amount a block at the provided height
// should have. This is mainly used for determining how much the coinbase for
// newly generated blocks awards as well as validating the coinbase for blocks
// has the expected value.
//
// The subsidy is halved every SubsidyReductionInterval blocks.  Mathematically
// this is: BaseSubsidy / 2^(height/SubsidyReductionInterval)
//
// At the target block generation rate for the main network, this is
// approximately every 4 years.
func CalcBlockSubsidy(height int32, chainParams *chaincfg.Params) int64 {
	if chainParams.SubsidyReductionInterval == 0 {
		return BaseSubsidy
	}

	// Equivalent to: BaseSubsidy / 2^(height/subsidyHalvingInterval)
	return BaseSubsidy >> uint(height/chainParams.SubsidyReductionInterval)
}
