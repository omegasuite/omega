// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcutil

const (
	// HaoPerBitcent is the number of hao in one bitcoin cent.
	HaoPerBitcent = 1e6

	// HaoPerBitcoin is the number of hao in one bitcoin (1 OMC).
	HaoPerBitcoin = 1e8

	// MaxHao is the maximum transaction amount allowed in hao.
	MaxHao = 21e6 * HaoPerBitcoin
)
