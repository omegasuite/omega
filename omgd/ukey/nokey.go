// Copyright (C) 2019-2022 Omegasuite developer
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// +build !usekey

package ukey

const 	UseUKey = false		// to use ukey, set UkeyChecker value below

func Readinfo() string {
	return ""
}

func Clear() {
}
