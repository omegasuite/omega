// Copyright (C) 2019-2022 Omegasuite developer
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// build flags: -i -ldflags "-X 'main.CompileTime=`%date%`'" -tags=usekey
// remove  -tags=usekey to build normal version

// +build usekey

package ukey

// #include <stdio.h>
// #include <stdlib.h>
// #include <windows.h>
/*
typedef char*(*info)();

char _result[260];
char * result;
char *  readinfo() {
	HINSTANCE p = LoadLibraryA("omgs.dll");
	info q = (info) GetProcAddress(p, "getuinfo");;

	result = _result;

	return q(result);
}

void clear() {
	memset(_result, 0, 256);
}
 */
import "C"

const 	UseUKey = true		// to use ukey, set UkeyChecker value below

func Readinfo() string {
	C.readinfo()
	return C.GoString(C.result)
}

func Clear() {
	C.clear();
}
