// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (C) 2019-2021 Omegasuite developer
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	//	"os/exec"
	"os/signal"
	"runtime/pprof"
	//	"syscall"
	"time"
)

// shutdownRequestChannel is used to initiate shutdown from one of the
// subsystems using the same code paths as when an interrupt signal is received.
var shutdownRequestChannel = make(chan struct{})

// interruptSignals defines the default signals to catch in order to do a proper
// shutdown.  This may be modified during init depending on the platform.
var interruptSignals = []os.Signal{os.Interrupt}

// interruptListener listens for OS Signals such as SIGINT (Ctrl+C) and shutdown
// requests from shutdownRequestChannel.  It returns a channel that is closed
// when either signal is received.

var intchannel chan struct{}

func interruptListener() <-chan struct{} {
	if intchannel == nil {
		intchannel = make(chan struct{})
	} else {
		return intchannel
	}

	go func() {
		interruptChannel := make(chan os.Signal, 1)
		signal.Notify(interruptChannel, interruptSignals...)

		var wbuf bytes.Buffer

		select {
		case sig := <-interruptChannel:
			btcdLog.Infof("Received signal (%s).  Shutting down...", sig)

			pprof.Lookup("mutex").WriteTo(&wbuf, 1)
			pprof.Lookup("goroutine").WriteTo(&wbuf, 1)
			btcdLog.Infof("pprof Info: \n%s", wbuf.String())

		case <-shutdownRequestChannel:
			btcdLog.Info("Shutdown requested.  Shutting down...")
			pprof.Lookup("mutex").WriteTo(&wbuf, 1)
			pprof.Lookup("goroutine").WriteTo(&wbuf, 1)
			btcdLog.Infof("pprof Info: \n%s", wbuf.String())
		}

		close(intchannel)

		time.Sleep(5 * time.Minute)
		btcdLog.Infof("Forced exit 5 min. after shutdown notice.")

		pprof.Lookup("mutex").WriteTo(&wbuf, 1)
		pprof.Lookup("goroutine").WriteTo(&wbuf, 1)
		btcdLog.Infof("pprof Info: \n%s", wbuf.String())

		os.Exit(9)
	}()

	return intchannel
}

// interruptRequested returns true when the channel returned by
// interruptListener was closed.  This simplifies early shutdown slightly since
// the caller can just use an if statement instead of a select.
func interruptRequested(interrupted <-chan struct{}) bool {
	select {
	case <-interrupted:
		return true
	default:
	}

	return false
}
