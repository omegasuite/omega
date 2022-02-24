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
func interruptListener() <-chan struct{} {
	c := make(chan struct{})
//	last := int64(0)

	go func() {
		interruptChannel := make(chan os.Signal, 1)
		signal.Notify(interruptChannel, interruptSignals...)

		var wbuf bytes.Buffer

		// Listen for initial shutdown signal and close the returned
		// channel to notify the caller.
//	shutdown:
//		for true {
			select {
			case sig := <-interruptChannel:
				btcdLog.Infof("Received signal (%s).  Shutting down...", sig)
//				t := time.Now().Unix()
//				if t-last < 20 {
//					break shutdown
//				}
//				last = t

				pprof.Lookup("mutex").WriteTo(&wbuf, 1)
				pprof.Lookup("goroutine").WriteTo(&wbuf, 1)
				btcdLog.Infof("pprof Info: \n%s", wbuf.String())

//				pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
//				consensus.CommitteePolling()

			case <-shutdownRequestChannel:
				btcdLog.Info("Shutdown requested.  Shutting down...")
				pprof.Lookup("mutex").WriteTo(&wbuf, 1)
				pprof.Lookup("goroutine").WriteTo(&wbuf, 1)
				btcdLog.Infof("pprof Info: \n%s", wbuf.String())

//				pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
//				consensus.CommitteePolling()
//				break shutdown
			}
//		}

		close(c)
/*
		repeats := 0

		// Listen for repeated signals and display a message so the user
		// knows the shutdown is in progress and the process is not
		// hung.
		for {
			select {
			case sig := <-interruptChannel:
				btcdLog.Infof("Received signal (%s).  Already "+
					"shutting down...", sig)
				repeats++

			case <-shutdownRequestChannel:
				btcdLog.Info("Shutdown requested.  Already " +
					"shutting down...")
				repeats++
			}

			if repeats > 5 {
				pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
				repeats = 0
			}
		}
 */
		time.AfterFunc(5 * time.Minute, func() {
			btcdLog.Infof("Forced exit 5 min. after shutdown notice.")

			pprof.Lookup("mutex").WriteTo(&wbuf, 1)
			pprof.Lookup("goroutine").WriteTo(&wbuf, 1)
			btcdLog.Infof("pprof Info: \n%s", wbuf.String())

			// forced exit if not shutdown 5 mnin after receiving signal to shutdown
			os.Exit(9)
		})
	}()

	return c
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
