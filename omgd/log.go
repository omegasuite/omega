// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/omegasuite/btcd/addrmgr"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/blockchain/indexers"
	"github.com/omegasuite/btcd/connmgr"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/mempool"
	"github.com/omegasuite/btcd/mining"
	"github.com/omegasuite/btcd/mining/cpuminer"
	"github.com/omegasuite/btcd/netsync"
	"github.com/omegasuite/btcd/peer"

	"github.com/jrick/logrotate/rotator"
	"github.com/omegasuite/btclog"
	"github.com/omegasuite/omega/consensus"
	"github.com/omegasuite/omega/minerchain"
	"github.com/omegasuite/omega/ovm"
	"github.com/omegasuite/omega/token"
)

// logWriter implements an io.Writer that outputs to both standard output and
// the write-end pipe of an initialized log rotator.
type logWriter struct{}

func (logWriter) Write(p []byte) (n int, err error) {
	os.Stdout.Write(p)
	logRotator.Write(p)
	return len(p), nil
}

// Loggers per subsystem.  A single backend logger is created and all subsytem
// loggers created from it will write to the backend.  When adding new
// subsystems, add the subsystem logger variable here and to the
// subsystemLoggers map.
//
// Loggers can not be used before the log rotator has been initialized with a
// log file.  This must be performed early during application startup by calling
// initLogRotator.
var (
	// backendLog is the logging backend used to create all subsystem loggers.
	// The backend must not be used before the log rotator has been initialized,
	// or data races and/or nil pointer dereferences will occur.
	backendLog = btclog.NewBackend(logWriter{})

	// logRotator is one of the logging outputs.  It should be closed on
	// application shutdown.
	logRotator *rotator.Rotator

	adxrLog = backendLog.Logger("ADXR", 0xFFFF)
	amgrLog = backendLog.Logger("AMGR", 0xFFFF)
	cmgrLog = backendLog.Logger("CMGR", 0xFFFF)
	bcdbLog = backendLog.Logger("BCDB", 0xFFFF)
	btcdLog = backendLog.Logger("BTCD", 0xFFFF)
	chanLog = backendLog.Logger("CHAN", 0xFFFF)
	discLog = backendLog.Logger("DISC", 0xFFFF)
	indxLog = backendLog.Logger("INDX", 0xFFFF)
	minrLog = backendLog.Logger("MINR", 0xFFFF)
	peerLog = backendLog.Logger("PEER", 0xFFFF)
	rpcsLog = backendLog.Logger("RPCS", 0xFFFF)
	scrpLog = backendLog.Logger("SCRP", 0xFFFF)
	srvrLog = backendLog.Logger("SRVR", 0xFFFF)
	syncLog = backendLog.Logger("SYNC", 0xFFFF)
	txmpLog = backendLog.Logger("TXMP", 0xFFFF)
	ovmLog = backendLog.Logger("OVM", 0xFFFF)
	consensusLog = backendLog.Logger("CNSS", 0xFFFF)
	minerLog = backendLog.Logger("MNER", 0xFFFF)
	tokenLog = backendLog.Logger("TKN", 0xFFFF)
)

// Initialize package-global logger variables.
func init() {
	addrmgr.UseLogger(amgrLog)
	amgrLog.SetLevel(btclog.LevelTrace)

	connmgr.UseLogger(cmgrLog)
	cmgrLog.SetLevel(btclog.LevelTrace)

	database.UseLogger(btclog.Disabled)	// bcdbLog)
	blockchain.UseLogger(chanLog)
	chanLog.SetLevel(btclog.LevelTrace)

	indexers.UseLogger(btclog.Disabled)	// indxLog)
	mining.UseLogger(btclog.Disabled)	// minrLog)
	cpuminer.UseLogger(minrLog)
	peer.UseLogger(peerLog)
	peerLog.SetLevel(btclog.LevelTrace)
//	UseLogger(scrpLog)

	netsync.UseLogger(syncLog)
//	syncLog.SetLevel(btclog.LevelWarn)
	syncLog.SetLevel(btclog.LevelTrace)

	mempool.UseLogger(btclog.Disabled)	// txmpLog)
	ovm.UseLogger(btclog.Disabled)	// ovmLog)
	consensus.UseLogger(consensusLog)
	minerchain.UseLogger(minerLog)
	token.UseLogger(btclog.Disabled)	// tokenLog)

	btcdLog.SetLevel(btclog.LevelTrace)

	srvrLog = btclog.Disabled
}

func debugLevel() {
/*
	amgrLog.SetLevel(btclog.LevelDebug)
	cmgrLog.SetLevel(btclog.LevelDebug)
	chanLog.SetLevel(btclog.LevelDebug)
	peerLog.SetLevel(btclog.LevelDebug)
	syncLog.SetLevel(btclog.LevelDebug)
	btcdLog.SetLevel(btclog.LevelDebug)
 */
}

// subsystemLoggers maps each subsystem identifier to its associated logger.
var subsystemLoggers = map[string]btclog.Logger{
	"ADXR": adxrLog,
	"AMGR": amgrLog,
	"CMGR": cmgrLog,
	"BCDB": bcdbLog,
	"BTCD": btcdLog,
	"CHAN": chanLog,
	"DISC": discLog,
	"INDX": indxLog,
	"MINR": minrLog,
	"PEER": peerLog,
	"RPCS": rpcsLog,
	"SCRP": scrpLog,
	"SRVR": srvrLog,
	"SYNC": syncLog,
	"TXMP": txmpLog,
}

// initLogRotator initializes the logging rotater to write logs to logFile and
// create roll files in the same directory.  It must be called before the
// package-global log rotater variables are used.
func initLogRotator(logFile string) {
	logDir, _ := filepath.Split(logFile)
	err := os.MkdirAll(logDir, 0700)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create log directory: %v\n", err)
		os.Exit(1)
	}
	r, err := rotator.New(logFile, 10*1024, false, 3)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create file rotator: %v\n", err)
		os.Exit(1)
	}

	logRotator = r
}

// setLogLevel sets the logging level for provided subsystem.  Invalid
// subsystems are ignored.  Uninitialized subsystems are dynamically created as
// needed.
func setLogLevel(subsystemID string, logLevel string) {
	// Ignore invalid subsystems.
	logger, ok := subsystemLoggers[subsystemID]
	if !ok {
		return
	}

	// Defaults to info if the log level is invalid.
	level, _ := btclog.LevelFromString(logLevel)
	logger.SetLevel(level)
}

// setLogLevels sets the log level for all subsystem loggers to the passed
// level.  It also dynamically creates the subsystem loggers as needed, so it
// can be used to initialize the logging system.
func setLogLevels(logLevel string) {
	// Configure all sub-systems with the new logging level.  Dynamically
	// create loggers as needed.
	for subsystemID := range subsystemLoggers {
		setLogLevel(subsystemID, logLevel)
	}
}

// directionString is a helper function that returns a string that represents
// the direction of a connection (inbound or outbound).
func directionString(inbound bool) string {
	if inbound {
		return "inbound"
	}
	return "outbound"
}

// pickNoun returns the singular or plural form of a noun depending
// on the count n.
func pickNoun(n uint64, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}


// LogClosure is a closure that can be printed with %v to be used to
// generate expensive-to-create data for a detailed log level and avoid doing
// the work if the data isn't printed.
type logClosure func() string

func (c logClosure) String() string {
	return c()
}

func newLogClosure(c func() string) logClosure {
	return logClosure(c)
}
