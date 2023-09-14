// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (C) 2019-2021 Omegasuite developer
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"fmt"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/consensus"
	"io/ioutil"
	"strings"

	//	"strconv"
	//	"strings"

	//	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	//	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	//	"syscall"
	"time"

	"github.com/omegasuite/btcd/blockchain/indexers"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/limits"
)

const (
	// blockDbNamePrefix is the prefix for the block database name.  The
	// database type is appended to this value to form the full block
	// database name.
	blockDbNamePrefix = "blocks"
	minerDbNamePrefix = "miners"
)

var (
	cfg *config
)

// winServiceMain is only invoked on Windows.  It detects when btcd is running
// as a service and reacts accordingly.
var winServiceMain func() (bool, error)

// Set by the linker.
var CompileTime string
var Server *server

// go build -ldflags "-X main.CompileTime='$(date)'"

// btcdMain is the real main function for btcd.  It is necessary to work around
// the fact that deferred functions do not run when os.Exit() is called.  The
// optional serverChan parameter is mainly used by the service code to be
// notified with the server once it is setup so it can gracefully stop it when
// requested from the service control manager.
func btcdMain(serverChan chan<- *server) error {
	fmt.Printf("OMGD built at %s\n", CompileTime)
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	tcfg, _, err := loadConfig()
	if err != nil {
		return err
	}

	debugLevel()

	cfg = tcfg
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	// Get a channel that will be closed when a shutdown signal has been
	// triggered either from an OS signal such as SIGINT (Ctrl+C) or from
	// another subsystem such as the RPC server.
	interrupt := interruptListener()

	// Show version at startup.
	btcdLog.Infof("Version %s", version())

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			listenAddr := net.JoinHostPort("", cfg.Profile)
			btcdLog.Infof("Profile server listening on %s", listenAddr)
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			btcdLog.Errorf("%v", http.ListenAndServe(listenAddr, nil))
		}()
	}

	// Write cpu profile if requested.
	if cfg.CPUProfile != "" {
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			btcdLog.Errorf("Unable to create cpu profile: %v", err)
			return err
		}
		pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	// Perform upgrades to btcd as new versions require it.
	if err := doUpgrades(); err != nil {
		btcdLog.Errorf("%v", err)
		return err
	}

	// Return now if an interrupt signal was triggered.
	if interruptRequested(interrupt) {
		return nil
	}

	// Load the block database.
	db, err := loadBlockDB()
	if err != nil {
		btcdLog.Errorf("%v", err)
		return err
	}

	// Load the block database.
	minerdb, err := loadMinerDB()
	if err != nil {
		btcdLog.Errorf("%v", err)
		return err
	}

	defer func() {
		// Ensure the database is sync'd and closed on shutdown.
		btcdLog.Infof("Gracefully shutting down the database...")
		db.Close()
		btcdLog.Infof("db Closed")
		minerdb.Close()
		btcdLog.Infof("minerdb Closed")
	}()

	// Return now if an interrupt signal was triggered.
	if interruptRequested(interrupt) {
		return nil
	}

	// Drop indexes and exit if requested.
	//
	// NOTE: The order is important here because dropping the tx index also
	// drops the address index since it relies on it.
	if cfg.DropAddrIndex {
		if err := indexers.DropAddrIndex(db, interrupt); err != nil {
			btcdLog.Errorf("%v", err)
			return err
		}

		return nil
	}
	if cfg.DropTxIndex {
		if err := indexers.DropTxIndex(db, interrupt); err != nil {
			btcdLog.Errorf("%v", err)
			return err
		}

		return nil
	}
	if cfg.DropCfIndex {
		if err := indexers.DropCfIndex(db, interrupt); err != nil {
			btcdLog.Errorf("%v", err)
			return err
		}

		return nil
	}

	activeNetParams.Params.MinRelayTxFee = int64(cfg.minRelayTxFee)

	if cfg.Generate && len(cfg.privateKeys) == 0 {
		// read from stdin. for security.
		// expect user to do something like: echo privkey | btcd
		fmt.Printf("Private Key in GIF ... ")
		input := make(chan string)
		go func() {
			var pvk [80]byte
			n, err := os.Stdin.Read(pvk[:])
			if err == nil {
				input <- string(pvk[:n])
			}
		}()

		select {
		case pvk := <-input:
			dwif, err := btcutil.DecodeWIF(pvk)
			if err == nil {
				privKey := dwif.PrivKey
				pkaddr, err := btcutil.NewAddressPubKey(dwif.SerializePubKey(), activeNetParams.Params)
				if err == nil {
					addr := pkaddr.AddressPubKeyHash()
					if addr.IsForNet(activeNetParams.Params) {
						cfg.miningAddrs = append(cfg.miningAddrs, addr)
						cfg.signAddress = append(cfg.signAddress, addr)
						cfg.privateKeys = append(cfg.privateKeys, privKey)
					}
				}
			}

		case <-time.After(time.Second * 30):
			// time out, ignore input
		}
	}

	activeNetParams.Params.ExternalIPs = tcfg.ExternalIPs
	activeNetParams.Params.ContractReqExp = tcfg.ContractReqExp
	activeNetParams.Params.LogBlockTime = tcfg.LogBlockTime

	activeNetParams.Params.ChainCurrentStd = time.Hour * time.Duration(tcfg.ChainCurrentStd)
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	activeNetParams.Params.SigVeriConcurrency = cfg.Concurrency

	// Create server and start it.
	server, err := newServer(cfg.Listeners, db, minerdb, activeNetParams.Params,
		interrupt)
	if err != nil {
		// TODO: this logging could do with some beautifying.
		btcdLog.Errorf("Unable to start server on %v: %v",
			cfg.Listeners, err)
		return err
	}

	Server = server

	defer func() {
		if len(cfg.privateKeys) != 0 && cfg.Generate {
			btcdLog.Infof("Gracefully shutting down consensus server...")
			consensus.Shutdown()
			btcdLog.Infof("consensus Server shutdown complete")
		}

		btcdLog.Infof("Gracefully shutting down the server...")
		server.Stop()

		btcdLog.Infof(" server Stopped")
		server.WaitForShutdown()
		btcdLog.Infof("Server shutdown complete")
	}()

	if cfg.Settip != "" {
		tips := strings.Split(cfg.Settip, ":")
		if !setTip(tips[0], tips[1], server.chain) {
			return nil
		}
	}

	if len(cfg.privateKeys) != 0 && cfg.Generate {
		go consensus.Consensus(server, cfg.DataDir, cfg.signAddress, activeNetParams.Params)
		for _, sa := range cfg.signAddress {
			btcdLog.Infof("Address of miner %s", sa.String())
		}
	} else {
		go consensus.SetupRelay(server)
	}

	flag := uint64(0)
	maintenance := []byte("maintenance")
	server.db.View(func(dbTx database.Tx) error {
		mflag := dbTx.Metadata().Get(maintenance)
		if mflag != nil {
			flag = binary.LittleEndian.Uint64(mflag)
		}
		return nil
	})

	if cfg.ReUtxo || (flag&1) == 0 {
		server.chain.Rebuildutxo(server.txIndex)
		server.db.Update(func(dbTx database.Tx) error {
			flag |= 1
			var b [8]byte
			binary.LittleEndian.PutUint64(b[:], flag)
			dbTx.Metadata().Put(maintenance, b[:])
			return nil
		})
	}

	server.Start()
	if serverChan != nil {
		serverChan <- server
	}

	if ((cfg.MemLimit != 0 && runtime.GOOS == "linux") || cfg.ExitOnStall) && !cfg.TestNet && !cfg.SimNet {
		var live int64
		server.chain.Subscribe(func(notification *blockchain.Notification) {
			switch notification.Type {
			case blockchain.NTBlockConnected:
				live = time.Now().Unix()
			}
		})

		pid := os.Getpid()
		stat := fmt.Sprintf("/proc/%d/statm", pid)

		go func() {
			for {
				time.Sleep(10 * time.Minute)
				if cfg.ExitOnStall && time.Now().Unix()-live > 600 {
					var wbuf bytes.Buffer
					pprof.Lookup("mutex").WriteTo(&wbuf, 1)
					pprof.Lookup("goroutine").WriteTo(&wbuf, 1)
					btcdLog.Infof("pprof Info: \n%s", wbuf.String())
					break
				}
				if cfg.MemLimit != 0 && runtime.GOOS == "linux" {
					contents, err := ioutil.ReadFile(stat)

					if err != nil {
						continue
					}

					var mem uint32
					fmt.Sscanf("%d", string(contents), &mem)
					if mem > cfg.MemLimit {
						if cfg.Generate {
							// wait until not generating blocks
							for i := 30; i > 0 && server.cpuMiner.IsGenerating(); i-- {
								time.Sleep(20 * time.Second)
							}
							if server.cpuMiner.IsGenerating() {
								continue
							}
						}
						btcdLog.Infof("Voluntary shutdown for exceeding memory limit (%d).", mem)
						break
					}
				}
			}

			btcdLog.Infof("Voluntary shutdown after no new block for 10 min.")

			shutdownRequestChannel <- struct{}{}
		}()
	}

	fmt.Printf("The system is %s", runtime.GOOS)

	// Wait until the interrupt signal is received from an OS signal or
	// shutdown is requested through one of the subsystems such as the RPC
	// server.
	<-interrupt

	srvrLog.Infof("interrupt received, going to shut down")

	return nil
}

func setTip(tx, miner string, chain *blockchain.BlockChain) bool {
	fmt.Printf("Setting new tips %s & %s\n", tx, miner)
	txtip, err := chainhash.NewHashFromStr(tx)
	if err != nil || txtip == nil {
		fmt.Printf("Non-exist tx tip hash\n")
		return false
	}
	minertip, err := chainhash.NewHashFromStr(miner)
	if err != nil || minertip == nil {
		fmt.Printf("Non-exist miner tip hash\n")
		return false
	}

	txblk, err := chain.HashToBlock(txtip)
	if err != nil || txblk == nil {
		fmt.Printf("Non-exist tx tip")
		return false
	}
	minerblk, err := chain.Miners.DBBlockByHash(minertip)
	if err != nil || minerblk == nil {
		fmt.Printf("Non-exist miner tip\n")
		return false
	}

	state := chain.BestSnapshot()
	bestblk, _ := chain.HashToBlock(&minerblk.MsgBlock().BestBlock)
	bestheight := bestblk.Height()

	mstate := chain.Miners.BestSnapshot()

	if !chain.SameChain(*txtip, state.Hash) {
		fmt.Printf("New tx tip %s not in same chain as current tip %s\n", txtip.String(), state.Hash.String())
		return false
	}

	pb := minerblk.MsgBlock().PrevBlock
	for i := minerblk.Height() - 1; i > mstate.Height; i-- {
		fmt.Printf("Add miner block %s\n", pb.String())
		pbb, err := chain.Miners.DBBlockByHash(&pb)
		if err != nil || pbb == nil {
			fmt.Printf("New miner tip %s not in same chain as current tip %s\n", minertip.String(), mstate.Hash.String())
			return false
		}
		if !chain.SameChain(minerblk.MsgBlock().BestBlock, pbb.MsgBlock().BestBlock) {
			fmt.Printf("Best chain not in sync @ miner block %s width best block %s compare to current tip best block %s\n", pb.String(), pbb.MsgBlock().BestBlock.String(), minerblk.MsgBlock().BestBlock.String())
			return false
		}
		bestblk, _ := chain.HashToBlock(&pbb.MsgBlock().BestBlock)
		nbestheight := bestblk.Height()
		if nbestheight > bestheight {
			fmt.Printf("Best not in order\n")
			return false
		}
		bestheight = nbestheight
		pb = pbb.MsgBlock().PrevBlock
	}
	if !pb.IsEqual(&mstate.Hash) {
		fmt.Printf("New miner tip not in same chain as current tip\n")
		return false
	}

	attachNodes := list.New()

	node := chain.NodeByHash(txtip)
	forkNode := chain.NodeByHash(&state.Hash)
	for n := node; n != nil && n != forkNode; n = n.Parent {
		fmt.Printf("Add tx block %s\n", n.Hash.String())
		attachNodes.PushFront(n)
	}
	err = chain.FastReorganizeChain(attachNodes)
	if err != nil {
		panic("Tx FastReorganizeChain failed: " + err.Error())
	}

	attachNodes = list.New()
	mnode := chain.Miners.DeepNodeByHash(minertip)
	mforkNode := chain.Miners.DeepNodeByHash(&mstate.Hash)
	for n := mnode; n != nil && n != mforkNode; n = n.Parent {
		attachNodes.PushFront(n)
	}
	err = chain.Miners.FastReorganizeChain(attachNodes)

	if err != nil {
		panic("Miner FastReorganizeChain failed: " + err.Error())
	}
	return true
}

// removeRegressionDB removes the existing regression test database if running
// in regression test mode and it already exists.
func removeRegressionDB(dbPath string) error {
	// Don't do anything if not in regression test mode.
	if !cfg.RegressionTest {
		return nil
	}

	// Remove the old regression test database if it already exists.
	fi, err := os.Stat(dbPath)
	if err == nil {
		btcdLog.Infof("Removing regression test database from '%s'", dbPath)
		if fi.IsDir() {
			err := os.RemoveAll(dbPath)
			if err != nil {
				return err
			}
		} else {
			err := os.Remove(dbPath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// dbPath returns the path to the block database given a database type.
func blockDbPath(dbType string) string {
	// The database name is based on the database type.
	dbName := blockDbNamePrefix + "_" + dbType
	if dbType == "sqlite" {
		dbName = dbName + ".db"
	}
	dbPath := filepath.Join(cfg.DataDir, dbName)
	return dbPath
}

// dbPath returns the path to the block database given a database type.
func minerDbPath(dbType string) string {
	// The database name is based on the database type.
	dbName := minerDbNamePrefix + "_" + dbType
	if dbType == "sqlite" {
		dbName = dbName + ".db"
	}
	dbPath := filepath.Join(cfg.DataDir, dbName)
	return dbPath
}

// warnMultipleDBs shows a warning if multiple block database types are detected.
// This is not a situation most users want.  It is handy for development however
// to support multiple side-by-side databases.
func warnMultipleDBs() {
	// This is intentionally not using the known db types which depend
	// on the database types compiled into the binary since we want to
	// detect legacy db types as well.
	dbTypes := []string{"ffldb", "leveldb", "sqlite"}
	duplicateDbPaths := make([]string, 0, len(dbTypes)-1)
	for _, dbType := range dbTypes {
		if dbType == cfg.DbType {
			continue
		}

		// Store db path as a duplicate db if it exists.
		dbPath := blockDbPath(dbType)
		if fileExists(dbPath) {
			duplicateDbPaths = append(duplicateDbPaths, dbPath)
		}
	}

	// Warn if there are extra databases.
	if len(duplicateDbPaths) > 0 {
		selectedDbPath := blockDbPath(cfg.DbType)
		btcdLog.Warnf("WARNING: There are multiple block chain databases "+
			"using different database types.\nYou probably don't "+
			"want to waste disk space by having more than one.\n"+
			"Your current database is located at [%v].\nThe "+
			"additional database is located at %v", selectedDbPath,
			duplicateDbPaths)
	}
}

// loadBlockDB loads (or creates when needed) the block database taking into
// account the selected database backend and returns a handle to it.  It also
// contains additional logic such warning the user if there are multiple
// databases which consume space on the file system and ensuring the regression
// test database is clean when in regression test mode.
func loadBlockDB() (database.DB, error) {
	// The memdb backend does not have a file path associated with it, so
	// handle it uniquely.  We also don't want to worry about the multiple
	// database type warnings when running with the memory database.
	if cfg.DbType == "memdb" {
		btcdLog.Infof("Creating block database in memory.")
		db, err := database.Create(cfg.DbType)
		if err != nil {
			return nil, err
		}
		return db, nil
	}

	warnMultipleDBs()

	// The database name is based on the database type.
	dbPath := blockDbPath(cfg.DbType)

	// The regression test is special in that it needs a clean database for
	// each run, so remove it now if it already exists.
	removeRegressionDB(dbPath)

	btcdLog.Infof("Loading block database from '%s'", dbPath)
	db, err := database.Open(cfg.DbType, dbPath, activeNetParams.Net)
	if err != nil {
		// Return the error if it's not because the database doesn't
		// exist.
		if dbErr, ok := err.(database.Error); !ok || dbErr.ErrorCode !=
			database.ErrDbDoesNotExist {

			return nil, err
		}

		// Create the db if it does not exist.
		err = os.MkdirAll(cfg.DataDir, 0700)
		if err != nil {
			return nil, err
		}
		db, err = database.Create(cfg.DbType, dbPath, activeNetParams.Net)
		if err != nil {
			return nil, err
		}
	}

	btcdLog.Info("Block database loaded")
	return db, nil
}

// loadMinerDB loads (or creates when needed) the miner database taking into
// account the selected database backend and returns a handle to it.  It also
// contains additional logic such warning the user if there are multiple
// databases which consume space on the file system and ensuring the regression
// test database is clean when in regression test mode.
func loadMinerDB() (database.DB, error) {
	// The memdb backend does not have a file path associated with it, so
	// handle it uniquely.  We also don't want to worry about the multiple
	// database type warnings when running with the memory database.
	if cfg.DbType == "memdb" {
		return nil, fmt.Errorf("Does not support miner database in memory.")
	}

	// The database name is based on the database type.
	dbPath := minerDbPath(cfg.DbType)

	// The regression test is special in that it needs a clean database for
	// each run, so remove it now if it already exists.
	removeRegressionDB(dbPath)

	btcdLog.Infof("Loading miner database from '%s'", dbPath)
	db, err := database.Open(cfg.DbType, dbPath, activeNetParams.Net)
	if err != nil {
		// Return the error if it's not because the database doesn't
		// exist.
		if dbErr, ok := err.(database.Error); !ok || dbErr.ErrorCode !=
			database.ErrDbDoesNotExist {

			return nil, err
		}

		// Create the db if it does not exist.
		err = os.MkdirAll(cfg.DataDir, 0700)
		if err != nil {
			return nil, err
		}
		db, err = database.Create(cfg.DbType, dbPath, activeNetParams.Net)
		if err != nil {
			return nil, err
		}
	}

	btcdLog.Info("Miner database loaded")
	return db, nil
}

func main() {
	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Block and transaction processing can cause bursty allocations.  This
	// limits the garbage collector from excessively overallocating during
	// bursts.  This value was arrived at with the help of profiling live
	// usage.
	debug.SetGCPercent(10)

	// Up some limits.
	if err := limits.SetLimits(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set limits: %v\n", err)
		os.Exit(1)
	}

	// Call serviceMain on Windows to handle running as a service.  When
	// the return isService flag is true, exit now since we ran as a
	// service.  Otherwise, just fall through to normal operation.
	if runtime.GOOS == "windows" {
		isService, err := winServiceMain()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if isService {
			os.Exit(0)
		}
	}

	// Work around defer not working after os.Exit()
	if err := btcdMain(nil); err != nil {
		os.Exit(1)
	}
}
