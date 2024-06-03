// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (C) 2019-2021 Omegasuite developer
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"container/list"
	"fmt"
	"github.com/omegasuite/famofchains/btcd/blockchain"
	"github.com/omegasuite/famofchains/btcd/chaincfg"
	"github.com/omegasuite/famofchains/btcutil"
	"github.com/omegasuite/famofchains/omega/consensus"
	"strings"
	"sync"

	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"time"

	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/famofchains/btcd/blockchain/indexers"
	"github.com/omegasuite/famofchains/btcd/database"
	"github.com/omegasuite/famofchains/btcd/limits"
)

const (
	// blockDbNamePrefix is the prefix for the block database name.  The
	// database type is appended to this value to form the full block
	// database name.
	blockDbNamePrefix = "blocks"
	minerDbNamePrefix = "miners"
)

type protocol struct {
	cfg             *config
	Server          *server
	IsSvp           bool
	db              database.DB
	minerdb         database.DB
	activeNetParams *params
	running         bool
}

var protocols []*protocol

func prepareServer(tcfg *config) (*protocol, bool) {
	// Get a channel that will be closed when a shutdown signal has been
	// triggered either from an OS signal such as SIGINT (Ctrl+C) or from
	// another subsystem such as the RPC server.
	interrupt := interruptListener()

	// Load the block database.
	db, err := loadBlockDB(tcfg)
	if err != nil {
		btcdLog.Errorf("%v", err)
		return nil, true
	}

	prot := &protocol{
		cfg:     tcfg,
		db:      db,
		running: false,
	}

	// Load the block database.
	minerdb, err := loadMinerDB(tcfg)
	if err != nil {
		btcdLog.Errorf("%v", err)
		return prot, true
	}

	prot.minerdb = minerdb

	// Return now if an interrupt signal was triggered.
	if interruptRequested(interrupt) {
		return prot, true
	}

	// Drop indexes and exit if requested.
	//
	// NOTE: The order is important here because dropping the tx index also
	// drops the address index since it relies on it.
	if tcfg.DropAddrIndex {
		if err := indexers.DropAddrIndex(db, interrupt); err != nil {
			btcdLog.Errorf("%v", err)
			return prot, true
		}

		return prot, true
	}
	if tcfg.DropTxIndex {
		if err := indexers.DropTxIndex(db, interrupt); err != nil {
			btcdLog.Errorf("%v", err)
			return prot, true
		}

		return prot, true
	}

	prot.activeNetParams = &params{
		Params:  &chaincfg.MainNetParams,
		rpcPort: "8789",
	}

	prot.activeNetParams.Params.MinRelayTxFee = int64(tcfg.minRelayTxFee)

	if tcfg.Generate && len(tcfg.privateKeys) == 0 {
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
						tcfg.miningAddrs = append(tcfg.miningAddrs, addr)
						tcfg.signAddress = append(tcfg.signAddress, addr)
						tcfg.privateKeys = append(tcfg.privateKeys, privKey)
					}
				}
			}

		case <-time.After(time.Second * 30):
			// time out, ignore input
		}
	}

	prot.activeNetParams.Params.ExternalIPs = tcfg.ExternalIPs
	prot.activeNetParams.Params.ContractReqExp = tcfg.ContractReqExp
	prot.activeNetParams.Params.LogBlockTime = tcfg.LogBlockTime

	prot.activeNetParams.Params.ChainCurrentStd = time.Hour * time.Duration(tcfg.ChainCurrentStd)
	if tcfg.Concurrency <= 0 {
		tcfg.Concurrency = 1
	}
	prot.activeNetParams.Params.SigVeriConcurrency = tcfg.Concurrency

	// Create server and start it.
	server, err := newServer(tcfg.Listeners, db, minerdb, prot, interrupt)
	if err != nil {
		// TODO: this logging could do with some beautifying.
		btcdLog.Errorf("Unable to start server on %v: %v",
			tcfg.Listeners, err)
		return prot, true
	}

	prot.Server = server

	defer func() {
		if len(tcfg.privateKeys) != 0 && tcfg.Generate {
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

	if tcfg.Settip != "" {
		tips := strings.Split(tcfg.Settip, ":")
		if !setTip(tips[0], tips[1], server.chain) {
			return nil, false
		}
	}

	if tcfg.Accounts {
		// print balances of all addresses
		accounts := server.chain.GetAccounts()
		for addr, bal := range accounts {
			var address btcutil.Address
			switch addr[0] {
			case server.chainParams.PubKeyHashAddrID:
				address, _ = btcutil.NewAddressPubKeyHash(addr[1:], server.chainParams)
			case server.chainParams.ContractAddrID:
				address, _ = btcutil.NewAddressContract(addr[1:], server.chainParams)
			case server.chainParams.ScriptHashAddrID:
				address, _ = btcutil.NewAddressScriptHash(addr[1:], server.chainParams)
			case server.chainParams.MultiSigAddrID:
				address, _ = btcutil.NewAddressMultiSig(addr[1:], server.chainParams)
			default:
				continue
			}
			fmt.Printf("%s, %f\n", address.EncodeAddress(), float64(bal)/1e8)
		}
	}

	return prot, false
}

func runserver(p *protocol) {
	interrupt := interruptListener()

	if !p.IsSvp && p.running {
		if len(p.cfg.privateKeys) != 0 && p.cfg.Generate {
			go consensus.Consensus(p.Server, p.cfg.DataDir, p.cfg.signAddress, activeNetParams.Params)
			for _, sa := range p.cfg.signAddress {
				btcdLog.Infof("Address of miner %s", sa.String())
			}
		} else {
			go consensus.SetupRelay(p.Server)
		}
	}

	if p.running {
		p.Server.Start()
	}

	fmt.Printf("The system is %s", runtime.GOOS)

	// Wait until the interrupt signal is received from an OS signal or
	// shutdown is requested through one of the subsystems such as the RPC
	// server.
	<-interrupt

	cleanup(p)

	srvrLog.Infof("interrupt received, going to shut down")
}

func cleanup(p *protocol) {
	if p.Server != nil {
		if len(p.cfg.privateKeys) != 0 && p.cfg.Generate && !p.IsSvp {
			btcdLog.Infof("Gracefully shutting down consensus server...")
			consensus.Shutdown()
			btcdLog.Infof("consensus Server shutdown complete")
		}

		btcdLog.Infof("Gracefully shutting down the server...")
		p.Server.Stop()

		btcdLog.Infof(" server Stopped")
		p.Server.WaitForShutdown()
	}
	btcdLog.Infof("Server shutdown complete")

	// Ensure the database is sync'd and closed on shutdown.
	btcdLog.Infof("Gracefully shutting down the database...")
	if p.db != nil {
		p.db.Close()
	}
	btcdLog.Infof("db Closed")
	if p.minerdb != nil {
		p.minerdb.Close()
	}
	btcdLog.Infof("minerdb Closed")

	if p.running {
		wg.Done()
	}
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
func removeRegressionDB(dbPath string, cfg *config) error {
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
func blockDbPath(dbType string, cfg *config) string {
	// The database name is based on the database type.
	dbName := blockDbNamePrefix + "_" + dbType
	if dbType == "sqlite" {
		dbName = dbName + ".db"
	}
	dbPath := filepath.Join(cfg.DataDir, dbName)
	return dbPath
}

// dbPath returns the path to the block database given a database type.
func minerDbPath(dbType string, cfg *config) string {
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
func warnMultipleDBs(cfg *config) {
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
		dbPath := blockDbPath(dbType, cfg)
		if fileExists(dbPath) {
			duplicateDbPaths = append(duplicateDbPaths, dbPath)
		}
	}

	// Warn if there are extra databases.
	if len(duplicateDbPaths) > 0 {
		selectedDbPath := blockDbPath(cfg.DbType, cfg)
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
func loadBlockDB(cfg *config) (database.DB, error) {
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

	warnMultipleDBs(cfg)

	// The database name is based on the database type.
	dbPath := blockDbPath(cfg.DbType, cfg)

	// The regression test is special in that it needs a clean database for
	// each run, so remove it now if it already exists.
	removeRegressionDB(dbPath, cfg)

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
func loadMinerDB(cfg *config) (database.DB, error) {
	// The memdb backend does not have a file path associated with it, so
	// handle it uniquely.  We also don't want to worry about the multiple
	// database type warnings when running with the memory database.
	if cfg.DbType == "memdb" {
		return nil, fmt.Errorf("Does not support miner database in memory.")
	}

	// The database name is based on the database type.
	dbPath := minerDbPath(cfg.DbType, cfg)

	// The regression test is special in that it needs a clean database for
	// each run, so remove it now if it already exists.
	removeRegressionDB(dbPath, cfg)

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

var wg sync.WaitGroup

func main() {
	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	tcfg, _, err := loadConfig(1) // load only the basic config
	if err != nil {
		os.Exit(1)
	}

	debugLevel()

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
	if tcfg.Profile != "" {
		go func() {
			listenAddr := net.JoinHostPort("", tcfg.Profile)
			btcdLog.Infof("Profile server listening on %s", listenAddr)
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			btcdLog.Errorf("%v", http.ListenAndServe(listenAddr, nil))
		}()
	}

	// Write cpu profile if requested.
	if tcfg.CPUProfile != "" {
		f, err := os.Create(tcfg.CPUProfile)
		if err != nil {
			btcdLog.Errorf("Unable to create cpu profile: %v", err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	// Return now if an interrupt signal was triggered.
	if interruptRequested(interrupt) {
		os.Exit(1)
	}

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

	protocols = make([]*protocol, 0)

	// Work around defer not working after os.Exit()
	p, quit := prepareServer(tcfg)
	if quit && p != nil {
		cleanup(p)
		os.Exit(1)
	}

	p.IsSvp = false
	protocols = append(protocols, p)

	tcfg, _, err = loadConfig(2) // load only the basic config
	if err != nil {
		os.Exit(1)
	}

	// Work around defer not working after os.Exit()
	p, quit = prepareServer(tcfg)
	if quit && p != nil {
		cleanup(p)
		os.Exit(1)
	}

	p.IsSvp = true
	protocols = append(protocols, p)
	/*
		err = protocols[0].Server.db.View(func(tx database.Tx) error {
			bucket := tx.Metadata().Bucket([]byte("SVP Clients"))
			cursor := bucket.Cursor()
			for ok := cursor.First(); ok; ok = cursor.Next() {
				cfg := config{}
				cfg.deserialize(cursor.Value())
				wg.Add(1)
				p, quit := prepareServer(&cfg)
				if quit {
					cleanup(p)
					return fmt.Errorf("fail to prepare Server")
				}

				if p != nil {
					p.IsSvp = true
					protocols = append(protocols, p)
				}
			}
			return nil
		})

		if err != nil {
			for _, p := range protocols {
				cleanup(p)
			}
			os.Exit(1)
		}
	*/

	for _, p := range protocols {
		wg.Add(1)
		p.running = true
		go runserver(p)
	}

	wg.Wait()
}
