// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (C) 2019-2021 Omegasuite developer
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"container/list"
	//	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/omegasuite/famofchains/btcd/blockchain"
	"github.com/omegasuite/famofchains/btcd/chaincfg"
	"github.com/omegasuite/famofchains/btcd/wire"
	"github.com/omegasuite/famofchains/btcd/wire/common"
	"github.com/omegasuite/famofchains/btcutil"
	"github.com/omegasuite/famofchains/omega/chainmap"
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

type Protocol struct {
	cfg             *config
	Server          *server
	IsSvp           bool
	db              database.DB
	minerdb         database.DB
	activeNetParams *chaincfg.Params
	running         bool
}

var protocols []*Protocol

func prepareServer(tcfg *config, pdb database.DB, globalParams *chaincfg.GlobalParams, svp bool) (*Protocol, bool) {
	// Get a channel that will be closed when a shutdown signal has been
	// triggered either from an OS signal such as SIGINT (Ctrl+C) or from
	// another subsystem such as the RPC server.
	interrupt := interruptListener()

	var db, minerdb database.DB
	var err error

	db = pdb
	// Load the block database.
	if pdb == nil {
		// Load the block database.
		db, err = loadBlockDB(tcfg)
		if err != nil {
			btcdLog.Errorf("%v", err)
			return nil, true
		}

		db.Update(func(dbTx database.Tx) error {
			meta := dbTx.Metadata()
			meta.CreateBucket([]byte("ChainMap"))
			return nil
		})
	}

	prot := &Protocol{
		cfg:     tcfg,
		db:      db,
		running: false,
		IsSvp:   svp,
	}

	// Load the block database.
	minerdb, err = loadMinerDB(tcfg)
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

	prot.activeNetParams = activeNetParams
	if globalParams != nil {
		prot.activeNetParams.GlobalParams = *globalParams
		//		prot.activeNetParams.PowLimit = blockchain.CompactToBig(globalParams.PowLimitBits)
	}
	if tcfg.TestNet {
		prot.activeNetParams.GenesisHash = chaincfg.TestNet3GenesisHash[uint32(tcfg.NetMagic)]
		prot.activeNetParams.GenesisBlock = chaincfg.TestNet3GenesisBlock[uint32(tcfg.NetMagic)]
		prot.activeNetParams.GenesisMinerHash = chaincfg.TestNet3GenesisMinerHash[uint32(tcfg.NetMagic)]
		prot.activeNetParams.GenesisMinerBlock = chaincfg.TestNet3GenesisMinerBlock[uint32(tcfg.NetMagic)]
	} else {
		prot.activeNetParams.GenesisHash = chaincfg.GenesisHash[uint32(tcfg.NetMagic)]
		prot.activeNetParams.GenesisBlock = chaincfg.GenesisBlock[uint32(tcfg.NetMagic)]
		prot.activeNetParams.GenesisMinerHash = chaincfg.GenesisMinerHash[uint32(tcfg.NetMagic)]
		prot.activeNetParams.GenesisMinerBlock = chaincfg.GenesisMinerBlock[uint32(tcfg.NetMagic)]
	}

	prot.activeNetParams.MinRelayTxFee = int64(tcfg.minRelayTxFee)

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
				pkaddr, err := btcutil.NewAddressPubKey(dwif.SerializePubKey(), prot.activeNetParams)
				if pkaddr.Format() != btcutil.PKFCompressed {
					btcdLog.Errorf("Private key is not compressed")
					return nil, true
				}
				if err == nil {
					addr := pkaddr.AddressPubKeyHash()
					if addr.IsForNet(activeNetParams) {
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

	prot.activeNetParams.ExternalIPs = tcfg.ExternalIPs
	prot.activeNetParams.ContractReqExp = tcfg.ContractReqExp
	prot.activeNetParams.LogBlockTime = tcfg.LogBlockTime
	for _, k := range tcfg.privateKeys {
		key := secp256k1.ModNScalar{}
		var bk [32]byte
		copy(bk[:], k.Serialize())
		key.SetBytes(&bk)
	}

	prot.activeNetParams.ChainCurrentStd = time.Hour * time.Duration(tcfg.ChainCurrentStd)
	if tcfg.Concurrency <= 0 {
		tcfg.Concurrency = 1
	}
	prot.activeNetParams.SigVeriConcurrency = tcfg.Concurrency

	prot.activeNetParams.AddChain = nil
	if tcfg.AddChain != "" {
		nc := &chainmap.ChainDescriptor{}
		err := json.Unmarshal([]byte(tcfg.AddChain), nc)
		if err != nil {
			btcdLog.Errorf("Unable to parse AddChain commanf %s", tcfg.AddChain)
			return nil, false
		}
		prot.activeNetParams.AddChain = nc
	}

	// Create server and start it.

	prot.activeNetParams.Net = prot.cfg.NetMagic
	servergr, err := newServer(tcfg.Listeners, db, minerdb, prot, interrupt)
	if err != nil {
		btcdLog.Errorf("Unable to start server on %v: %v",
			tcfg.Listeners, err)
		return prot, true
	}

	prot.Server = servergr

	defer func() {
		if len(tcfg.privateKeys) == 0 && tcfg.Generate {
			btcdLog.Infof("Gracefully shutting down consensus server...")
			consensus.Shutdown()
			btcdLog.Infof("consensus Server shutdown complete")

			btcdLog.Infof("Gracefully shutting down the server...")
			servergr.Stop()

			btcdLog.Infof(" server Stopped")
			servergr.WaitForShutdown()
			btcdLog.Infof("Server shutdown complete")
		}
	}()

	if tcfg.Settip != "" {
		tips := strings.Split(tcfg.Settip, ":")
		if !setTip(tips[0], tips[1], servergr.chain) {
			return nil, false
		}
	}

	if tcfg.Accounts {
		// print balances of all addresses
		accounts := servergr.chain.GetAccounts()
		for addr, bal := range accounts {
			var address btcutil.Address
			switch addr[0] {
			case servergr.chainParams.PubKeyHashAddrID:
				address, _ = btcutil.NewAddressPubKeyHash(addr[1:], servergr.chainParams)
			case servergr.chainParams.ContractAddrID:
				address, _ = btcutil.NewAddressContract(addr[1:], servergr.chainParams)
			case servergr.chainParams.ScriptHashAddrID:
				address, _ = btcutil.NewAddressScriptHash(addr[1:], servergr.chainParams)
			case servergr.chainParams.MultiSigAddrID:
				address, _ = btcutil.NewAddressMultiSig(addr[1:], servergr.chainParams)
			default:
				continue
			}
			for t, amt := range bal {
				fmt.Printf("%s, %x => %f\n", address.EncodeAddress(), t, float64(amt)/1e8)
			}
		}
	}

	return prot, false
}

func runserver(p *Protocol) {
	interrupt := interruptListener()

	if !p.IsSvp && p.running {
		if len(p.cfg.privateKeys) != 0 && p.cfg.Generate {
			go consensus.Consensus(p.Server, p.cfg.DataDir, p.cfg.signAddress, p.activeNetParams)
			for _, sa := range p.cfg.signAddress {
				btcdLog.Infof("Address of miner %s", sa.String())
			}
		} else {
			go consensus.SetupRelay(p.Server)
		}
	}

	if p.running {
		p.Server.Start()
		if p.Server.chainParams.ChainID == chaincfg.DefaultParentChainID {
			p.Server.Randcast(wire.NewMsgGetChainMap(uint32(len(chainmap.ChainMap))), nil)
		}
	}

	fmt.Printf("The system is %s", runtime.GOOS)

	// Wait until the interrupt signal is received from an OS signal or
	// shutdown is requested through one of the subsystems such as the RPC
	// server.
	<-interrupt

	cleanup(p)

	srvrLog.Infof("interrupt received, going to shut down")
}

func cleanup(p *Protocol) {
	if p.Server == nil {
		return
	}
	if len(p.cfg.privateKeys) != 0 && p.cfg.Generate && !p.IsSvp {
		btcdLog.Infof("%x Gracefully shutting down consensus server...", uint32(p.Server.chainParams.Net))
		go consensus.Shutdown()
		//			btcdLog.Infof("%x consensus Server shutdown complete", uint32(p.Server.chainParams.Net))
	}

	btcdLog.Infof("%x Gracefully shutting down the server...", uint32(p.Server.chainParams.Net))
	p.Server.Stop()

	btcdLog.Infof("%x WaitForShutdown", uint32(p.Server.chainParams.Net))

	p.Server.WaitForShutdown()
	btcdLog.Infof("%x server Stopped", uint32(p.Server.chainParams.Net))

	btcdLog.Infof("%x Server shutdown complete", uint32(p.Server.chainParams.Net))

	// Ensure the database is sync'd and closed on shutdown.
	btcdLog.Infof("%x Gracefully shutting down the database...", uint32(p.Server.chainParams.Net))
	if p.db != nil {
		p.db.Close()
	}
	btcdLog.Infof("%x db Closed", uint32(p.Server.chainParams.Net))
	if p.minerdb != nil {
		p.minerdb.Close()
	}
	btcdLog.Infof("%x minerdb Closed", uint32(p.Server.chainParams.Net))

	if p.running {
		p.running = false
		wg.Done()
	}
	btcdLog.Infof("%x done cleanup", uint32(p.Server.chainParams.Net))
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

func loadChainmapDB(tcfg *config) (database.DB, error) {
	path := strings.Split(tcfg.DataDir, "/")
	if len(path) == 1 {
		path = strings.Split(tcfg.DataDir, "\\")
	}
	path[len(path)-1] = "chainmap"
	dataDir := strings.Join(path, "/")

	db, err := database.Open(tcfg.DbType, dataDir, tcfg.NetMagic)
	if err != nil {
		// Return the error if it's not because the database doesn't
		// exist.
		if dbErr, ok := err.(database.Error); !ok || dbErr.ErrorCode !=
			database.ErrDbDoesNotExist {

			return nil, err
		}

		// Create the db if it does not exist.
		err = os.MkdirAll(tcfg.DataDir, 0700)
		if err != nil {
			return nil, err
		}
		db, err = database.Create(tcfg.DbType, dataDir, tcfg.NetMagic)
		if err != nil {
			return nil, err
		}
	}
	return db, nil
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
	db, err := database.Open(cfg.DbType, dbPath, cfg.NetMagic)
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
		db, err = database.Create(cfg.DbType, dbPath, cfg.NetMagic)
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
	db, err := database.Open(cfg.DbType, dbPath, cfg.NetMagic)
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
		db, err = database.Create(cfg.DbType, dbPath, cfg.NetMagic)
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

	tcfg, _, err := loadConfig("Main Options", 0) // chain main options
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

	activeNetParams.ChainCurrentStd = time.Hour * time.Duration(tcfg.ChainCurrentStd)
	if tcfg.Concurrency <= 0 {
		tcfg.Concurrency = 1
	}
	activeNetParams.SigVeriConcurrency = tcfg.Concurrency

	if chaincfg.DefaultChainID == chainmap.ROOT {
		s, _ := json.Marshal(activeNetParams.GlobalParams)
		chainmap.RootMeta.GlobalParams = string(s)
	}

	cmdb, err := loadChainmapDB(tcfg)
	if cmdb == nil || err != nil {
		os.Exit(1)
	}
	chainmap.LoadChainMap(cmdb, chaincfg.DefaultChainID == chainmap.ROOT)

	protocols = make([]*Protocol, 0)

	if _, ok := chainmap.ChainMap[chaincfg.DefaultParentChainID]; chaincfg.DefaultParentChainID != 0 && !ok {
		// create a svp server for parent
		fmt.Printf("loading parent options")
		pcfg, _, err := loadConfig("Parent Options", 0) // chain main options
		if err != nil {
			os.Exit(1)
		}
		pcfg.DbType = tcfg.DbType
		//		pcfg.LogDir = tcfg.LogDir
		//		pcfg.DataDir = tcfg.DataDir
		pcfg.NetMagic = common.OmegaNet(chainmap.ParentChain.Magic)

		fmt.Printf("parent options loaded, magic = %d", pcfg.NetMagic)

		pcfg.Generate = false
		pcfg.GenerateMiner = false
		// connect to parent chain but use main db
		p, quit := prepareServer(pcfg, cmdb, nil, false)
		if quit || p == nil {
			os.Exit(1)
		}
		p.cfg = pcfg
		p.running = true
		p.Server.syncManager.Passive()
		protocols = append(protocols, p)
		go runserver(p)
		time.Sleep(5 * time.Second)
		for done, i := false, 0; !done && i < 5; i++ {
			p.Server.Randcast(wire.NewMsgGetChainMap(uint32(0)), nil)
			time.Sleep(2 * time.Second)
			chainmap.LoadChainMap(cmdb, chaincfg.DefaultChainID == chainmap.ROOT)
			_, done = chainmap.ChainMap[chaincfg.DefaultParentChainID]
			if done {
				cmdb.Close()
				os.Exit(1)
			}
		}
		time.Sleep(2 * time.Minute)
		cmdb.Close()
		os.Exit(1)
	}

	// main chain
	fmt.Printf("loading main options, magic = %d", tcfg.NetMagic)
	p, quit := prepareServer(tcfg, nil, nil, false)
	if quit && p != nil {
		cleanup(p)
		os.Exit(1)
	} else if quit {
		os.Exit(1)
	}

	if tcfg.Clear != 0 {
		p.db.Update(func(tx database.Tx) error {
			meta := tx.Metadata()
			if tcfg.Clear&1 != 0 { // clear
				meta.DeleteBucket([]byte(common.INCOMINGPOOL))
				meta.CreateBucket([]byte(common.INCOMINGPOOL))
				meta.DeleteBucket([]byte(common.ROLLBACKPOOL))
				meta.CreateBucket([]byte(common.ROLLBACKPOOL))
			}
			if tcfg.Clear&8 != 0 { // clear
				meta.DeleteBucket([]byte(common.XCAssets))
				meta.CreateBucket([]byte(common.XCAssets))
			}

			return nil
		})

		cleanup(p)
		os.Exit(1)
	}

	Server := p.Server
	p.activeNetParams.MainChainID = p.activeNetParams.ChainID
	protocols = append(protocols, p)

	time.Sleep(3 * time.Second)

	for _, c := range chainmap.ChainMap {
		if c.ChainID == Server.chainParams.ChainID {
			continue
		}
		if c.ChainID != chaincfg.DefaultParentChainID && c.Parent != Server.chainParams.ChainID {
			continue
		}
		time.Sleep(3 * time.Second)
		dparams := &chaincfg.GlobalParams{}
		if err := json.Unmarshal([]byte(c.GlobalParams), dparams); err != nil {
			os.Exit(1)
		}

		svpid := fmt.Sprintf("%x", uint32(dparams.Net))

		fmt.Printf("loading SVP options, ChainID = %d magic = %x", c.ChainID, uint32(dparams.Net))

		vcfg, _, err := loadConfig(svpid, dparams.Net)
		if vcfg == nil || err != nil {
			os.Exit(1)
		}
		vcfg.NetMagic = dparams.Net
		vcfg.GenerateMiner = false
		vcfg.Generate = false
		vcfg.privateKeys = nil
		vcfg.PrivKeys = nil
		vcfg.MiningAddrs = nil
		vcfg.Collateral = nil
		vcfg.AddrIndex = false
		vcfg.BlocksOnly = false
		vcfg.collateral = nil
		vcfg.DisablePOWMining = true
		vcfg.miningAddrs = nil
		vcfg.TxIndex = false
		vcfg.AddrIndex = false
		//		vcfg.NoCFilters = true
		vcfg.signAddress = nil

		fmt.Printf("datadir = %s\n", vcfg.DataDir)

		// svp chain
		q, quit := prepareServer(vcfg, nil, dparams, true)
		if quit || q == nil {
			if q != nil {
				cleanup(q)
			}
			chainmap.Close()
			for _, r := range protocols {
				cleanup(r)
			}
			os.Exit(1)
		}

		q.activeNetParams.MainChainID = protocols[0].activeNetParams.ChainID
		q.Server.chain.MainChain = protocols[0].Server.chain

		protocols = append(protocols, q)
		if q.Server.chainParams.ChainID == chaincfg.DefaultParentChainID {
			q.Server.Randcast(wire.NewMsgGetChainMap(uint32(len(chainmap.ChainMap))), nil)
		}
	}

	for i, p := range protocols {
		wg.Add(1)
		p.running = true

		go runserver(p)

		if i > 0 {
			go retrievedefs(protocols[0], protocols[i])
		} else {
			go checkfinal()
		}
		time.Sleep(3 * time.Second)
	}

	wg.Wait()
	chainmap.Close()
	return
}

var btcHeight int32

func checkfinal() {
	interrupt := interruptListener()

	for true {
		select {
		case <-interrupt:
			return
		default:
		}

		protocols[0].db.Update(func(dbtx database.Tx) error {
			bucket := dbtx.Metadata().Bucket([]byte(common.INCOMINGPOOL))
			cursor := bucket.Cursor()
			for ok := cursor.First(); ok; ok = cursor.Next() {
				xdata := wire.XchainData{}
				if err := xdata.DeSerialize(cursor.Value()); err != nil || xdata.Finalized != 0 {
					continue
				}
				if xdata.Txs[0].Txo.PkScript[21] != 0x66 {
					fmt.Printf("bad XchainData")
				}
				for _, p := range protocols[1:] {
					chain := chainmap.ChainMap[p.Server.chainParams.ChainID]
					if xdata.ChainID&0x400000 != 0 {
						switch xdata.ChainID {
						case common.BTCCHAINID:
							if btcHeight >= xdata.Height+7 {
								xdata.Finalized = -int32(time.Now().Unix() + 120)
								bucket.Put(cursor.Key(), xdata.Serialize())
								break
							}
						}
					} else if chain.PassThru(protocols[0].Server.chainParams.MainChainID, xdata.ChainID) {
						p.Server.Randcast(wire.NewMsgFinalized(xdata.ChainID, xdata.Hash), nil)
					}
				}
			}
			return nil
		})
		time.Sleep(15 * time.Second)
	}
}

func retrievedefs(p *Protocol, q *Protocol) {
	interrupt := interruptListener()

	for true {
		select {
		case <-interrupt:
			return
		default:
		}

		p.db.View(func(dbtx database.Tx) error {
			bucket := dbtx.Metadata().Bucket([]byte("RECVTXPOOL"))
			cursor := bucket.Cursor()
			for ok := cursor.First(); ok; ok = cursor.Next() {
				var tx wire.MsgTx
				var r bytes.Reader
				r.Reset(cursor.Value()[:])
				tx.Deserialize(&r)

				undefined := p.Server.chain.UndefinedDefinitions(btcutil.NewTx(&tx), p.activeNetParams)
				q.Server.GetDefinition(undefined)
			}
			return nil
		})
		time.Sleep(15 * time.Second)
	}
}
