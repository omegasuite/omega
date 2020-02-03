// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package minerchain

import (
	"bytes"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/mining"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"math/big"
	//	"runtime"
	"sync"
	"time"
)

const (
	// maxNonce is the maximum value a nonce can be in a block header.
	maxNonce = ^uint32(0) // 2^32 - 1

	// hpsUpdateSecs is the number of seconds to wait in between each
	// update to the hashes per second monitor.
	hpsUpdateSecs = 10

	// hashUpdateSec is the number of seconds each worker waits in between
	// notifying the speed monitor with how many hashes have been completed
	// while they are actively searching for a solution.  This is done to
	// reduce the amount of syncs between the workers that must be done to
	// keep track of the hashes per second.
	hashUpdateSecs = 15
)

var (
	// defaultNumWorkers is the default number of workers to use for mining
	// and is based on the number of processor cores.  This helps ensure the
	// system stays reasonably responsive under heavy load.

	// since we are in development phase, use 1 miner to free CPU do other work
	// in final release we may want to keep it this way if most people would
	// use hardware mining
	defaultNumWorkers = uint32(1)	// uint32(runtime.NumCPU())
)

// Config is a descriptor containing the cpu miner configuration.
type Config struct {
	// ChainParams identifies which chain parameters the cpu miner is
	// associated with.
	ChainParams *chaincfg.Params
	
	// ExternalIPs, the ip we listen on
	ExternalIPs []string
	
	// RSAPubKey for people to connect to us
	RSAPubKey   string

	// BlockTemplateGenerator identifies the instance to use in order to
	// generate block templates that the miner will attempt to solve.
	BlockTemplateGenerator *mining.BlkTmplGenerator

	// MiningAddrs is a list of payment addresses to use for the generated
	// blocks.  Each generated block will randomly choose one of them.
	MiningAddrs []btcutil.Address

	SignAddress btcutil.Address

	// ProcessBlock defines the function to call with any solved blocks.
	// It typically must run the provided block through the same set of
	// rules and handling as any other block coming from the network.
	ProcessBlock func(*wire.MinerBlock, blockchain.BehaviorFlags) (bool, error)

	// ConnectedCount defines the function to use to obtain how many other
	// peers the server is connected to.  This is used by the automatic
	// persistent mining routine to determine whether or it should attempt
	// mining.  This is useful because there is no point in mining when not
	// connected to any peers since there would no be anyone to send any
	// found blocks to.
	ConnectedCount func() int32

	// IsCurrent defines the function to use to obtain whether or not the
	// block chain is current.  This is used by the automatic persistent
	// mining routine to determine whether or it should attempt mining.
	// This is useful because there is no point in mining if the chain is
	// not current since any solved blocks would be on a side chain and and
	// up orphaned anyways.
	IsCurrent func() bool
}

// CPUMiner provides facilities for solving blocks (mining) using the CPU in
// a concurrency-safe manner.  It consists of two main goroutines -- a speed
// monitor and a controller for worker goroutines which generate and solve
// blocks.  The number of goroutines can be set via the SetMaxGoRoutines
// function, but the default is based on the number of processor cores in the
// system which is typically sufficient.
type CPUMiner struct {
	sync.Mutex
	g                 *mining.BlkTmplGenerator
	cfg               Config
	numWorkers        uint32
	started           bool
	discreteMining    bool
	submitBlockLock   sync.Mutex
	wg                sync.WaitGroup
	workerWg          sync.WaitGroup
	updateNumWorkers  chan struct{}
	queryHashesPerSec chan float64
	updateHashes      chan uint64
	speedMonitorQuit  chan struct{}
	quit              chan struct{}
	Stale			  bool
}

// speedMonitor handles tracking the number of hashes per second the mining
// process is performing.  It must be run as a goroutine.
func (m *CPUMiner) speedMonitor() {
	var hashesPerSec float64
	var totalHashes uint64
	ticker := time.NewTicker(time.Second * hpsUpdateSecs)
	defer ticker.Stop()

out:
	for {
		select {
		// Periodic updates from the workers with how many hashes they
		// have performed.
		case numHashes := <-m.updateHashes:
			totalHashes += numHashes

		// Time to update the hashes per second.
		case <-ticker.C:
			curHashesPerSec := float64(totalHashes) / hpsUpdateSecs
			if hashesPerSec == 0 {
				hashesPerSec = curHashesPerSec
			}
			hashesPerSec = (hashesPerSec + curHashesPerSec) / 2
			totalHashes = 0

			if len(m.queryHashesPerSec) == 0 {
//				m.queryHashesPerSec <- hashesPerSec
			}

		// Request for the number of hashes per second.
		case m.queryHashesPerSec <- hashesPerSec:
			// Nothing to do.

		case <-m.speedMonitorQuit:
			break out
		}
	}

	m.wg.Done()
}

// submitBlock submits the passed block to network after ensuring it passes all
// of the consensus validation rules.
func (m *CPUMiner) submitBlock(block *wire.MinerBlock) bool {
	log.Infof("submitBlock %d", block.Height())
	m.submitBlockLock.Lock()
	defer m.submitBlockLock.Unlock()

	// Ensure the block is not stale since a new block could have shown up
	// while the solution was being found.  Typically that condition is
	// detected and all work on the stale block is halted to start work on
	// a new block, but the check only happens periodically, so it is
	// possible a block was found and submitted in between.
	msgBlock := block.MsgBlock()
	if !msgBlock.PrevBlock.IsEqual(&m.g.BestMinerSnapshot().Hash) {
		log.Infof("PrevHash %s is not the best hash %s", msgBlock.PrevBlock.String(), m.g.BestMinerSnapshot().Hash.String())
		return false
	}

	// Process this block using the same rules as blocks coming from other
	// nodes.  This will in turn relay it to the network like normal.
	isOrphan, err := m.cfg.ProcessBlock(block, blockchain.BFNone)
	if err != nil {
		log.Infof("ProcessBlock error %s", err.Error())
		// Anything other than a rule violation is an unexpected error,
		// so log that error as an internal error.
		if _, ok := err.(blockchain.RuleError); !ok {
			return false
		}

		return false
	}
	if isOrphan {
		log.Info("It is an orphan")
		return false
	}

	log.Info("Miner Block submitted via CPU miner accepted (hash %s, "+
		"Newnode %v)", block.Hash(), block.MsgBlock().Miner)

	return true
}

func (m *CPUMiner) factorPOW(baseh uint32, h0 chainhash.Hash) int64 {	// *big.Int {
	h := m.g.Chain.BestSnapshot().LastRotation	// .LastRotation(h0)
	if h == 0 {
		return 1 	// nil
	}

	d := int32(baseh) - int32(h)
	if d > wire.DESIRABLE_MINER_CANDIDATES {
		return int64(1) << (d - wire.DESIRABLE_MINER_CANDIDATES)
	} else {
		return 1
	}
//	return int64(1) << (d - wire.DESIRABLE_MINER_CANDIDATES)
/*
	factor := float64(1024.0)
	if d > wire.DESIRABLE_MINER_CANDIDATES {
		factor *= math.Pow(powScaleFactor, float64(d - wire.DESIRABLE_MINER_CANDIDATES))
	}
	return big.NewInt(int64(factor))
*/
}

// solveBlock attempts to find some combination of a nonce, extra nonce, and
// current timestamp which makes the passed block hash to a value less than the
// target difficulty.  The timestamp is updated periodically and the passed
// block is modified with all tweaks during this process.  This means that
// when the function returns true, the block is ready for submission.
//
// This function will return early with false when conditions that trigger a
// stale block such as a new block showing up or periodically when there are
// new transactions and enough time has elapsed without finding a solution.
func (m *CPUMiner) solveBlock(header *mining.BlockTemplate, blockHeight int32,
	ticker *time.Ticker, quit chan struct{}) bool {

	// Create some convenience variables.
	targetDifficulty := blockchain.CompactToBig(header.Bits)
	header.Block.(*wire.MingingRightBlock).Bits = header.Bits

	factorPOW := m.factorPOW(uint32(header.Height), header.Block.(*wire.MingingRightBlock).PrevBlock)
/*
	if factorPOW != nil {
		targetDifficulty.Mul(targetDifficulty, big.NewInt(1024))
		targetDifficulty.Div(targetDifficulty, factorPOW)
	}
*/

	// Initial state.
	hashesCompleted := uint64(0)

	for true {
		// Search through the entire nonce range for a solution while
		// periodically checking for early quit and stale block
		// conditions along with updates to the speed monitor.
		for i := uint32(1); i <= maxNonce; i++ {
			select {
			case <-quit:
				return false

			case <-ticker.C:
				m.updateHashes <- hashesCompleted
				hashesCompleted = 0

				// The current block is stale if the best block
				// has changed.
				best := m.g.Chain.Miners.BestSnapshot()
				if !header.Block.(*wire.MingingRightBlock).PrevBlock.IsEqual(&best.Hash) {
					log.Infof("quit solving block because best hash is not prev block")
					return false
				}

				m.g.UpdateMinerBlockTime(header.Block.(*wire.MingingRightBlock))

				if m.cfg.ChainParams.ReduceMinDifficulty {
					targetDifficulty = blockchain.CompactToBig(header.Bits)
				}

			default:
				// Non-blocking select to fall through
			}

			// Update the nonce and hash the block header.  Each
			// hash is actually a double sha256 (two hashes), so
			// increment the number of hashes completed for each
			// attempt accordingly.
			header.Block.(*wire.MingingRightBlock).Nonce = int32(i)
			hash := header.Block.(*wire.MingingRightBlock).BlockHash()
			hashesCompleted += 2

			// The block is solved when the new block hash is less
			// than the target difficulty.  Yay!
			res := blockchain.HashToBig(&hash)
			if res.Mul(res, big.NewInt(factorPOW)).Cmp(targetDifficulty) <= 0 {
				return true
			}
		}
		m.g.UpdateMinerBlockTime(header.Block.(*wire.MingingRightBlock))
	}

	return false
}

func (g * MinerChain) QualifiedMier(privKeys map[btcutil.Address]*btcec.PrivateKey) btcutil.Address {
	curHeight := g.BestSnapshot().Height
	// Choose a payment address at random.

	good := false
	for addr, _ := range privKeys {
		good = true
		for i := 0; i < wire.MinerGap && int32(i) <= curHeight; i++ {
			p, _ := g.BlockByHeight(curHeight - int32(i))
			if bytes.Compare(p.MsgBlock().Miner, addr.ScriptAddress()) == 0 {
				good = false
				break
			}
		}
		if good {
			return addr
		}
	}
	return nil
}

// generateBlocks is a worker that is controlled by the miningWorkerController.
// It is self contained in that it creates block templates and attempts to solve
// them while detecting when it is performing stale work and reacting
// accordingly by generating a new block template.  When a block is solved, it
// is submitted.
//
// It must be run as a goroutine.
func (m *CPUMiner) generateBlocks(quit chan struct{}) {
	// Start a ticker which is used to signal checks for stale work and
	// updates to the speed monitor.
	ticker := time.NewTicker(time.Second * hashUpdateSecs)
	defer ticker.Stop()
out:
	for {
		// Quit when the miner is stopped.
		select {
		case <-quit:
			break out
		default:
			// Non-blocking select to fall through
		}

		// Wait until there is a connection to at least one other peer
		// since there is no way to relay a found block or receive
		// transactions to work on when there are no connected peers.
		if m.cfg.ConnectedCount() == 0 {
			m.Stale = true
			log.Info("generateBlocks: sleep because of no connection")
			time.Sleep(time.Second * 5)
			continue
		}

		// No point in searching for a solution before the chain is
		// synced.  Also, grab the same lock as used for block
		// submission, since the current block will be changing and
		// this would otherwise end up building a new block template on
		// a block that is in the process of becoming stale.
		m.submitBlockLock.Lock()
		curHeight := m.g.Chain.Miners.BestSnapshot().Height
		isCurrent := m.cfg.IsCurrent()
		if curHeight != 0 && !isCurrent {
			m.submitBlockLock.Unlock()
			m.Stale = true
			log.Infof("generateBlocks: sleep on curHeight != 0 && !isCurrent ")
			time.Sleep(time.Second * 5)
			continue
		}

		h := m.g.Chain.BestSnapshot().LastRotation	// .LastRotation(h0)
		d := curHeight - int32(h)
		if d > wire.DESIRABLE_MINER_CANDIDATES + 3 {
			m.submitBlockLock.Unlock()
			m.Stale = true
			log.Infof("generateBlocks: sleep because of too many candidates %d", d)
			time.Sleep(time.Second * time.Duration(5 * (d -3 - wire.DESIRABLE_MINER_CANDIDATES )))
			continue
		}
		
		// Choose a payment address at random.

		good := true
		for i := 0; i < wire.MinerGap && int32(i) <= curHeight; i++ {
			p, _ := m.g.Chain.Miners.BlockByHeight(curHeight - int32(i))
			if p == nil {
				log.Infof("miner.generateBlocks incorrect height %d out of ", curHeight - int32(i), curHeight)
				continue
			}
			if bytes.Compare(p.MsgBlock().Miner, m.cfg.SignAddress.ScriptAddress()) == 0 {
				log.Infof("miner.generateBlocks won't mine because I am block %d before the best block %d", curHeight - int32(i), curHeight)
				good = false
				break
			}
		}

		// Create a new block template using the available transactions
		// in the memory pool as a source of transactions to potentially
		// include in the block.
		var template *mining.BlockTemplate
		var err error

		if good {
			template, err = m.g.NewMinerBlockTemplate(m.cfg.SignAddress)
			if err != nil {
				log.Infof("NewMinerBlockTemplate error: %s", err.Error())
			}
		}
		m.submitBlockLock.Unlock()
		
		if err != nil || template == nil {
			m.Stale = true
			log.Infof("miner.generateBlocks: sleep on err != nil || template == nil, curHeight = %d", curHeight)
			time.Sleep(time.Second * 5)
			continue
		}

		m.Stale = false

		// Attempt to solve the block.  The function will exit early
		// with false when conditions that trigger a stale block, so
		// a new block template can be generated.  When the return is
		// true a solution was found, so submit the solved block.
		block := wire.NewMinerBlock(template.Block.(*wire.MingingRightBlock))
		if len(m.cfg.ExternalIPs) > 0 {
			block.MsgBlock().Connection = []byte(m.cfg.ExternalIPs[0])
		} else if len(m.cfg.RSAPubKey) > 0 {
			block.MsgBlock().Connection = []byte(m.cfg.RSAPubKey)
		}

		log.Infof("miner Trying to solve block at %d with difficulty %d", template.Height, template.Bits)
		if m.solveBlock(template, curHeight+1, ticker, quit) {
			log.Infof("New miner block produced by %x at %d", m.cfg.SignAddress.ScriptAddress(), template.Height)
			m.submitBlock(block)
		} else {
			log.Info("solveBlock: No New block produced")
		}
	}

	m.workerWg.Done()
}

// miningWorkerController launches the worker goroutines that are used to
// generate block templates and solve them.  It also provides the ability to
// dynamically adjust the number of running worker goroutines.
//
// It must be run as a goroutine.
func (m *CPUMiner) miningWorkerController() {
	// launchWorkers groups common code to launch a specified number of
	// workers for generating blocks.
	var runningWorkers []chan struct{}
	launchWorkers := func(numWorkers uint32) {
		for i := uint32(0); i < numWorkers; i++ {
			quit := make(chan struct{})
			runningWorkers = append(runningWorkers, quit)

			m.workerWg.Add(1)
			go m.generateBlocks(quit)
		}
	}

	// Launch the current number of workers by default.
	runningWorkers = make([]chan struct{}, 0, m.numWorkers)
	launchWorkers(m.numWorkers)

out:
	for {
		select {
		// Update the number of running workers.
		case <-m.updateNumWorkers:
			// No change.
			numRunning := uint32(len(runningWorkers))
			if m.numWorkers == numRunning {
				continue
			}

			// Add new workers.
			if m.numWorkers > numRunning {
				launchWorkers(m.numWorkers - numRunning)
				continue
			}

			// Signal the most recently created goroutines to exit.
			for i := numRunning - 1; i >= m.numWorkers; i-- {
				close(runningWorkers[i])
				runningWorkers[i] = nil
				runningWorkers = runningWorkers[:i]
			}

		case <-m.quit:
			for _, quit := range runningWorkers {
				close(quit)
			}
			break out
		}
	}

	// Wait until all workers shut down to stop the speed monitor since
	// they rely on being able to send updates to it.
	m.workerWg.Wait()
	close(m.speedMonitorQuit)
	m.wg.Done()
}

// Start begins the CPU mining process as well as the speed monitor used to
// track hashing metrics.  Calling this function when the CPU miner has
// already been started will have no effect.
//
// This function is safe for concurrent access.
func (m *CPUMiner) Start() {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is already running or if running in
	// discrete mode (using GenerateNBlocks).
	if m.started || m.discreteMining {
		return
	}

	m.quit = make(chan struct{})
	m.speedMonitorQuit = make(chan struct{})
	m.wg.Add(2)
	go m.speedMonitor()
	go m.miningWorkerController()

	m.started = true
}

// Stop gracefully stops the mining process by signalling all workers, and the
// speed monitor to quit.  Calling this function when the CPU miner has not
// already been started will have no effect.
//
// This function is safe for concurrent access.
func (m *CPUMiner) Stop() {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is not currently running or if running in
	// discrete mode (using GenerateNBlocks).
	if !m.started || m.discreteMining {
		return
	}

	close(m.quit)
	m.wg.Wait()
	m.started = false
}

// IsMining returns whether or not the CPU miner has been started and is
// therefore currenting mining.
//
// This function is safe for concurrent access.
func (m *CPUMiner) IsMining() bool {
	m.Lock()
	defer m.Unlock()

	return m.started
}

// HashesPerSecond returns the number of hashes per second the mining process
// is performing.  -1 is returned if the miner is not currently running.
//
// This function is safe for concurrent access.
func (m *CPUMiner) HashesPerSecond() float64 {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is not currently running.
	if !m.started {
		return -1
	}

	return <-m.queryHashesPerSec
}

// SetNumWorkers sets the number of workers to create which solve blocks.  Any
// negative values will cause a default number of workers to be used which is
// based on the number of processor cores in the system.  A value of 0 will
// cause all CPU mining to be stopped.
//
// This function is safe for concurrent access.
func (m *CPUMiner) SetNumWorkers(numWorkers int32) {
	if numWorkers == 0 {
		m.Stop()
	}

	// Don't lock until after the first check since Stop does its own
	// locking.
	m.Lock()
	defer m.Unlock()

	// Use default if provided value is negative.
	if numWorkers < 0 {
		m.numWorkers = defaultNumWorkers
	} else {
		m.numWorkers = uint32(numWorkers)
	}

	// When the miner is already running, notify the controller about the
	// the change.
	if m.started {
		m.updateNumWorkers <- struct{}{}
	}
}

// NumWorkers returns the number of workers which are running to solve blocks.
//
// This function is safe for concurrent access.
func (m *CPUMiner) NumWorkers() int32 {
	m.Lock()
	defer m.Unlock()

	return int32(m.numWorkers)
}

// New returns a new instance of a CPU miner for the provided configuration.
// Use Start to begin the mining process.  See the documentation for CPUMiner
// type for more details.
func NewMiner(cfg *Config) *CPUMiner {
	return &CPUMiner{
		g:                 cfg.BlockTemplateGenerator,
		cfg:               *cfg,
		numWorkers:        defaultNumWorkers,
		updateNumWorkers:  make(chan struct{}),
		queryHashesPerSec: make(chan float64),
		updateHashes:      make(chan uint64),
	}
}
