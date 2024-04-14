/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package minerchain

import (
	"bytes"
	//	"fmt"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/mining"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"math/big"
	"math/rand"
	"sort"

	//	"runtime"
	"sync"
	"time"
)

const (
	// maxNonce is the maximum value a nonce can be in a block header.
	maxNonce = 0x7FFFFFFF

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
	defaultNumWorkers = uint32(1) // uint32(runtime.NumCPU())
)

// Config is a descriptor containing the cpu miner configuration.
type Config struct {
	// ChainParams identifies which chain parameters the cpu miner is
	// associated with.
	ChainParams *chaincfg.Params

	// ExternalIPs, the ip we listen on
	ExternalIPs []string

	// RSAPubKey for people to connect to us
	RSAPubKey string

	// whether in ShareMining mode
	ShareMining bool

	// BlockTemplateGenerator identifies the instance to use in order to
	// generate block templates that the miner will attempt to solve.
	BlockTemplateGenerator *mining.BlkTmplGenerator

	// MiningAddrs is a list of payment addresses to use for the generated
	// blocks.  Each generated block will randomly choose one of them.
	MiningAddrs []btcutil.Address

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
	miningkeys        chan btcutil.Address
	Stale             bool
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
	/*
		msgBlock := block.MsgBlock()

		if !msgBlock.PrevBlock.IsEqual(&m.g.BestMinerSnapshot().Hash) {
			log.Infof("PrevHash %s is not the best hash %s", msgBlock.PrevBlock.String(), m.g.BestMinerSnapshot().Hash.String())
			return false
		}
	*/

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

func (m *CPUMiner) factorPOW(prevh int32, best chainhash.Hash) int64 { // *big.Int {
	h := m.g.Chain.Rotation(best)

	if h < 0 { // the best block is not in chain. since this is for mining, we do the max.
		return int64(1) << wire.SCALEFACTORCAP
	}

	d := prevh - h

	if d-wire.DESIRABLE_MINER_CANDIDATES > wire.SCALEFACTORCAP {
		return int64(1) << wire.SCALEFACTORCAP
	} else if d < wire.DESIRABLE_MINER_CANDIDATES/2 {
		m := wire.DESIRABLE_MINER_CANDIDATES/2 - d
		if m > 10 {
			m = 10
		}
		return (-1) << m
	} else if d <= wire.DESIRABLE_MINER_CANDIDATES {
		return 1
	}

	return int64(1) << (d - wire.DESIRABLE_MINER_CANDIDATES)
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
func (m *CPUMiner) solveBlock(header *mining.BlockTemplate, blockHeight int32, h int64,
	quit chan struct{}, numWorkers uint32) bool {

	// Create some convenience variables.
	targetDifficulty := blockchain.CompactToBig(header.Bits)
	header.Block.(*wire.MingingRightBlock).Bits = header.Bits

	block := header.Block.(*wire.MingingRightBlock)

	factorPOW := int64(1)

	if header.Height > 2200 || block.Version&0x7FFF0000 >= 0x20000 {
		factorPOW = m.factorPOW(header.Height-1, header.Block.(*wire.MingingRightBlock).BestBlock)
	}

	// Normal mode
	//if block.Version < chaincfg.Version5 && block.Version >= chaincfg.Version2 && factorPOW > 0 {
	//	factorPOW = 16 * factorPOW // factor 16 is for smooth transition from V1 to V2
	//}

	if factorPOW < 0 {
		targetDifficulty = targetDifficulty.Mul(targetDifficulty, big.NewInt(-factorPOW))
		factorPOW = 1
	}

	if block.Version&0x7FFF0000 >= chaincfg.Version2 {
		targetDifficulty = targetDifficulty.Mul(targetDifficulty, big.NewInt(h))
		if block.Version&0x7FFF0000 <= chaincfg.Version5 && targetDifficulty.Cmp(m.cfg.ChainParams.PowLimit.Mul(m.cfg.ChainParams.PowLimit, big.NewInt(16))) > 0 {
			targetDifficulty = m.cfg.ChainParams.PowLimit.Mul(m.cfg.ChainParams.PowLimit, big.NewInt(16))
		} else if block.Version&0x7FFF0000 > chaincfg.Version5 && targetDifficulty.Cmp(m.cfg.ChainParams.PowLimit) > 0 {
			targetDifficulty = m.cfg.ChainParams.PowLimit
		}
	} else if targetDifficulty.Cmp(m.cfg.ChainParams.PowLimit) > 0 {
		targetDifficulty = m.cfg.ChainParams.PowLimit
	}

	// Initial state.
	tbest := m.g.Chain.BestSnapshot()
	rotation := tbest.LastRotation

	resch := make(chan *wire.MingingRightBlock, numWorkers)
	locquit := make(chan struct{})

	solver := func(start uint32, numWorkers uint32) {
		locheader := *header.Block.(*wire.MingingRightBlock)
		hashesCompleted := uint64(0)

		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()

		for true {
			// Search through the entire nonce range for a solution while
			// periodically checking for early quit and stale block
			// conditions along with updates to the speed monitor.
			for i, j := start, 0; i <= maxNonce-numWorkers; i += numWorkers {
				j++
				if j%10000 == 0 { // normal mode
					select {
					case <-locquit:
						return

					case <-quit:
						resch <- nil
						return

					case <-ticker.C:
						m.updateHashes <- hashesCompleted
						hashesCompleted = 0

						tbest = m.g.Chain.BestSnapshot()
						if rotation != tbest.LastRotation {
							log.Infof("quit solving block because a rotation occurred in TX chain")
							resch <- nil
							return
						}

						// The current block is stale if the best block has changed.
						best := m.g.Chain.Miners.BestSnapshot()
						if !locheader.PrevBlock.IsEqual(&best.Hash) {
							log.Infof("quit solving block because tip changed")
							resch <- nil
							return
						}

						m.g.UpdateMinerBlockTime(&locheader)

					default:
						// Non-blocking select to fall through
					}
				}

				// Update the nonce and hash the block header.  Each
				// hash is actually a double sha256 (two hashes), so
				// increment the number of hashes completed for each
				// attempt accordingly.
				locheader.Nonce = int32(i)
				hash := locheader.BlockHash()
				hashesCompleted += 2

				// The block is solved when the new block hash is less
				// than the target difficulty.  Yay!
				res := blockchain.HashToBig(&hash)

				if res.Cmp(m.cfg.ChainParams.PowLimit) >= 0 {
					continue
				}

				res = res.Mul(res, big.NewInt(factorPOW))

				if res.Cmp(targetDifficulty) <= 0 {
					best := m.g.Chain.Miners.BestSnapshot()
					if !locheader.PrevBlock.IsEqual(&best.Hash) {
						log.Infof("quit solving block because tip changed")
						resch <- nil
						return
					}
					log.Infof("miner block solved")
					resch <- &locheader
					return
				}
			}
			m.g.UpdateMinerBlockTime(&locheader)
		}
	}

	for i := uint32(1); i <= numWorkers; i++ {
		go solver(i, numWorkers)
	}

	for i := uint32(0); i < numWorkers; i++ {
		v := <-resch
		if v != nil {
			*header.Block.(*wire.MingingRightBlock) = *v
			close(locquit)
			return true
		}
	}

	return false
}

func (g *MinerChain) QualifiedMier(privKeys map[btcutil.Address]*btcec.PrivateKey) btcutil.Address {
	curHeight := g.BestSnapshot().Height
	// Choose a payment address at random.

	good := false
	for addr, _ := range privKeys {
		good = true
		for i := 0; i < wire.MinerGap && int32(i) <= curHeight; i++ {
			p, _ := g.BlockByHeight(curHeight - int32(i))
			if bytes.Compare(p.MsgBlock().Miner[:], addr.ScriptAddress()) == 0 {
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

func (m *CPUMiner) ChangeMiningKey(miningAddr btcutil.Address) {
	m.miningkeys <- miningAddr
}

// generateBlocks is a worker that is controlled by the miningWorkerController.
// It is self contained in that it creates block templates and attempts to solve
// them while detecting when it is performing stale work and reacting
// accordingly by generating a new block template.  When a block is solved, it
// is submitted.
//
// It must be run as a goroutine.
func (m *CPUMiner) generateBlocks(quit chan struct{}, numWorkers uint32) {
	// Start a ticker which is used to signal checks for stale work and
	// updates to the speed monitor.
	m.workerWg.Add(1)

out:
	for {
		// Quit when the miner is stopped.
		select {
		case <-quit:
			break out

		case k := <-m.miningkeys:
			if len(m.cfg.MiningAddrs) == 0 {
				m.cfg.MiningAddrs = make([]btcutil.Address, 1)
			} else {
				m.cfg.MiningAddrs = m.cfg.MiningAddrs[:1]
			}
			m.cfg.MiningAddrs[0] = k

		default:
			// Non-blocking select to fall through
		}

		// Wait until there is a connection to at least one other peer
		// since there is no way to relay a found block or receive
		// transactions to work on when there are no connected peers.
		if m.cfg.ConnectedCount() == 0 {
			m.Stale = true
			//			log.Info("miner.generateBlocks: sleep because of no connection")
			time.Sleep(time.Second * 5)
			continue
		}

		if len(m.cfg.MiningAddrs) == 0 || m.g.Chain.IsPacking {
			time.Sleep(time.Second * 5)
			continue
		}

		// No point in searching for a solution before the chain is
		// synced.  Also, grab the same lock as used for block
		// submission, since the current block will be changing and
		// this would otherwise end up building a new block template on
		// a block that is in the process of becoming stale.
		m.submitBlockLock.Lock()
		isCurrent := m.cfg.IsCurrent()
		curHeight := m.g.Chain.Miners.BestSnapshot().Height

		if curHeight == 0 && !isCurrent {
			time.Sleep(time.Minute * 10)
			curHeight = m.g.Chain.Miners.BestSnapshot().Height
		}

		if curHeight != 0 && !isCurrent {
			m.submitBlockLock.Unlock()
			m.Stale = true
			log.Infof("miner.generateBlocks: sleep on curHeight != 0 && !isCurrent ")
			time.Sleep(time.Second * 5)
			continue
		}

		// choice of chain
		// instead of extending the longest MR chain, we will try to entend
		// a best chain that will allow us to refer the tip of TX chain as
		// best block. In most time, it would be the longest MR chain. But if
		// the longest MR chain refers to a stalled TX side chain, we should
		// switch to a side chain.

		chainChoice, d := m.g.Chain.Miners.(*MinerChain).choiceOfChain()

		//		h := m.g.Chain.BestSnapshot().LastRotation	// .LastRotation(h0)
		//		d := curHeight - int32(h)
		if d > wire.DESIRABLE_MINER_CANDIDATES+10 {
			m.submitBlockLock.Unlock()
			m.Stale = true
			log.Infof("miner.generateBlocks: sleep because of too many candidates %d", d)
			select {
			case <-m.quit:
			case <-time.After(time.Second * time.Duration(5*(d-3-wire.DESIRABLE_MINER_CANDIDATES))):
			}
			continue
		}

		// Choose a payment address at random.
		rand.Seed(time.Now().Unix())
		rnd := rand.Intn(len(m.cfg.MiningAddrs))
		if m.cfg.ShareMining && rnd > 1 {
			rnd = 1 // all addresses except for the first are external
		}

		mtch := false
		qc := chainChoice
		es := ""
		for i := 0; i < wire.MinerGap && qc != nil && !mtch; i++ {
			p := NodetoHeader(qc)
			qc = qc.Parent
			for _, s := range m.cfg.ExternalIPs {
				if bytes.Compare(p.Connection, []byte(s)) == 0 {
					mtch = true
					es += s
				}
			}
			for _, s := range m.cfg.MiningAddrs {
				if bytes.Compare(p.Miner[:], s.ScriptAddress()) == 0 {
					mtch = true
					es += s.String()
				}
			}
		}

		if mtch {
			m.submitBlockLock.Unlock()
			log.Infof("miner.generateBlocks won't mine because I am in GAP before the best block %d. %s", curHeight, es)
			time.Sleep(5 * time.Second)
			continue
		}

		// Create a new block template using the available transactions
		// in the memory pool as a source of transactions to potentially
		// include in the block.
		var template *mining.BlockTemplate
		var err error

		signAddr := m.cfg.MiningAddrs[rnd]

		template, err = m.g.NewMinerBlockTemplate(chainChoice, signAddr)

		if err != nil {
			log.Infof("miner.NewMinerBlockTemplate error: %s", err.Error())
		}

		if err != nil || template == nil {
			m.submitBlockLock.Unlock()
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

		if chainChoice.Hash == *m.g.Chain.Miners.Tip().Hash() && block.MsgBlock().Version&0x7FFF0000 >= chaincfg.Version2 {
			// we choose the best chain, file violation report
			violations := m.g.Chain.Miners.(*MinerChain).violations
			t := make([]*wire.Violations, 0, len(violations))
			for _, v := range violations {
				vb := make(map[chainhash.Hash]struct{})
				for _, h := range v.Blocks {
					vb[h] = struct{}{}
				}

				// check dup report
				inrange := false
				for p, i := chainChoice, int32(0); i < m.cfg.ChainParams.ViolationReportDeadline; i++ {
					if v.MRBlock == p.Data.(*blockchainNodeData).block.BlockHash() {
						inrange = true
					}
					for _, u := range p.Data.(*blockchainNodeData).block.ViolationReport {
						for _, h := range u.Blocks {
							delete(vb, h)
						}
					}
					p = p.Parent
				}
				if inrange && len(vb) > 0 {
					t = append(t, v)
				}
			}
			sort.Slice(t, func(i int, j int) bool {
				return t[i].Height < t[j].Height
			})
			block.MsgBlock().ViolationReport = t
			if len(t) > 0 {
				log.Infof("violation report -- %d", len(t))
			}
		}

		if len(m.cfg.ExternalIPs) > 0 {
			block.MsgBlock().Connection = []byte(m.cfg.ExternalIPs[0])
		} else if len(m.cfg.RSAPubKey) > 0 {
			block.MsgBlock().Connection = []byte(m.cfg.RSAPubKey)
		} else {
			m.submitBlockLock.Unlock()
			m.Stale = true
			log.Infof("miner.generateBlocks: sleep because no connection info is set = %d", curHeight)
			time.Sleep(time.Second * 5)
			continue
		}
		/*
			bm := len(m.g.Chain.BlackedList)
			if bm > 0 {
				bl := make([]*wire.Violations, 0, bm)
				for j := 0; j < bm; j++ {
					n := m.g.Chain.BlackedList[j]
					mb, _ := m.g.Chain.Miners.BlockByHash(&n.MRBlock)
					if mb.Height() < template.Height-99 {
						continue
					}
					bl = append(bl, n)
				}
				m.g.Chain.BlackedList = m.g.Chain.BlackedList[bm:]
				if len(bl) > 0 {
					block.MsgBlock().ViolationReport = bl
				}
			}
		*/
		m.submitBlockLock.Unlock()

		var h1, h2 int64

		if block.MsgBlock().Version&0x7FFF0000 >= chaincfg.Version2 {
			// for h1, we compare this block's coin & Collateral for simplicity
			h := NodetoHeader(chainChoice)
			c := h.Collateral
			if c == 0 {
				c = 1
			}
			v, err := m.g.Chain.CheckCollateral(block, nil, 0)
			if err != nil {
				time.Sleep(time.Second * 5)
				continue
			}
			h1 = int64(v / c)
			if h1 < 1 {
				h1 = 1
			}

			me := m.g.Chain.Miners.(*MinerChain)
			prev, _ := me.BlockByHash(&block.MsgBlock().PrevBlock)
			minscore := prev.MsgBlock().MeanTPH >> 3
			if minscore == 0 {
				minscore = 1
			}
			r := me.TPSreportFromDB(block.MsgBlock().Miner, uint32(template.Height-1)) // max most recent 100 records
			for i := len(r); i < 100; i++ {
				r = append(r, blockchain.TPSrv{Val: minscore})
			}
			sort.Slice(r, func(i, j int) bool {
				return r[i].Val < r[j].Val
			})

			sum := uint32(0)
			for k := 25; k < 75; k++ {
				sum += r[k].Val
			}
			sum /= 50

			if sum <= minscore {
				h2 = 1
			} else {
				h2 = int64(sum / minscore)
			}
		}

		log.Infof("miner Trying to solve block at %d with difficulty %d", template.Height, template.Bits)
		if m.solveBlock(template, curHeight+1, h1+h2, quit, numWorkers) {
			log.Infof("New miner block produced by %x at %d", signAddr.ScriptAddress(), template.Height)
			m.submitBlock(block)
		} else {
			log.Infof("miner.solveBlock: No New block produced")
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

	var numRunning uint32

	quit := make(chan struct{})

	launchWorkers := func(numWorkers uint32) {
		numRunning = numWorkers
		go m.generateBlocks(quit, numWorkers)
	}

	// Launch the current number of workers by default.
	launchWorkers(m.numWorkers)

out:
	for {
		select {
		// Update the number of running workers.
		case <-m.updateNumWorkers:
			// No change.
			if m.numWorkers == numRunning {
				continue
			}

			close(quit)

			m.workerWg.Wait()
			quit = make(chan struct{})

			launchWorkers(m.numWorkers)

		case <-m.quit:
			log.Infof("Closing %d miner works", numRunning)
			close(quit)
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
func (m *CPUMiner) Start(collateral []*wire.OutPoint) {
	m.Lock()
	defer m.Unlock()

	if collateral != nil {
		m.g.Collateral = collateral
	}

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
	if m.started {
		m.Lock()
		defer m.Unlock()

		// Nothing to do if the miner is not currently running or if running in
		// discrete mode (using GenerateNBlocks).
		if !m.started || m.discreteMining {
			return
		}

		close(m.quit)
		m.started = false
		m.wg.Wait()
	}
}

// IsMining returns whether or not the CPU miner has been started and is
// therefore currenting mining.
//
// This function is safe for concurrent access.
func (m *CPUMiner) IsMining() bool {
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
	workers := cfg.ChainParams.SigVeriConcurrency - 1
	if workers <= 0 {
		workers = 1
	}
	log.Infof("Mining with %d threads", workers)

	return &CPUMiner{
		g:                 cfg.BlockTemplateGenerator,
		cfg:               *cfg,
		numWorkers:        uint32(workers),
		updateNumWorkers:  make(chan struct{}),
		queryHashesPerSec: make(chan float64),
		updateHashes:      make(chan uint64),
		miningkeys:        make(chan btcutil.Address, 10),
	}
}

func (b *MinerChain) choiceOfChain() (*chainutil.BlockNode, int32) {
	// choose a branch that will allow us to refer the longest tx chain (sign block)
	n := b.BestChain.Tip()
	/*
		h := NodetoHeader(n)
		bestBlk := b.blockChain.LongestTip()
		for bestBlk.Data.GetNonce() > 0 {
			bestBlk = bestBlk.Parent
		}
	*/
	//		b.blockChain.BestChain.Tip()
	//	if b.blockChain.SameChain(bestBlk.Hash, h.BestBlock) {
	h2 := b.blockChain.BestSnapshot().LastRotation
	d := n.Height - int32(h2)
	return n, d
	//	}
	/*
		for !b.blockChain.SameChain(bestBlk.Hash, h.BestBlock) {
			n = n.Parent
			h = NodetoHeader(n)
		}

		for _,t := range b.index.Tips {
			if t.Height <= n.Height {
				continue
			}
			h = NodetoHeader(t)
			if !b.blockChain.SameChain(bestBlk.Hash, h.BestBlock) {
				continue
			}
			n = t
		}

		// waiting list length of the choice
		d = n.Height - int32(b.blockChain.BestSnapshot().LastRotation)

		return n, d
	*/
}
