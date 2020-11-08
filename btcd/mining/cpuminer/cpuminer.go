// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cpuminer

import (
	"fmt"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/omega/consensus"
	"math/big"
	"math/rand"
	"github.com/omegasuite/btcd/wire/common"
	//	"runtime"
	"sync"
	"time"

	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/mining"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/token"
)

const (
	// maxNonce is the maximum value a nonce can be in a block header.
	maxNonce = 0x7FFFFFFF	// ^uint32(0) // 2^32 - 1

	// hpsUpdateSecs is the number of seconds to wait in between each
	// update to the hashes per second monitor.
	hpsUpdateSecs = 10

	// hashUpdateSec is the number of seconds each worker waits in between
	// notifying the speed monitor with how many hashes have been completed
	// while they are actively searching for a solution.  This is done to
	// reduce the amount of syncs between the workers that must be done to
	// keep track of the hashes per second.
	hashUpdateSecs = 15

	// if no new block received in 3000 Millisecond, start POW mining
	miningGap = 3000
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

	// BlockTemplateGenerator identifies the instance to use in order to
	// generate block templates that the miner will attempt to solve.
	BlockTemplateGenerator *mining.BlkTmplGenerator

	// MiningAddrs is a list of payment addresses to use for the generated
	// blocks.  Each generated block will randomly choose one of them.
	MiningAddrs []btcutil.Address
	SignAddress []btcutil.Address
	PrivKeys    []*btcec.PrivateKey
	EnablePOWMining bool

	// ProcessBlock defines the function to call with any solved blocks.
	// It typically must run the provided block through the same set of
	// rules and handling as any other block coming from the network.
	ProcessBlock func(*btcutil.Block, blockchain.BehaviorFlags) (bool, error)

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
//	numWorkers        uint32
	started           bool
	discreteMining    bool
//	connLock          sync.Mutex
	wg                sync.WaitGroup
//	updateNumWorkers  chan struct{}
//	queryHashesPerSec chan float64
//	updateHashes      chan uint64
//	speedMonitorQuit  chan struct{}
	quit              chan struct{}
	connch            chan int32

	// the block being mined by committee
	minedBlock		  * btcutil.Block
	Stale			  bool
}

// speedMonitor handles tracking the number of hashes per second the mining
// process is performing.  It must be run as a goroutine.
/*
func (m *CPUMiner) speedMonitor() {
	log.Tracef("CPU miner speed monitor started")

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
			if hashesPerSec != 0 {
				log.Debugf("Hash speed: %6.0f kilohashes/s",
					hashesPerSec/1000)
			}
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
	log.Tracef("CPU miner speed monitor done")
}
 */

// submitBlock submits the passed block to network after ensuring it passes all
// of the consensus validation rules.
func (m *CPUMiner) submitBlock(block *btcutil.Block) bool {
	// Ensure the block is not stale since a new block could have shown up
	// while the solution was being found.  Typically that condition is
	// detected and all work on the stale block is halted to start work on
	// a new block, but the check only happens periodically, so it is
	// possible a block was found and submitted in between.
	msgBlock := block.MsgBlock()

	best := m.g.BestSnapshot()
	if !msgBlock.Header.PrevBlock.IsEqual(&best.Hash) {
		log.Infof("Block submitted via CPU miner with previous "+
			"block %s is stale", msgBlock.Header.PrevBlock)
		return false
	}

	// Process this block using the same rules as blocks coming from other
	// nodes.  This will in turn relay it to the network like normal.
	flag := blockchain.BFNone

	if block.MsgBlock().Header.Nonce < 0 && wire.CommitteeSize > 1 {
		flag = blockchain.BFSubmission | blockchain.BFNoConnect
	}
	coinbaseTx := block.MsgBlock().Transactions[0].TxOut[0]

	isOrphan, err := m.cfg.ProcessBlock(block, flag)

	if err != nil {
		// Anything other than a rule violation is an unexpected error,
		// so log that error as an internal error.
		if _, ok := err.(blockchain.RuleError); !ok {
			log.Infof("Unexpected error while processing "+
				"block submitted via CPU miner: %v", err)
			return false
		}

		log.Infof("Block submitted via CPU miner rejected: %s", err.Error())
//		log.Info("Block submitted via CPU miner rejected: %v", err)
		return false
	}

	if isOrphan {
		log.Info("Block submitted via CPU miner is an orphan")
		return false
	}

	// The block was accepted.
	log.Infof("Block submitted via CPU miner accepted (hash %s, "+
		"amount %v)", block.Hash(), btcutil.Amount(coinbaseTx.Value.(*token.NumToken).Val))
	return true
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
func (m *CPUMiner) solveBlock(template *mining.BlockTemplate, blockHeight int32,
	ticker *time.Ticker, quit chan struct{}) bool {

	// Create some convenience variables.
	msgBlock := template.Block.(*wire.MsgBlock)
	header := &msgBlock.Header

	targetDifficulty := blockchain.CompactToBig(template.Bits)

	if template.Height < 383300 {
		targetDifficulty = targetDifficulty.Mul(targetDifficulty, big.NewInt(wire.DifficultyRatio))
	}

	// Initial state.
	lastGenerated := time.Now()
	lastTxUpdate := m.g.TxSource().LastUpdated()
//	hashesCompleted := uint64(0)

//	for true {
		// Search through the entire nonce range for a solution while
		// periodically checking for early quit and stale block
		// conditions along with updates to the speed monitor.
		for i := uint32(1); i <= maxNonce; i++ {
			select {
			case <-quit:
				return false

			case <- m.connch:
				return false

			case <-consensus.POWStopper:
				return false

			case <-ticker.C:
//				m.updateHashes <- hashesCompleted
//				hashesCompleted = 0

				// The current block is stale if the best block
				// has changed.
				best := m.g.BestSnapshot()
				if !header.PrevBlock.IsEqual(&best.Hash) {
					return false
				}

				// The current block is stale if the memory pool
				// has been updated since the block template was
				// generated and it has been at least one
				// minute.
				if lastTxUpdate != m.g.TxSource().LastUpdated() &&
					time.Now().After(lastGenerated.Add(time.Minute)) {

					return false
				}

			default:
				// Non-blocking select to fall through
			}

			// Update the nonce and hash the block header.  Each
			// hash is actually a double sha256 (two hashes), so
			// increment the number of hashes completed for each
			// attempt accordingly.
			header.Nonce = int32(i)
			hash := header.BlockHash()
//			hashesCompleted += 2

			// The block is solved when the new block hash is less
			// than the target difficulty.  Yay!
			hashNum := blockchain.HashToBig(&hash)
			if template.Height >= 383300 {
				hashNum = hashNum.Mul(hashNum, big.NewInt(wire.DifficultyRatio))
			}
			if hashNum.Cmp(targetDifficulty) <= 0 {
				log.Info("Block solved ", hash, " vs ", targetDifficulty)
//				m.updateHashes <- hashesCompleted
				return true
			}
		}
//		m.g.UpdateBlockTime(msgBlock)
//	}

	return false
}

func (m *CPUMiner) Notice (notification *blockchain.Notification) {
	switch notification.Type {
	case blockchain.NTBlockConnected, blockchain.NTBlockRejected:
		if !m.started {
			return
		}

		if len(m.connch) > 50 {
			<- m.connch
		}

		switch notification.Data.(type) {
		case *btcutil.Block:
			m.connch <- notification.Data.(*btcutil.Block).Height() // (*wire.MinerBlock).
			log.Infof("cpuminer notice: sending %d", notification.Data.(*btcutil.Block).Height())

		case *wire.MinerBlock:
			m.connch <- 0	// this will only affect POW mining
		}
	}
}

func (m *CPUMiner) CurrentBlock(h * chainhash.Hash) * btcutil.Block {
	if m.minedBlock != nil {
		bh := m.minedBlock.Hash()
		if bh.IsEqual(h) {
			return m.minedBlock
		}
	}
	return consensus.ServeBlock(h)
}

// generateBlocks is a worker that is controlled by the miningWorkerController.
// It is self contained in that it creates block templates and attempts to solve
// them while detecting when it is performing stale work and reacting
// accordingly by generating a new block template.  When a block is solved, it
// is submitted.
//
// It must be run as a goroutine.
func (m *CPUMiner) generateBlocks() {
	log.Info("Starting generate blocks")

	// Start a ticker which is used to signal checks for stale work and
	// updates to the speed monitor.
	ticker := time.NewTicker(time.Second * hashUpdateSecs)
	defer ticker.Stop()

	lastblkgen := time.Now().Unix()

out:
	for {
		// Quit when the miner is stopped.
		select {
			case _, ok := <-m.connch: // prevent chan full & blocking
				if !ok { // chan closed. we have received stop sig.
					break out
				} else {
					for len(m.connch) > 0 {
						<-m.connch
					}
					lastblkgen = time.Now().Unix()
				}

			case <-m.quit:
				break out
				
			case <-consensus.POWStopper:

			default:
				// Non-blocking select to fall through
		}

//		log.Infof("generate Block go!")

		// Wait until there is a connection to at least one other peer
		// since there is no way to relay a found block or receive
		// transactions to work on when there are no connected peers.
		if ccnt := m.cfg.ConnectedCount(); ccnt == 0 {
			log.Infof("Sleep 5 sec because there is no connected peer.")
			m.Stale = true
			time.Sleep(time.Second * 5)
			continue
//		} else {
//			log.Infof("ConnectedCount = %d.", ccnt)
		}

		// No point in searching for a solution before the chain is
		// synced.  Also, grab the same lock as used for block
		// submission, since the current block will be changing and
		// this would otherwise end up building a new block template on
		// a block that is in the process of becoming stale.

		isCurrent := m.cfg.IsCurrent()
//		log.Infof("isCurrent = %v.", isCurrent)

		bs := m.g.BestSnapshot()
		curHeight := bs.Height
//		log.Infof("curHeight = %d.", curHeight)

		if curHeight != 0 && !isCurrent {
			m.Stale = true
			log.Infof("generateBlocks: sleep on curHeight != 0 && !isCurrent @ height %d", curHeight)
			time.Sleep(time.Second * 5)
			continue
		}

		m.Stale = false

		// Choose a payment address.
		// check whether the address is allowed to mine a POW block
		// the rule is that we don't do POW mining while in committee

		var payToAddr * btcutil.Address

		tip := m.g.Chain.BestChain.Tip()
		pb := tip.Data.GetNonce()
		height := tip.Height

		committee := m.g.Committee()

		var adr [20]byte
		powMode := true
		var sigaddr *btcec.PrivateKey

//		log.Infof("committee size = %d.", len(committee))

		if len(m.cfg.SignAddress) != 0 && len(committee) == wire.CommitteeSize {
			for j,pt := range m.cfg.SignAddress {
				copy(adr[:], pt.ScriptAddress())
				if _, ok := committee[adr]; ok {
					payToAddr = &pt
					sigaddr = m.cfg.PrivKeys[j]
					powMode = false
					break
				}
			}
		}

		if powMode {
			// pick one from address list
			payToAddr = &m.cfg.MiningAddrs[rand.Int()%len(m.cfg.MiningAddrs)]
		}

		// Create a new block template using the available transactions
		// in the memory pool as a source of transactions to potentially
		// include in the block.

		payToAddress := []btcutil.Address{*payToAddr}

//		log.Infof("powMode = %v.", powMode)

		nonce := pb
		if !powMode {
//			log.Infof("Non-POW mode")

			if nonce >= 0 || nonce <= -wire.MINER_RORATE_FREQ {
				nonce = -1
			} else if nonce == -wire.MINER_RORATE_FREQ+1 {
				nonce = -int32(bs.LastRotation) - 1 - wire.MINER_RORATE_FREQ
			} else {
				nonce--
			}

			if wire.CommitteeSize > 1 {
				// check collateral. kick out those not qualified.
				payToAddress = m.coinbaseByCommittee(*payToAddr)
				if len(payToAddress) == 0 {
					// My this address is not qualified. Use a random in POW mode.
//					log.Infof("Change to POW mining because my address is not qualified.")
					powMode = true
					payToAddr = &m.cfg.MiningAddrs[rand.Int() % len(m.cfg.MiningAddrs)]
					payToAddress = []btcutil.Address{*payToAddr}
					nonce = 1
				} else if len(payToAddress) <= wire.CommitteeSize / 2 {
					// impossible to form a qualified consensus
//					log.Infof("Change to POW mining because insufficient committee members.")
					powMode = true
					payToAddress = []btcutil.Address{*payToAddr}
					nonce = 1
				}
			}
		} else {
//			log.Infof("POW mode")
			nonce = 1
		}

		template, err := m.g.NewBlockTemplate(payToAddress, nonce)
		if err != nil {
//			errStr := fmt.Sprintf("Failed to create new block template: %v", err)
			log.Info(err.Error())
//			log.Error(errStr)
			continue
		}

		wb := template.Block.(*wire.MsgBlock)
		block := btcutil.NewBlock(wb)
		block.SetHeight(template.Height)

		if template.Height != height + 1 {
			// a new block got inserted between we get tip ino and gen template
			continue
		}

//		log.Infof("New template with %d txs", len(template.Block.(*wire.MsgBlock).Transactions))

		if !powMode {
			if wire.CommitteeSize == 1 {
				// solo miner, add signature to coinbase, otherwise will add after committee decides
				mining.AddSignature(block, sigaddr)
			} else {
				block.ClearSize()
				block.MsgBlock().Transactions[0].SignatureScripts = append(block.MsgBlock().Transactions[0].SignatureScripts, adr[:])
			}
			m.minedBlock = block

			blockMaxSize := m.g.Chain.GetBlockLimit(template.Height)

			sz := len(block.MsgBlock().Transactions)
			block.ClearSize()

			// if block is too small, wait upto wire.TimeGap
			nt := wire.TimeGap - (time.Now().Unix() - lastblkgen)

			if m.g.Chain.ChainParams.Net == common.MainNet {
//				log.Infof("sz = %d blockMaxSize = %d nt = %d", sz, blockMaxSize, nt)

				if sz < int(blockMaxSize)/2 && nt > 4 {
					log.Infof("Re-try be cause %d < int(%d) / 2 && %d > 4", sz, blockMaxSize, nt)
					time.Sleep(time.Duration(nt) / 4 * time.Second)
					continue
				} else if sz < int(blockMaxSize)/2 && nt > 0 {
					log.Infof("Re-try be cause %d < int(%d) / 2 && %d > 0", sz, blockMaxSize, nt)
					time.Sleep(time.Duration(nt) * time.Second)
					continue
				}
			} else if sz <= 1 && nt > 1 {
				log.Infof("Re-try be cause %d <= 1 && %d > 1", sz, nt)
				time.Sleep(time.Duration(nt) * time.Second)
				continue
			}

			lastblkgen = time.Now().Unix()

//			log.Infof("New committee block produced by %s nonce = %d at %d", (*payToAddr).String(), block.MsgBlock().Header.Nonce, template.Height)
			if !m.submitBlock(block) {
				continue
			}
//			log.Infof("Waiting for block connected at %d", block.Height())

		connected:
			for true {
				select {
				case blk,ok := <-m.connch:
//					log.Infof("Noticed of new connected block %d", blk)
					if !ok || blk >= block.Height() {
						break connected
					}
					
				case _,ok := <-consensus.POWStopper:
					if !ok {
						break connected
					}

				case <-m.quit:
					m.minedBlock = nil
					break out

				case <-time.After(time.Second * 5):
					if m.g.Chain.BestSnapshot().Height >= block.Height() || time.Now().Unix() - lastblkgen > 600 {
						break connected
					}

//					log.Infof("cpuminer waiting for consus to finish block %d", block.Height())
					consensus.DebugInfo()
				}
			}

			m.minedBlock = nil

//			log.Infof("Proceed to generate next block")

			continue
		}

		lastblkgen = time.Now().Unix()
		m.minedBlock = nil

		if !m.cfg.EnablePOWMining {
			select {
			case <-consensus.POWStopper:

			case <-m.quit:
				break out

			case <-time.After(time.Second * wire.TimeGap):
			}
//			log.Infof("Retry because POW Mining disabled.")
			continue
		}

		pows := 0
		blk := m.g.Chain.BestChain.Tip()
		for blk != nil && blk.Data.GetNonce() > 0 && pows < 7 {
			pows++
			blk = blk.Parent
		}

		select {
		case <-m.connch:
			continue

		case <-consensus.POWStopper:
			continue

		case <-m.quit:
			break out

		case <-time.After(time.Second * time.Duration(2*wire.TimeGap+(1<<pows))):
		}

		
		fmt.Printf("Try to solve block ")

		// Attempt to solve the block.  The function will exit early
		// with false when conditions that trigger a stale block, so
		// a new block template can be generated.  When the return is
		// true a solution was found, so submit the solved block.
		if m.solveBlock(template, curHeight+1, ticker, m.quit) {
			wb := * template.Block.(*wire.MsgBlock)
			block := btcutil.NewBlock(&wb)
			log.Infof("New POW block produced nonce = %s at %d", block.MsgBlock().Header.Nonce, template.Height)
			block.SetHeight(template.Height)
			m.submitBlock(block)
			log.Infof("Tx chian = %d Miner chain = %d", m.g.Chain.BestSnapshot().Height,
				m.g.Chain.Miners.BestSnapshot().Height)
		} else {
			log.Info("No New block produced")
		}
	}

//	close(m.speedMonitorQuit)
	m.wg.Done()

	log.Tracef("Generate blocks worker done")
}

var negHash = chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }

func (m *CPUMiner) coinbaseByCommittee(me btcutil.Address) []btcutil.Address {
	addresses := make([]btcutil.Address, 0)

	best := m.g.Chain.BestSnapshot()
	bh := best.LastRotation

	good := int64(0)

	// check collateral, any miner who has collateral spent will not
	// be qualified for award, his signature will not be accepted. award
	// will be distributed only among those whose collateral are intact.
	qualified := false
	for i := -int32(wire.CommitteeSize - 1); i <= 0; i++ {
		if mb, _ := m.g.Chain.Miners.BlockByHeight(int32(bh) + i); mb != nil {
			if m.g.Chain.CheckCollateral(mb, blockchain.BFNone) != nil {
				log.Infof("CheckCollateral failed")
				continue
			}
			adr, _ := btcutil.NewAddressPubKeyHash(mb.MsgBlock().Miner[:], m.cfg.ChainParams)
			addresses = append(addresses, adr)

			if !qualified && adr.EncodeAddress() == me.EncodeAddress() {
				qualified = true
			}
			good++
		}
	}

	if qualified && good >= wire.CommitteeSigs {
		return addresses
	} else {
		return nil
	}
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
//	m.speedMonitorQuit = make(chan struct{})
	m.wg.Add(1)
//	go m.speedMonitor()
	go m.generateBlocks()

	consensus.POWStopper = make(chan struct{}, 3 * wire.MINER_RORATE_FREQ)

	m.started = true
	log.Infof("CPU miner started")
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

	close(m.connch)

//	t := consensus.POWStopper
//	consensus.POWStopper = nil
//	close(t)

	close(m.quit)
	m.started = false

	m.wg.Wait()

	log.Infof("CPU miner stopped")
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
/*
func (m *CPUMiner) HashesPerSecond() float64 {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is not currently running.
	if !m.started {
		return -1
	}

	return <-m.queryHashesPerSec
}
 */

// SetNumWorkers sets the number of workers to create which solve blocks.  Any
// negative values will cause a default number of workers to be used which is
// based on the number of processor cores in the system.  A value of 0 will
// cause all CPU mining to be stopped.
//
// This function is safe for concurrent access.
/*
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
 */

// NumWorkers returns the number of workers which are running to solve blocks.
//
// This function is safe for concurrent access.
/*
func (m *CPUMiner) NumWorkers() int32 {
	m.Lock()
	defer m.Unlock()

	return int32(m.numWorkers)
}
 */

// GenerateNBlocks generates the requested number of blocks. It is self
// contained in that it creates block templates and attempts to solve them while
// detecting when it is performing stale work and reacting accordingly by
// generating a new block template.  When a block is solved, it is submitted.
// The function returns a list of the hashes of generated blocks.

func (m *CPUMiner) GenerateNBlocks(n uint32) ([]*chainhash.Hash, error) {
	return nil, fmt.Errorf("not supported")
/*
	m.Lock()

	// Respond with an error if server is already mining.
	if m.started || m.discreteMining {
		m.Unlock()
		return nil, errors.New("Server is already CPU mining. Please call " +
			"`setgenerate 0` before calling discrete `generate` commands.")
	}

	m.started = true
	m.discreteMining = true

	m.speedMonitorQuit = make(chan struct{})
	m.wg.Add(1)
	go m.speedMonitor()

	m.Unlock()

	log.Tracef("Generating %d blocks", n)

	i := uint32(0)
	blockHashes := make([]*chainhash.Hash, n)

	// Start a ticker which is used to signal checks for stale work and
	// updates to the speed monitor.
	ticker := time.NewTicker(time.Second * hashUpdateSecs)
	defer ticker.Stop()

	for {
		// Read updateNumWorkers in case someone tries a `setgenerate` while
		// we're generating. We can ignore it as the `generate` RPC call only
		// uses 1 worker.
		select {
		case <-m.updateNumWorkers:
		default:
		}

		// Grab the lock used for block submission, since the current block will
		// be changing and this would otherwise end up building a new block
		// template on a block that is in the process of becoming stale.
		m.submitBlockLock.Lock()
		curHeight := m.g.BestSnapshot().CHeight

		// Choose a payment address at random.
		rand.Seed(time.Now().UnixNano())
		payToAddr := m.cfg.MiningAddrs[rand.Intn(len(m.cfg.MiningAddrs))]

		// Create a new block template using the available transactions
		// in the memory pool as a source of transactions to potentially
		// include in the block.
		template, err := m.g.NewBlockTemplate(payToAddr)
		m.submitBlockLock.Unlock()
		if err != nil {
			errStr := fmt.Sprintf("Failed to create new block "+
				"template: %v", err)
			log.Errorf(errStr)
			continue
		}

		// Attempt to solve the block.  The function will exit early
		// with false when conditions that trigger a stale block, so
		// a new block template can be generated.  When the return is
		// true a solution was found, so submit the solved block.
		if m.solveBlock(template, curHeight+1, ticker, nil) {
			block := btcutil.NewBlock(template.Block.(*wire.MsgBlock))
			m.submitBlock(block)
			blockHashes[i] = block.Hash()
			i++
			if i == n {
				log.Tracef("Generated %d blocks", i)
				m.Lock()
				close(m.speedMonitorQuit)
				m.wg.Wait()
				m.started = false
				m.discreteMining = false
				m.Unlock()
				return blockHashes, nil
			}
		}
	}
*/
}

// New returns a new instance of a CPU miner for the provided configuration.
// Use Start to begin the mining process.  See the documentation for CPUMiner
// type for more details.
func New(cfg *Config) *CPUMiner {
	m := &CPUMiner{
		g:                 cfg.BlockTemplateGenerator,
		cfg:               *cfg,
//		numWorkers:        defaultNumWorkers,
//		updateNumWorkers:  make(chan struct{}),
//		queryHashesPerSec: make(chan float64),
//		updateHashes:      make(chan uint64),
		connch: 		   make(chan int32, 100),
	}

	consensus.POWStopper = make(chan struct{}, 3 * wire.MINER_RORATE_FREQ)

	m.g.Chain.Subscribe(m.Notice)	// Miners.(*minerchain.MinerChain).
	m.g.Chain.Miners.Subscribe(m.Notice)	// Miners.(*minerchain.MinerChain).
	return m
}
