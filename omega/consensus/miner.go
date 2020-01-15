package consensus

import (
	"fmt"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"net/http"
	"sync"
)

const (
	maxTxPerBlock = 50000
)

type Message interface {
	Block() int32
}

var Debug        int // hash of last block

type PeerNotifier interface {
	MyPlaceInCommittee(r int32) int32
	CommitteeMsg(int32, wire.Message) bool
	CommitteeCast(int32, wire.Message)
	CommitteeMsgMG(int32, wire.Message, int32)
	CommitteeCastMG(int32, wire.Message, int32)
	NewConsusBlock(block * btcutil.Block)
	GetPrivKey([20]byte) * btcec.PrivateKey
	BestSnapshot() * blockchain.BestState
	MinerBlockByHeight(int32) (* wire.MinerBlock,error)
}

type Miner struct {
	syncMutex    sync.Mutex
	Sync         map[int32]*Syncer
	server		 PeerNotifier
	updateheight chan int32
	name [20]byte
}

type newblock struct {
	block *btcutil.Block
	flags blockchain.BehaviorFlags
}

/*
type newhead struct {
	chain *blockchain.BlockChain
	head *MsgMerkleBlock
	flags blockchain.BehaviorFlags
}

 */

var newblockch chan newblock
// var newheadch chan newhead

func ProcessBlock(block *btcutil.Block, flags blockchain.BehaviorFlags) {
	flags |= blockchain.BFNoConnect
	log.Infof("Consensus.ProcessBlock for block %s at %d, flags=%x",
		block.Hash().String(), block.Height(), flags)

	newblockch <- newblock { block, flags }
}

/*
func ProcessHeader(b *blockchain.BlockChain, block *MsgMerkleBlock) {
	flags := blockchain.BFNoConnect
	fmt.Printf("Consensus for header at %d", block.Height)
	newheadch <- newhead { b,block, flags }
}
*/

var miner * Miner

var Quit chan struct{}
var errMootBlock error
var errInvalidBlock error

func Consensus(s PeerNotifier, addr btcutil.Address) {
	miner = &Miner{}
	miner.server = s

	miner.Sync = make(map[int32]*Syncer, 0)
	miner.syncMutex = sync.Mutex{}

	var name [20]byte
	copy(name[:], addr.ScriptAddress())
	miner.name = name

	newblockch = make(chan newblock)
	errMootBlock = fmt.Errorf("Moot block.")
	errInvalidBlock = fmt.Errorf("Invalid block")
	Quit = make(chan struct{})

	log.Info("Consensus running")

	// this should run as a goroutine
	out:
	for true {
		select {
		case height := <- miner.updateheight:
			log.Infof("updateheight %d", height)
			cleaner(height)
			miner.syncMutex.Lock()
			for _, t := range miner.Sync {
				t.UpdateChainHeight(height)
			}
			miner.syncMutex.Lock()

		case blk := <- newblockch:
			top := miner.server.BestSnapshot().Height
			bh := blk.block.Height()
			log.Infof("miner received newblockch %s at %d vs. %d",
				blk.block.Hash().String(), top, bh)

			if bh <= top {
				continue
			}

			if len(blk.block.MsgBlock().Transactions[0].SignatureScripts) > wire.CommitteeSize / 2 + 1 {
				// should never gets here
				log.Infof("Block is a consensus. Accept it and close processing for height %d.", bh)
				continue
/*
				miner.syncMutex.Lock()
				if _, ok := miner.Sync[bh]; ok {
					miner.Sync[bh].Quit()
					miner.syncMutex.Unlock()
//					delete(miner.Sync, bh)
					continue
				}
				miner.syncMutex.Unlock()
 */
			}

//			cleaner(top)
			miner.syncMutex.Lock()
			if _, ok := miner.Sync[bh]; !ok {
				log.Infof(" CreateSyncer at %d", bh)
				miner.Sync[bh] = CreateSyncer(bh)
			}
			log.Infof(" BlockInit at %d for block %s", bh, blk.block.Hash().String())
			miner.Sync[bh].BlockInit(blk.block)
			miner.syncMutex.Unlock()
/*
		case head := <- newheadch:
			top := head.chain.BestSnapshot().Height
//			cleaner(top)
			if head.head.Height < top {
				continue
			}

			if _, ok := miner.Sync[head.head.Height]; !ok {
				miner.Sync[head.head.Height] = CreateSyncer()
			}
			if !miner.Sync[head.head.Height].Initialized {
				miner.Sync[head.head.Height].Initialize(head.chain, head.head.Height)
			}
			miner.Sync[head.head.Height].HeaderInit(head.head)
*/
		case <- Quit:
			log.Info("consensus received Quit")
			miner.syncMutex.Lock()
			for i, t := range miner.Sync {
				log.Infof("Sync %d to Quit", i)
				t.Quit()
				delete(miner.Sync, i)
			}
			miner.syncMutex.Unlock()
			break out
		}
	}

	for true {
		select {
		case <-miner.updateheight:
		case <-newblockch:
//		case <-newheadch:

		default:
			log.Info("consensus quits")
			return
		}
	}
}

func HandleMessage(m Message) {
	// the messages here are consensus messages. specifically, it does not include block msg.
	h := m.Block()

	miner.syncMutex.Lock()
	s, ok := miner.Sync[h]

	if !ok {
		miner.Sync[h] = CreateSyncer(h)
		s = miner.Sync[h]
	} else if miner.Sync[h].Done {
		miner.syncMutex.Unlock()
		log.Infof("syncer has finished with %h. Ignore this message", h)
		return
	}
	miner.syncMutex.Unlock()

//	log.Infof("miner dispatching Message for height %d", m.Block())

	s.SetCommittee()
	
	if !s.Runnable {
		log.Infof("syncer is not ready for height %d, message will be queues. Current que len = %d", h, len(s.messages))
	}

	s.messages <- m
}

func UpdateChainHeight(latestHeight int32) {
	if miner != nil {
		miner.updateheight <- latestHeight
	}
}

func cleaner(top int32) {
	miner.syncMutex.Lock()
	for i, t := range miner.Sync {
		if i < top {
			t.Quit()
			delete(miner.Sync, i)
		}
	}
	miner.syncMutex.Unlock()
}

func VerifyMsg(msg wire.OmegaMessage, pubkey * btcec.PublicKey) bool {
	signature, err := btcec.ParseSignature(msg.GetSignature(), btcec.S256())
	if err != nil {
		return false
	}
	valid := signature.Verify(msg.DoubleHashB(), pubkey)
	return valid
}

func (self *Miner) Debug(w http.ResponseWriter, r *http.Request) {
}

func DebugInfo() {
	log.Infof("Miner has %d Syncers\n\n", len(miner.Sync))
	top := int32(0)
	miner.syncMutex.Lock()
	for h,_ := range miner.Sync {
		if h > top {
			top = h
		}
	}
	for h,_ := range miner.Sync {
		if h < top - 2 {
			delete(miner.Sync, h)
		}
	}
	for h,s := range miner.Sync {
		log.Infof("Syncer at %d", h)
		s.DebugInfo()
	}
	miner.syncMutex.Unlock()
}