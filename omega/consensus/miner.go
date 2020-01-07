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
	NewConsusBlock(block * btcutil.Block)
	GetPrivKey([20]byte) * btcec.PrivateKey
}

type Miner struct {
	syncMutex    sync.Mutex
	Sync         map[int32]*Syncer
	server		 PeerNotifier
	updateheight chan int32
}

type newblock struct {
	chain *blockchain.BlockChain
	block *btcutil.Block
	flags blockchain.BehaviorFlags
}

type newhead struct {
	chain *blockchain.BlockChain
	head *MsgMerkleBlock
	flags blockchain.BehaviorFlags
}

var newblockch chan newblock
var newheadch chan newhead

func ProcessBlock(b *blockchain.BlockChain, block *btcutil.Block, flags blockchain.BehaviorFlags) {
	flags |= blockchain.BFNoConnect
	log.Infof("Consensus for block at %d", block.Height)
	newblockch <- newblock { b,block, flags }
}

func ProcessHeader(b *blockchain.BlockChain, block *MsgMerkleBlock) {
	flags := blockchain.BFNoConnect
	fmt.Printf("Consensus for header at %d", block.Height)
	newheadch <- newhead { b,block, flags }
}

var miner * Miner

var Quit chan struct{}
var errMootBlock error
var errInvalidBlock error

func Consensus(s PeerNotifier) {
	newblockch = make(chan newblock)
	errMootBlock = fmt.Errorf("Moot block.")
	errInvalidBlock = fmt.Errorf("Invalid block")
	Quit = make(chan struct{})

	miner = CreateMiner(s)

	log.Info("Consensus running")

	// this should run as a goroutine
	out:
	for {
		select {
		case height := <- miner.updateheight:
			cleaner(height)
			for _, t := range miner.Sync {
				t.UpdateChainHeight(height)
			}

		case blk := <- newblockch:
			top := blk.chain.BestSnapshot().Height
			cleaner(top)
			if blk.block.Height() < top {
				continue
			}

			if _, ok := miner.Sync[blk.block.Height()]; !ok {
				miner.Sync[blk.block.Height()] = CreateSyncer()
			}
			if !miner.Sync[blk.block.Height()].Initialized {
				miner.Sync[blk.block.Height()].Initialize(blk.chain, blk.block.Height())
			}
			miner.Sync[blk.block.Height()].BlockInit(blk.block)

		case head := <- newheadch:
			top := head.chain.BestSnapshot().Height
			cleaner(top)
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

		case <- Quit:
			log.Info("consensus received Quit")
			for i, t := range miner.Sync {
				log.Infof("Sync %d to Quit", i)
				t.Quit()
				delete(miner.Sync, i)
			}
			break out
		}
	}

	for {
		select {
		case <-miner.updateheight:
		case <-newblockch:
		case <-newheadch:

		default:
			log.Info("consensus quits")
			return
		}
	}
}

func HandleMessage(m Message) {
	log.Infof("consensus message for height %d", m.Block())
	s, ok := miner.Sync[m.Block()]
	if !ok {
		miner.Sync[m.Block()] = CreateSyncer()
	}
	s.messages <- m
}

func CreateMiner(s PeerNotifier) *Miner {
	p := Miner{}
	p.server = s
	p.Sync = make(map[int32]*Syncer, 0)
	p.syncMutex = sync.Mutex{}

	return &p
}

func UpdateChainHeight(latestHeight int32) {
	miner.updateheight <- latestHeight
}

var doneque = make(map[int64]bool, 0)
var Mutex sync.Mutex

func cleaner(top int32) {
	for i, t := range miner.Sync {
		if i < top {
			t.Quit()
			delete(miner.Sync, i)
		}
	}
}

func VerifyMsg(msg OmegaMessage, pubkey * btcec.PublicKey) bool {
	signature, err := btcec.ParseSignature(msg.GetSignature(), btcec.S256())
	if err != nil {
		return false
	}
	valid := signature.Verify(msg.DoubleHashB(), pubkey)
	return valid
}

func (self *Miner) Debug(w http.ResponseWriter, r *http.Request) {
}
