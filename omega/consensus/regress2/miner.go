package main

import (
	"fmt"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/limits"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btclog"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/consensus"
	"github.com/omegasuite/omega/minerchain"
	"github.com/omegasuite/omega/token"
	flags "github.com/jessevdk/go-flags"
	"github.com/npipe"
	"net"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"time"
)

type server struct {
	state blockchain.BestState
	minerBlocks []wire.MinerBlock
}

type Options struct {
	Myself int `short:"m" long:"me" description:"My id"`

	Stall int `short:"s" long:"stall" description:"stall time in milliseconds"`

	Pipe string `short:"p" long:"pipe" description:"pipe name"`

	// Example of verbosity with level
	Verbose []bool `short:"v" long:"verbose" description:"Verbose output"`

	// Example of optional value
	User string `short:"u" long:"user" description:"User name" optional:"yes" optional-value:"pancake"`

	// Example of map with multiple default values
	Users map[string]string `long:"users" description:"User e-mail map" default:"system:system@example.org" default:"admin:admin@example.org"`
}

var options Options
var wdone bool
var msgLog = btclog.Disabled

type pvk struct {
	wif string
	address [20]byte
	privkey * btcec.PrivateKey
}
var connections = []string{"127.0.0.1:1836", "127.0.0.1:1837", "127.0.0.1:1838", "127.0.0.1:1839"}
var privKeys = []pvk{
	pvk{wif: "" },
	pvk{wif: "" },
	pvk{wif: "" },
	pvk{wif: "" },
}

var conns [4]net.Conn

var miners = int32(len(privKeys))
var messageSR [4][2]int

type serveReq struct {
	who int
	rmsg wire.Message
	buf []byte
	block * btcutil.Block
}
var servicequeue chan serveReq

func (s *server) MyPlaceInCommittee(r int32) int32 {
	r -= wire.CommitteeSize - 1
	w := r % miners
	if int32(options.Myself) < w {
		return int32(options.Myself) + miners + r - w
	} else {
		return int32(options.Myself) + r - w
	}
}

var log btclog.Logger

// Initialize package-global logger variables.
func init() {
	consensus.UseLogger(consensusLog)
	minerchain.UseLogger(minerLog)
	log = mainLog
}

func dialing(i int) net.Conn {
	if i == options.Myself {
		return nil
	}
	if conns[i] == nil {
		dial := net.Dialer{}
		c, err := dial.Dial("tcp", connections[i])
		if err != nil {
			return nil
		}
		conns[i] = c
		c.Write([]byte{byte(options.Myself)})
	}
	return conns[i]
}

type retry struct {
	who int32
	what wire.Message
}

var retryQ chan retry
var blkchain []chainhash.Hash

func (s *server) CommitteeMsg(r int32, m wire.Message) bool {
	dial := dialing(int(r % miners))

	if dial != nil {
		log.Infof("sending message to %s (remote = %s)", dial.LocalAddr().String(), dial.RemoteAddr().String())
		dial.SetWriteDeadline(time.Now().Add(time.Second * 10))
		_, err := wire.WriteMessageWithEncodingN(dial, m, 0, 1, wire.SignatureEncoding)
		if err == nil {
			msgLog.Info(formatMsg("send to ", int(r % miners), m))
			messageSR[r % miners][1]++
			return true
		}
	}

	retryQ <- retry{ r, m }

	return false
}

func (s *server) CommitteeCast(r int32, m wire.Message) {
	for i := s.state.LastRotation - wire.CommitteeSize + 1; i <= s.state.LastRotation; i++ {
		if i != uint32(r) {
			dial := dialing(int(int32(i) % miners))
			if dial != nil {
				gdial := dial
				who := int32(i)
				go func() {
					log.Infof("cast sending message to %s (remote = %s)", gdial.LocalAddr().String(), gdial.RemoteAddr().String())
					gdial.SetWriteDeadline(time.Now().Add(time.Second * 10))
					_, err := wire.WriteMessageWithEncodingN(gdial, m, 0, 1, wire.SignatureEncoding)
					if err == nil {
						msgLog.Info(formatMsg("send to ", int(who%miners), m))
						messageSR[who][1]++
					} else {
						retryQ <- retry{who, m}
					}
				}()
			} else {
				retryQ <- retry{int32(i), m}
			}
		}
	}
}

func (s *server) BroadCast(r int32, m wire.Message) {
	for i, _ := range connections {
		if int32(i) != r % miners {
			dial := dialing(i)
			if dial != nil {
				dial.SetWriteDeadline(time.Now().Add(time.Second * 10))
				_, err := wire.WriteMessageWithEncodingN(dial, m, 0, 1, wire.SignatureEncoding)
				if err == nil {
					msgLog.Info(formatMsg("send to ", i, m))
					messageSR[i][1]++
					continue
				}
			}
		}
	}
}

var nextBlk chan bool
var nxtblkrdy chan bool

func (s *server) NewConsusBlock(block * btcutil.Block) {
	log.Infof("consensus reached! sigs = %d", len(block.MsgBlock().Transactions[0].SignatureScripts))
	s.BroadCast(int32(options.Myself), block.MsgBlock())

	servicequeue <- serveReq {
		options.Myself, block.MsgBlock(), nil, block,
	}
}

func (s *server) GetPrivKey(m[20]byte) * btcec.PrivateKey {
	for _,p := range privKeys {
		if p.address == m {
			return p.privkey
		}
	}
	return nil
}

func (s *server) BestSnapshot() * blockchain.BestState {
	return &s.state
}

func (s *server) MinerBlockByHeight(n int32) (* wire.MinerBlock,error) {
	return &s.minerBlocks[int(n) % len(s.minerBlocks)], nil
}

var block * btcutil.Block

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

	wdone = false

	var parser = flags.NewParser(&options, flags.Default)

	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	if len(options.Pipe) > 0 {
		ln, err := npipe.Listen(`\\.\pipe\` + options.Pipe)
		if err == nil {
			conn, err := ln.Accept()
			if err != nil {
				// handle error
				return
			}

			conn.Write([]byte("Hello!\n"))

			b := btclog.NewBackend(conn)

			log = b.Logger("MAIN", 0xFFFF)
		}
	}

	param := &chaincfg.Params{Net:111}

	for i, strAddr := range privKeys {
		dwif,err := btcutil.DecodeWIF(strAddr.wif)
		if err != nil {
			os.Exit(4)
		}

		privKey := dwif.PrivKey
		pkaddr,err := btcutil.NewAddressPubKeyPubKey(*privKey.PubKey(), param)

		if err != nil {
			os.Exit(5)
		}

		paddr := pkaddr.AddressPubKeyHash()
		copy(privKeys[i].address[:], paddr.ScriptAddress())
		privKeys[i].privkey = privKey
	}

	defer func() {
		consensus.Quit <- struct{}{}
	}()

	file, err := os.OpenFile(fmt.Sprintf("%d.log",options.Myself), os.O_CREATE | os.O_WRONLY, os.ModePerm)
	if err == nil && file != nil {
		b := btclog.NewBackend(file)
		msgLog = b.Logger("MSG", 0xFFFF)
	}

	server := server{
		state: blockchain.BestState {
			Height: 3,
			LastRotation: 2,
		},
		minerBlocks: make([]wire.MinerBlock, 0),
	}

	server.minerBlocks = make([]wire.MinerBlock, 0)
	i := int32(0)

	log.Infof("I am %d. all key holders:", options.Myself)
	for _, mnr := range privKeys {
		log.Infof("%x", mnr.address)
		blk := wire.NewMinerBlock(&wire.MingingRightBlock {})
		copy(blk.MsgBlock().Miner[:], mnr.address[:])
		blk.SetHeight(i)
		if i == int32(options.Myself) {
			consensus.SetMiner(blk.MsgBlock().Miner)
		}
		i++
		t := *blk
		server.minerBlocks = append(server.minerBlocks, t)
	}

	listener, err := net.Listen("tcp", connections[options.Myself])

	if err != nil {
		os.Exit(7)
	}

	go server.service()

	go func() {
		for !wdone {
			conn, err := listener.Accept()
			if err != nil {
				log.Infof("error on listener.Accept: %s", err.Error())
				continue
			}
			c := conn.RemoteAddr().String()

			var b [1]byte
			conn.Read(b[:])

			fmt.Printf("received connection from %s who is %d\n", c, b[0])
			go server.serve(conn, int(b[0]))
		}
	}()

	go consensus.Consensus(&server)

	blkchain = make([]chainhash.Hash, 4)
	blkchain[3] = chainhash.Hash{}

	msgblk := wire.MsgBlock{
		Header:wire.BlockHeader{
			Version:      1,
			PrevBlock:    chainhash.Hash{},
			MerkleRoot:   chainhash.Hash{},
			Timestamp:    time.Unix(258945146, 0),
			ContractExec: 100,
			Nonce:        256,
		},
		Transactions: []*wire.MsgTx{
				&wire.MsgTx{
					Version:          1,
					TxDef:            nil,
					TxIn:             []*wire.TxIn{
						&wire.TxIn{
							PreviousOutPoint: wire.OutPoint{
								Hash:  chainhash.Hash{},
								Index: 0xFFFFFFFF,
							},
							Sequence:       0xFFFFFFFF,
							SignatureIndex: 0xFFFFFFFF,
						},
					},
					TxOut:            []*wire.TxOut{
						&wire.TxOut{
							Token: token.Token{
								TokenType: 0,
								Value:     &token.NumToken{ Val: 5000000 },
								Rights:    nil,
							},
							PkScript: name[:],
						},
						&wire.TxOut{
							Token: token.Token{
								TokenType: 0,
								Value:     &token.NumToken{ Val: 5000000 },
								Rights:    nil,
							},
							PkScript: []byte{2},
						},
						&wire.TxOut{
							Token: token.Token{
								TokenType: 0,
								Value:     &token.NumToken{ Val: 5000000 },
								Rights:    nil,
							},
							PkScript: []byte{3},
						},
					},
					SignatureScripts: [][]byte {
						[]byte{0,1,2,3}, name[:],
					},
					LockTime:         0,
				},
		},
	}

	time.Sleep(time.Second * 10)
	done := make(chan bool)
	nextBlk = make(chan bool)
	nxtblkrdy = make(chan bool)

//	if options.Myself == 0 {
//	}
//	server.CommitteeCast(int32(options.Myself), block.MsgBlock())

	retryQ = make(chan retry, 100)
	go func() {
		for !wdone {
			select {
			case q := <-retryQ:
				log.Infof("retry %s from %d", q.what.Command(), q.who)
				server.CommitteeMsg(q.who, q.what)
				time.Sleep(time.Second)
			}
		}
	}()

	go func() {
		for true {
			time.Sleep(time.Minute)
			consensus.DebugInfo()
			for i,h := range blkchain {
				log.Infof("Block %d: %s", i, h.String())
			}
		}
	}()

	nxtblkrdy = make(chan bool)
	msgblk.Header.Timestamp = time.Now()
	block = btcutil.NewBlock(&msgblk)
	block.SetHeight(server.state.Height + 1)

	for true {
		msgLog.Info(formatMsg("generated block by ", options.Myself, block.MsgBlock()))

		consensus.ProcessBlock(block, blockchain.BFSubmission)

		<- nextBlk

		log.Infof("clean up retryQ")
/*
		outretry:
		for true {
			select {
			case <-retryQ:
			default:
				break outretry
			}
		}

 */
		time.Sleep(time.Second * 1)
		fmt.Printf("\n\n\n\n\n\n\n\n\n\n")

		msgLog.Infof("Conclusion of a round. Chain Tip = %s Height = %d\n\n",
			server.state.Hash.String(), server.state.Height)
//		file.Sync()

		consensus.DebugInfo()
		log.Infof("Message received and sent:")
		for i, sr := range messageSR {
			log.Infof("For miner %s, received %d, sent %d", i, sr[0], sr[1])
		}

		msgblk.Header.PrevBlock = server.state.Hash
		msgblk.Transactions[0].SignatureScripts = [][]byte{
			msgblk.Transactions[0].SignatureScripts[0],
			name[:],
		}
		msgblk.Header.Timestamp = time.Now()

		block = btcutil.NewBlock(&msgblk)
		block.SetHeight(server.state.Height + 1)

		log.Infof("\n\n\n\n\nstarting next block")
		nxtblkrdy <- true
	}

	<-done
}

// this is the main server go routine
func (s * server) service() {
	servicequeue = make(chan serveReq, 200)
	for true {
		q := <- servicequeue
		switch msg := q.rmsg.(type) {
		case *wire.MsgBlock:
			var block *btcutil.Block
			if q.block == nil {
				block = btcutil.NewBlockFromBlockAndBytes(msg, q.buf)
				i := len(blkchain) - 1
				for ; i >= 0; i-- {
					if blkchain[i] == block.MsgBlock().Header.PrevBlock {
						block.SetHeight(int32(i) + 1)
						log.Infof("block.SetHeight %d, prev = %s\n", i+1, block.MsgBlock().Header.PrevBlock.String())
						break
					}
				}
				if i < 0 {
					msgLog.Error(formatMsg("Error: prev node is not in chain", q.who, q.rmsg))
					log.Errorf("Error: prev node is not in chain")
				}

				consensus.ProcessBlock(block, blockchain.BFNone)
			} else {
				block = q.block
			}

			if s.state.Height < block.Height() && len(block.MsgBlock().Transactions[0].SignatureScripts) > wire.CommitteeSigs {
				s.state.Height = block.Height()
				s.state.Hash = *block.Hash()
				blkchain = append(blkchain, s.state.Hash)
				if s.state.Height % wire.MINER_RORATE_FREQ == 0 {
					s.state.LastRotation++
				}
				fmt.Printf("\n\n\n\n\n\n\n\n\n\n\n\n")
				log.Infof("Update chain state height = %d LastRotation = %s", s.state.Height, s.state.LastRotation)
				nextBlk <- true
				<- nxtblkrdy
			}

		case *wire.MsgGetData:
			log.Infof("sending my block to %d", q.who)
			s.CommitteeMsg(int32(q.who), block.MsgBlock())
//			wire.WriteMessageWithEncodingN(conns[who], block.MsgBlock(), 0, 1, wire.SignatureEncoding)

		case consensus.Message:
			consensus.HandleMessage(msg)
		}
	}
}

func (s * server) serve(connect net.Conn, who int) {
	for true {
		log.Infof("wait for message at %s (remote = %s)", connect.LocalAddr().String(), connect.RemoteAddr().String())
		_, rmsg, buf, err := wire.ReadMessageWithEncodingN(connect, 0, 1, wire.SignatureEncoding)

		if err != nil {
			fmt.Printf("error %s in reading message [%x] from %d\n", err.Error(), buf, who)
			return
		}

		if options.Stall != 0 {
			time.Sleep(time.Millisecond * time.Duration(options.Stall))
		}

		messageSR[who][0]++
		msgLog.Infof(formatMsg("received from ", who, rmsg))
		log.Infof("received message %s from %d\n", reflect.TypeOf(rmsg).String(), who)
		servicequeue <- serveReq { who, rmsg, buf, nil }
	}
}

func formatMsg(tag string, who int, rmsg wire.Message) string {
	var s string

	switch msg := rmsg.(type) {
	case *wire.MsgBlock:
		s = fmt.Sprintf("MsgBlock with hash = %s", msg.BlockHash().String())

	case *wire.MsgGetData:
		s = fmt.Sprintf("MsgGetData for hash = %s", msg.InvList[0].Hash.String())

	case consensus.Message:
		s = fmt.Sprintf("consensus.Message at height %d\n", msg.Block())
		switch k := msg.(type) {
		case *wire.MsgKnowledge: // passing knowledge
			s += fmt.Sprintf("MsgKnowledge: Finder = %x\nFrom = %x\nHeight = %d\nM = %s\nK = [%v]",
				k.Finder, k.From, k.Height, k.M.String(), k.K)

		case *wire.MsgCandidate: // announce candidacy
			s += fmt.Sprintf("MsgCandidate: M = %s\nHeight = %d\nF = %x\nSignature = %x",
				k.M.String(), k.Height, k.F, k.Signature)

		case *wire.MsgCandidateResp: // response to candidacy announcement
			s += fmt.Sprintf("MsgCandidateResp: M = %s\nHeight = %d\nFrom = %x\nSignature = %x\n",
				k.M.String(), k.Height, k.From, k.Signature)
			s += fmt.Sprintf("Reply = %s\nBetter = %d\nK = %v",
				k.Reply, k.Better, k.K)

		case *wire.MsgRelease: // grant a release from duty
			s += fmt.Sprintf("MsgRelease: M = %s\nHeight = %d\nFrom = %x\n",
				k.M.String(), k.Height, k.From)
			s += fmt.Sprintf("Better = %d\nK = %v",	k.Better, k.K)

		case *wire.MsgConsensus: // announce consensus reached
			s += fmt.Sprintf("MsgConsensus: Height = %d\nFrom = %x\nSignature = %x",
				k.Height, k.From, k.Signature)

		case *wire.MsgSignature: // give signature
			s += fmt.Sprintf("MsgSignature: Height = %d\nFrom = %x\nSignature = %x",
				k.Height, k.From, k.Signature)
		}
	}

	return tag + fmt.Sprintf("%d", who) + ": " + s + "\n\n"
}
