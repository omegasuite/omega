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

func (s *server) MyPlaceInCommittee(r int32) int32 {
	return int32(options.Myself)
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

func (s *server) CommitteeMsg(r int32, m wire.Message) bool {
	dial := dialing(int(r))

	if dial != nil {
		_, err := wire.WriteMessageWithEncodingN(dial, m, 0, 1, wire.SignatureEncoding)
		if err == nil {
			return true
		}
	}

	retryQ <- retry{ r, m }

	return false
}

func (s *server) CommitteeCast(r int32, m wire.Message) {
	for i, _ := range connections {
		if int32(i) != r && i < wire.CommitteeSize {
			dial := dialing(i)
			if dial != nil {
				_,err := wire.WriteMessageWithEncodingN(dial, m, 0, 1, wire.SignatureEncoding)
				if err == nil {
					continue
				}
			}
			retryQ <- retry{ int32(i), m }
		}
	}
}

func (s *server) NewConsusBlock(block * btcutil.Block) {
	log.Infof("consensus reached!")
	s.CommitteeCast(-1, block.MsgBlock())
	for _, c := range conns {
		if c != nil {
			c.Close()
		}
	}
	wdone = true
//	os.Exit(0)
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
	if n < int32(len(s.minerBlocks)) {
		return &s.minerBlocks[n], nil
	}
	return nil, fmt.Errorf("miner block %d does not exist", n)
}

var block * btcutil.Block

type Pipe os.File


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

	server := server{
		state: blockchain.BestState {
			Height: 3,
			LastRotation: 2,
		},
		minerBlocks: make([]wire.MinerBlock, 0),
	}

	server.minerBlocks = make([]wire.MinerBlock, 0)
	i := int32(0)
	var name [20]byte
	log.Infof("I am %d. all key holders:", options.Myself)
	for _, mnr := range privKeys {
		log.Infof("%x", mnr.address)
		blk := wire.NewMinerBlock(&wire.MingingRightBlock{})
		copy(blk.MsgBlock().Miner[:], mnr.address[:])
		blk.SetHeight(i)
		if i == int32(options.Myself) {
			name = mnr.address
			consensus.SetMiner(name)
		}
		i++
		t := *blk
		server.minerBlocks = append(server.minerBlocks, t)
	}

	listener, err := net.Listen("tcp", connections[options.Myself])

	if err != nil {
		os.Exit(7)
	}

	go func() {
		for !wdone {
			conn, err := listener.Accept()
			if err != nil {
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

	block = btcutil.NewBlock(&wire.MsgBlock{
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
	})
	block.SetHeight(4)

	time.Sleep(time.Second * 10)
	done := make(chan bool)

//	if options.Myself == 0 {
		consensus.ProcessBlock(block, blockchain.BFSubmission)
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

	<-done
}

func (s * server) serve(connect net.Conn, who int) {
	for true {
		_, rmsg, buf, err := wire.ReadMessageWithEncodingN(connect, 0, 1, wire.SignatureEncoding)

		if options.Stall != 0 {
			time.Sleep(time.Millisecond * time.Duration(options.Stall))
		}

		if err != nil {
			fmt.Printf("error %s in reading message [%x] from %d\n", err.Error(), buf, who)
			return
		}

		fmt.Printf("received message %s from %d\n", reflect.TypeOf(rmsg).String(), who)

		switch msg := rmsg.(type) {
		case *wire.MsgBlock:
			block := btcutil.NewBlockFromBlockAndBytes(msg, buf)
			block.SetHeight(4)
			consensus.ProcessBlock(block, blockchain.BFNone)

		case *wire.MsgGetData:
			log.Infof("sending my block to %d", who)
			s.CommitteeMsg(int32(who), block.MsgBlock())
//			wire.WriteMessageWithEncodingN(conns[who], block.MsgBlock(), 0, 1, wire.SignatureEncoding)

		case consensus.Message:
			consensus.HandleMessage(msg)

		default:
		}
	}
}
