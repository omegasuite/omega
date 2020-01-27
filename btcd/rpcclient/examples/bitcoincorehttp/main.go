// Copyright (c) 2014-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"log"

	"bufio"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	flags "github.com/jessevdk/go-flags"
	"os"
	"strings"
)

type Options struct {
	Host string `short:"h" long:"host" description:"host"`

	Port string `short:"p" long:"port" description:"port"`
}

var options = Options { Host: "localhost", Port: "18334"}

var minerName = map[string]string{
	"6beafade16563e9f87e5625708af74196d2a523c":"alice",
	"638e212c048282aa3f8e04ffda0726e6131b17e3":"alice",
	"241ef4f1427b2cb443d92aaa607d1f900d7a08e5":"bob",
	"58d0219a31ca4902e42f5a657c87627905d1644d":"cathy",
	"4e3b7e6fd416b92c0ff168712552479bae812a9d":"donald"}

var detail = int(4)

func main() {
	var parser = flags.NewParser(&options, flags.Default)

	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	// Connect to local bitcoin core RPC server using HTTP POST mode.
	connCfg := &rpcclient.ConnConfig{
		Host:         options.Host + ":" + options.Port,
		User:         "admin",
		Pass:         "123456",
		HTTPPostMode: true, // Bitcoin core only supports HTTP POST mode
		DisableTLS:   true, // Bitcoin core does not provide TLS by default
	}
	// Notice the notification parameter is nil since notifications are
	// not supported in HTTP POST mode.
	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Shutdown()

	fmt.Println("Using " + connCfg.Host)

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Simple Shell")
	fmt.Println("---------------------")

	var gtx * wire.MsgTx
	var mining bool

	for {
		fmt.Print("-> ")
		text, _ := reader.ReadString('\n')
		// convert CRLF to LF
		text = strings.Replace(strings.Replace(text, "\r", "", -1), "\n", "", -1)

		switch text {
		case "hi":
			fmt.Println("hello, Yourself")
			break
		case "port":
			fmt.Println("Port number -> ")
			s, _ := reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			if s == options.Port {
				continue
			}
			client.Shutdown()
			options.Port = s
			connCfg.Host = options.Host + ":" + options.Port
			client, err = rpcclient.New(connCfg, nil)
			if err != nil {
				log.Fatal(err)
			}
			break
		// 一般性的命令
		case "stop":
			// Shutdown shuts down the client by disconnecting any connections associated
			// with the client
			client.Shutdown()
			log.Printf("Shutdown\n")
			break
		case "shutdown":
			// Shutdown shuts down the btcd server
			err = client.ShutdownServer()
			if err != nil {
				log.Printf("ShutdownServer: %s\n", err)
			} else {
				log.Printf("Server shut down\n")
				os.Exit(1)
			}
			break
		case "getinfo":
			res, err := client.GetInfo()
			if err != nil {
				log.Print(err)
			} else {
				log.Printf("Version: %d\nBlocks:%d\nBalance:%f\nConnections:%d\nDifficulty:%f\nErrors:%s\n"+
					"KeypoolOldest:%d\nKeypoolSize:%d\nPaytxFee:%fProtocol\nVersion:%d\nProxy:%s\nRelayFee:%f\n"+
					"TestNet:%s\nTimeOffset:%d\nUnlockedUntil:%d\nWalletVersion:%d\n", res.Version, res.Blocks,
					res.Balance, res.Connections, res.Difficulty, res.Errors, res.KeypoolOldest, res.KeypoolSize, res.PaytxFee,
					res.ProtocolVersion, res.Proxy, res.RelayFee, res.TestNet, res.TimeOffset, res.UnlockedUntil, res.WalletVersion)
			}
			break
		case "ping":
			err := client.Ping()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Ping\n")
			break
		case "getnettotals":
			res, err := client.GetNetTotals()
			if err != nil {
				log.Print(err)
			}
			log.Printf("TimeMillis: %d\nTotalBytesRecv:%d\nTotalBytesSent:%d\n", res.TimeMillis, res.TotalBytesRecv, res.TotalBytesSent)
			break
		case "getnetworkinfo":
			h, err := client.GetNetworkHashPS()
			if err != nil {
				log.Print(err)
			}
			log.Printf("NetworkHashPS: %d", h)
			break
		case "getpeerinfo":
			res, err := client.GetPeerInfo()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Peer: %d", res)
			break
		case "getconnectioncount":
			count, err := client.GetConnectionCount()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Count: %d", count)
			break
		case "verifychain":	// ( checklevel numblocks )
			b, err := client.VerifyChain()
			if err != nil {
				log.Print(err)
			}
			log.Printf("VerifyChain: %s", b)
			break
		case "getaddednodeinfo":	// dns ( "node" )
			b, err := client.GetAddedNodeInfo("")
			if err != nil {
				log.Print(err)
			}
			log.Printf("getaddednodeinfo: %s", b)
			break
		case "addnode":	// "node" "add|remove|onetry"
			err := client.AddNode("", "add")
			if err != nil {
				log.Print(err)
			}
			log.Printf("AddNode")
			break

		// New commands
		case "define":	//  add definition to Tx
			fmt.Println("hello, Yourself")
			break

		// Tx、Block、Ming
		case "createrawtransaction":	//  [{"txid":"id","vout":n},...] {"address":amount,...}
			fmt.Println("Input (utxo hash & seq) -> ")
			// 90039e47190579daf219d0ec2348d117126c73c812bdd06c3b2ccf62026ea5d7 (polygon)
			// 3392c719652d306c0887ec503ea87b16269428a020c81dbbfe715700ae5c5620 (coin)
			s, _ := reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			var i int
			fmt.Sscanf(s, "%d", &i)

			in := make([]btcjson.TransactionInput, 0)
			defs := make([]btcjson.Definition, 0)

			in = append(in, btcjson.TransactionInput{
				Txid: s,
				Vout: uint32(i),
			})

			out := make(map[btcutil.Address]btcjson.Token, 0)
			fmt.Println("Output to -> ")

			// mainnet addresses:
			// 1EnJHhq8Jq8vDuZA5ahVh6H4t6jh1mB4rq
			// 1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v
			// 33wvNiUkXJAJ85e4yXJxJVWtsKqWDsDFK4

			// testnet addresses:
			// ms6HYbv1YGKbxgQEEHa7TZBQvKRTcSQmtZ
			// 2MuVt8ZtHw1mTawgbru2SA5mH1Ubriyv97Q
			// 2N1CFREjXRetQXPcwk3zN5se7mZuUAJRVqb

			// mvRwyVFjTeVqRjAywZk9sfpPewwaBpvpR5	genesis?

			s = ""
			for len(s) == 0 {
				s, _ = reader.ReadString('\n')
				s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			}

			fmt.Println("Output amount/hash -> ")
			t, _ := reader.ReadString('\n')
			t = strings.Replace(strings.Replace(t, "\r", "", -1), "\n", "", -1)

			// 3cdb999564d87eafaa2952c814418a891e3c9ae3dab6e1a0e9c724ba58a19e27
//			a,_ := btcutil.DecodeAddress(s, &chaincfg.MainNetParams)
			a,_ := btcutil.DecodeAddress(s, &chaincfg.TestNet3Params)
//			a,_ := btcutil.DecodeAddress(s, &chaincfg.RegressionNetParams)
//			a,_ := btcutil.NewAddressPubKeyHash([]byte(s), &chaincfg.RegressionNetParams)

			if len(t) == 64 {
				out[a] = btcjson.Token {
					TokenType:3,
					Value:map[string]interface{}{"hash":t},
//					Rights: nil,
				}
			} else {
				var f float64
				fmt.Sscanf(t, "%f", &f)
				out[a] = btcjson.Token {
					TokenType:0,
					Value:map[string]interface{}{"value":uint64(f * btcutil.SatoshiPerBitcoin)},
//					Rights: nil,
				}
			}
			lock := int64(0)
			tx, err := client.CreateRawTransaction(in, defs, out, &lock)
			if err != nil {
				log.Print(err)
			}
			gtx = tx
			log.Printf("createrawtransaction: %s", tx)
			break
//createrawtransaction
// 3392c719652d306c0887ec503ea87b16269428a020c81dbbfe715700ae5c5620
// 0
// 2MuVt8ZtHw1mTawgbru2SA5mH1Ubriyv97Q
// 49.5

// createrawtransaction
// 90039e47190579daf219d0ec2348d117126c73c812bdd06c3b2ccf62026ea5d7
// 0
// 2MuVt8ZtHw1mTawgbru2SA5mH1Ubriyv97Q
// a9e984676a31c48ef9bfd97ca3eea1df4d76ef934d149f22eec4a373308f27cb
// Right: 59e6ecc2d08f9aee602bcae38a95bd1a5041923a16323c8ca2ba2b9cb6887626
		case "signrawtransaction":	//  "hexstring" ( [{"txid":"id","vout":n,"scriptPubKey":"hex","redeemScript":"hex"},...] ["privatekey1",...] sighashtype )
			keys := make([]string, 1)
			keys[0] = string("cQdPVU5KSzLkD1rhvLJztvpWBu9TrVAE2iPxfgEQrzWuS5xLNRX6")
			tx, suc, err := client.SignRawTransaction(gtx, keys)
			if err != nil {
				log.Print(err)
			} else if suc {
				log.Printf("signrawtransaction: %s", tx)
			} else {
				log.Printf("signrawtransaction: failed. tx = %s", tx)
			}
			gtx = tx
			break
		case "sendrawtransaction":	// "hexstring" ( allowhighfees )
			hash, err := client.SendRawTransaction(gtx, true)
			if err != nil {
				log.Print(err)
			} else {
				log.Printf("sendrawtransaction hash=: %s", hash)
			}
			break
		case "getrawmempool":	//  ( verbose )
			h, err := client.GetRawMempool()
			if err != nil {
				log.Print(err)
			}
			for _,s := range h {
				log.Printf("getrawmempool: %s", s.String())
			}
			break
		case "gettxout":	//  "txid" n ( includemempool )
			fmt.Println("UTXO(!) tx hash -> ")
			// 90039e47190579daf219d0ec2348d117126c73c812bdd06c3b2ccf62026ea5d7 (polygon)
			// 3392c719652d306c0887ec503ea87b16269428a020c81dbbfe715700ae5c5620 (coin)
			s, _ := reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)

			h,_ := chainhash.NewHashFromStr(s)

			mp := false

			res, err := client.GetTxOut(h, 0, mp)
			if err != nil {
				log.Print(err)
			}
			log.Printf("gettxout: %s", res)
			break
		case "lod":	//  "txid" ( verbose )
			fmt.Println("Level of detail (0-4) -> ")
			s, _ := reader.ReadString('\n')
			fmt.Sscanf(s,"%d", &detail)
			break
		case "getrawtransaction":	//  "txid" ( verbose )
			fmt.Println("Tx (any) hash -> ")
			// 90039e47190579daf219d0ec2348d117126c73c812bdd06c3b2ccf62026ea5d7 (polygon)
			// 3392c719652d306c0887ec503ea87b16269428a020c81dbbfe715700ae5c5620 (coin)
			s, _ := reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)

			h,_ := chainhash.NewHashFromStr(s)

			res, err := client.GetRawTransaction(h)
			if err != nil {
				log.Print(err)
			}
			log.Printf("getrawtransaction: %s", *(res.MsgTx()))
			break
		case "decoderawtransaction":	//  "hexstring"
			res, err := client.DecodeRawTransaction(nil)
			if err != nil {
				log.Print(err)
			}
			log.Printf("gettxout: %d", res)
			break
		case "decodescript":	//  "hex"
			res, err := client.DecodeScript(nil)
			if err != nil {
				log.Print(err)
			}
			log.Printf("decodescript: %d", res)
			break
		case "getblockchaininfo":	//
			res, err := client.GetBlockChainInfo()
			if err != nil {
				log.Print(err)
			} else {
				log.Printf("Chain: %s", res.Chain)
				log.Printf("Blocks: %d", res.Blocks)
				log.Printf("Headers: %d", res.Headers)
				log.Printf("Rotate: %d", res.Rotate)
				log.Printf("BestBlockHash: %s", res.BestBlockHash)
				log.Printf("Difficulty: %f", res.Difficulty)
				log.Printf("MedianTime: %d", res.MedianTime)
				log.Printf("MinerBlocks: %d", res.MinerBlocks)
				log.Printf("MinerHeaders: %d", res.MinerHeaders)
				log.Printf("MinerBestBlockHash: %s", res.MinerBestBlockHash)
				log.Printf("MinerDifficulty: %f", res.MinerDifficulty)
				log.Printf("MinerMedianTime: %d", res.MinerMedianTime)
			}
			break
		case "getblockcount":	//
			// Get the current block count.
			blockCount, err := client.GetBlockCount()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Block count: %d", blockCount)
			break
		case "getminerblockcount":	//
			// Get the current block count.
			blockCount, err := client.GetMinerBlockCount()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Block count: %d", blockCount)
			break
		case "getbestblockhash":	//
			res, err := client.GetBestBlockHash()
			if err != nil {
				log.Print(err)
			}
			log.Printf("GetBestBlockHash: %s", res)
			break
		case "getbestminerblockhash":	//
			res, err := client.GetBestMinerBlockHash()
			if err != nil {
				log.Print(err)
			}
			log.Printf("GetBestMinerBlockHash: %s", res)
			break
		case "getblockhash":	//  index
			fmt.Println("Block height -> ")
			s, _ := reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			var h int64
			fmt.Sscanf(s, "%d", &h)
			res, err := client.GetBlockHash(h)
			if err != nil {
				log.Print(err)
			} else {
				log.Printf("GetBlockHash: %s", res.String())
			}
			break
		case "getminerblockhash":	//  index
			fmt.Println("Block height -> ")
			s, _ := reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			var h int64
			fmt.Sscanf(s, "%d", &h)
			res, err := client.GetMinerBlockHash(h)
			if err != nil {
				log.Print(err)
			} else {
				log.Printf("GetMinerBlockHash: %s", res.String())
			}
			break
		case "getblock":	//  "hash" ( verbose )
			fmt.Println("Block hash -> ")
			s := "00002c7307e3905a38ca29a862cc2e018202de40619c88765124d37a771cae49"	// block 0 hash
			s, _ = reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			h,_ := chainhash.NewHashFromStr(s)
			res, err := client.GetBlock(h)
			if err != nil {
				log.Print(err)
			} else {
				log.Printf("Header.Version:%d\n", res.Header.Version)
				log.Printf("Header.Nonce:%d\n", res.Header.Nonce)
				log.Printf("Header.Timestamp:%d\n", res.Header.Timestamp)
				log.Printf("Header.MerkleRoot:%d\n", res.Header.MerkleRoot.String())
				log.Printf("Header.PrevBlock:%d\n", res.Header.PrevBlock.String())
				for _, t := range res.Transactions {
					log.Printf("-------------------------- Transaction ------------------------------\n")
					log.Printf("TxHash: %s", t.TxHash().String())
					log.Printf("Version: %d\n", t.Version)
					log.Printf("LockTime: %d\n", t.LockTime)
					log.Printf("TxIn: \n")
					for _, in := range t.TxIn {
						log.Printf("PreviousOutPoint: %s : %d\n", in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
						log.Printf("Sequence: %d\n", in.Sequence)
					}
					log.Printf("TxDef: \n")
					for _, d := range t.TxDef {
						log.Printf("DefType: %s Hash: %s\n", d.DefType(), d.Hash().String())
					}
					log.Printf("TxOut: \n")
					for _, out := range t.TxOut {
						log.Printf("TokenType: \n", out.TokenType)
						log.Printf("Value: \n", out.Value)
						log.Printf("Rights: \n", out.Rights)
					}
					log.Printf("SignatureScripts: \n")
					for _, out := range t.SignatureScripts {
						log.Printf("Signature: %x\n", out)
					}
				}
			}
			break
		case "getminerblock":	//  "hash" ( verbose )
			fmt.Println("Block hash -> ")
			s := "00002c7307e3905a38ca29a862cc2e018202de40619c88765124d37a771cae49"	// block 0 hash
			s, _ = reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			h,_ := chainhash.NewHashFromStr(s)
			res, err := client.GetMinerBlock(h)
			if err != nil {
				log.Print(err)
			} else {
				mn := minerName[fmt.Sprintf("%x", res.Miner)]

				log.Printf("Header.Version:%d\n", res.Version)
				log.Printf("Nonce:%d\n", res.Nonce)
				log.Printf("Bits:%d\n", res.Bits)
				log.Printf("Timestamp:%d\n", res.Timestamp)
				log.Printf("PrevBlock:%s\n", res.PrevBlock.String())
				log.Printf("ReferredBlock:%s\n", res.ReferredBlock.String())
				log.Printf("BestBlock:%s\n", res.BestBlock.String())
				log.Printf("Miner:%s (%s)\n", hex.EncodeToString(res.Miner), mn)
				log.Printf("Connection:%s\n", string(res.Connection))
//				log.Printf("Header.BlackList:%s\n", hex.EncodeToString(res.BlackList))
			}
			break
		case "getminerblocks":	//  "hash" ( verbose )
			fmt.Println("Start Block Height -> ")
			s, _ := reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			var start int64
			fmt.Sscanf(s, "%d", &start)

			fmt.Println("End Block Height -> ")
			s, _ = reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			var end int64
			fmt.Sscanf(s, "%d", &end)

			for i := start; i <= end; i++ {
				res, err := client.GetMinerBlockHash(i)
				if err != nil {
					log.Print(err)
					break
				}
/*
				s, _ := client.GetMinerBlockVerbose(res)
				log.Print(string(s))
*/
				blk, err := client.GetMinerBlock(res)
				if err != nil {
					log.Print(err)
				} else {
					mn := minerName[fmt.Sprintf("%x", blk.Miner)]

					log.Printf("\nBlock Height and Hash:%d %s\n", i, res.String())
					if detail < 3 {
						if detail < 1 {
							log.Printf("Version:%d\n", blk.Version)
							log.Printf("Timestamp:%d\n", blk.Timestamp)
						}
						if detail < 2 {
							log.Printf("Nonce:%d\n", blk.Nonce)
							log.Printf("Bits:%d\n", blk.Bits)
						}
						log.Printf("PrevBlock:%s\n", blk.PrevBlock.String())
						log.Printf("ReferredBlock:%s\n", blk.ReferredBlock.String())
						log.Printf("BestBlock:%s\n", blk.BestBlock.String())
					}
					log.Printf("Miner:%s (%s)\n", hex.EncodeToString(blk.Miner), mn)
					log.Printf("Connection:%s\n", string(blk.Connection))

//					log.Printf("Header.BlackList:%s\n", hex.EncodeToString(blk.BlackList))
				}
			}

			break

		case "getblocks":	//  "hash" ( verbose )
			fmt.Println("Start Block Height -> ")
			s, _ := reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			var start int64
			fmt.Sscanf(s, "%d", &start)

			fmt.Println("End Block Height -> ")
			s, _ = reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			var end int64
			fmt.Sscanf(s, "%d", &end)

			for i := start; i <= end; i++ {
				res, err := client.GetBlockHash(i)
				if err != nil {
					log.Print(err)
					break
				}

				blk, err := client.GetBlock(res)
				if err != nil {
					log.Print(err)
				} else {
					log.Printf("\nBlock Height and Hash:%d %s\n", i, res.String())
					if detail < 1 {
						log.Printf("Header.Version:%d\n", blk.Header.Version)
						log.Printf("Header.Timestamp:%d\n", blk.Header.Timestamp)
						log.Printf("Header.MerkleRoot:%d\n", blk.Header.MerkleRoot.String())
					}
					log.Printf("Header.Nonce:%d\n", blk.Header.Nonce)
					log.Printf("Header.PrevBlock:%d\n", blk.Header.PrevBlock.String())
					if detail < 2 {
						for _, t := range blk.Transactions {
							log.Printf("-------------------------- Transaction ------------------------------\n")
							log.Printf("TxHash: %s", t.TxHash().String())
							log.Printf("Version: %d\n", t.Version)
							log.Printf("LockTime: %d\n", t.LockTime)
							log.Printf("TxIn: \n")
							for _, in := range t.TxIn {
								log.Printf("PreviousOutPoint: %s : %d\n", in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
								log.Printf("Sequence: %d\n", in.Sequence)
							}
							log.Printf("TxDef: \n")
							for _, d := range t.TxDef {
								log.Printf("DefType: %s Hash: %s\n", d.DefType(), d.Hash().String())
							}
							log.Printf("TxOut: \n")
							for _, out := range t.TxOut {
								log.Printf("TokenType: \n", out.TokenType)
								log.Printf("Value: \n", out.Value)
								log.Printf("Rights: \n", out.Rights)
							}
						}
					}
				}
			}

			break
		case "getmininginfo":	//
			res, err := client.GetMiningInfo()
			if err != nil {
				log.Print(err)
			}
			log.Printf("getmininginfo: %d", res)
			break
		case "getdifficulty":	//
			res, err := client.GetDifficulty()
			if err != nil {
				log.Print(err)
			}
			log.Printf("GetDifficulty: %d", res)
			break
		case "getnetworkhashps":	//  ( blocks height )
			res, err := client.GetNetworkHashPS()
			if err != nil {
				log.Print(err)
			}
			log.Printf("GetNetworkHashPS: %d", res)
			break
		case "gethashespersec":	//
			res, err := client.GetHashesPerSec()
			if err != nil {
				log.Print(err)
			}
			log.Printf("GetHashesPerSec: %d", res)
			break
		case "getgenerate":	//
			mining, err := client.GetGenerate()
			if err != nil {
				log.Print(err)
			}
			log.Printf("GetGenerate: %d", mining)
			break
		case "setgenerate":	//  generate ( genproclimit )
			mining = !mining
			err := client.SetGenerate(mining, 2)
			if err != nil {
				log.Print(err)
			}
			log.Printf("SetGenerate to %s", mining)
			break
		case "getwork":	//  ( "data" )
			res, err := client.GetWork()
			if err != nil {
				log.Print(err)
			}
			log.Printf("getwork: %d", res)
			break
		case "getblocktemplate":	//  ( "jsonrequestobject" )
			log.Printf("getblocktemplate: ")
			break
		case "submitblock":	//  "hexdata" ( "jsonparametersobject" )
			fmt.Println("hello, Yourself")
			break
		case "searchrawtransactions":	//  "hexdata" ( "jsonparametersobject" )
			// ms6HYbv1YGKbxgQEEHa7TZBQvKRTcSQmtZ
			// 2MuVt8ZtHw1mTawgbru2SA5mH1Ubriyv97Q
			// 2N1CFREjXRetQXPcwk3zN5se7mZuUAJRVqb
			address,_ := btcutil.DecodeAddress("2MuVt8ZtHw1mTawgbru2SA5mH1Ubriyv97Q", &chaincfg.TestNet3Params)
//			address,_ := btcutil.DecodeAddress("1FuzgSAked4aechNDzmn3kc4nxLsFfLadq", &chaincfg.RegressionNetParams)
//			address,_ := btcutil.DecodeAddress("1FuzgSAked4aechNDzmn3kc4nxLsFfLadq", &chaincfg.MainNetParams)
			res, err := client.SearchRawTransactions(address, 0, 10, false, make([]string, 0))

			if err != nil {
				log.Print(err)
			}
			log.Printf("searchrawtransactions: %d", res)
			break
		case "generate":	//  "hexdata" ( "jsonparametersobject" )
			res, err := client.Generate(1)

			if err != nil {
				log.Print(err)
			}
			log.Printf("generate: %s", res)
			break
		case "getworksubmit":	//  "hexdata" ( "jsonparametersobject" )
			res, err := client.GetWorkSubmit("")

			if err != nil {
				log.Print(err)
			}
			log.Printf("getworksubmit: %s", res)
			break

		// 钱包、账户、地址、转帐、发消息
		case "listsinceblock":	//  ( "blockhash" target-confirmations )
			fmt.Println("Block hash -> ")
			// 00002c7307e3905a38ca29a862cc2e018202de40619c88765124d37a771cae49
			s, _ := reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			h,_ := chainhash.NewHashFromStr(s)

			b, err := client.ListSinceBlock(h)
			if err != nil {
				log.Print(err)
			}
			log.Printf("listsinceblock: %s", b)
			break
		case "listtransactions":	//  ( "account" count from )
			b, err := client.ListTransactions("*")
			if err != nil {
				log.Print(err)
			}
			log.Printf("listtransactions: %V", b)
			break
		case "gettransaction":	// "txid"
			fmt.Println("Input tx hash-> ")
			// 30917d0cf74d82f1b8ad1f5686a2b4c478d34bfadafe064fe75883baa63a0a07
			s, _ := reader.ReadString('\n')
			s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)

			h,_ := chainhash.NewHashFromStr(s)

			b, err := client.GetTransaction(h)
			if err != nil {
				log.Print(err)
			}
			log.Printf("gettransaction: %s", b)
			break
/*
		case "getwalletinfo":	//
			res, err := client.GetWalletInfo()
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Peer: %d", res)
			break
*/
		case "walletpassphrase":	//  "passphrase" timeout
			err := client.WalletPassphrase("123456", 20)
			if err != nil {
				log.Print(err)
			}
			log.Printf("walletpassphrase: %d", err)
			break
		case "walletlock":	//
			res, err := client.GetPeerInfo()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Peer: %d", res)
			break
		case "walletpassphrasechange":	// "oldpassphrase" "newpassphrase"
			fmt.Println("hello, Yourself")
			break
/*
		case "backupwallet":	// "destination"
			res, err := client.BackUpWallet()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Peer: %d", res)
			break
		case "importwallet":	// "filename"
			res, err := client.Importwallet()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Peer: %d", res)
			break
		case "dumpwallet":	// "filename"
			res, err := client.DumpWallet()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Peer: %d", res)
			break
*/
		case "listaccounts":	// ( minconf )
			res, err := client.ListAccounts()
			if err != nil {
				log.Print(err)
			}
			log.Printf("listaccounts: %s", res)
			break
		case "getaddressesbyaccount":	// "account"
			res, err := client.GetAddressesByAccount("default")
			if err != nil {
				log.Print(err)
			}
			log.Printf("getaddressesbyaccount: %s", res)
			break
/*
		case "getaccountaddress":	// "account"
			fmt.Println("account-> ")
			s := ""
			for len(s) == 0 {
				s, _ = reader.ReadString('\n')
				s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			}

			res, err := client.GetAccountAddress(s)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("getaccountaddress: %s", res)
			break
*/
		case "getaccount":	// "bitcoinaddress"
			// ms6HYbv1YGKbxgQEEHa7TZBQvKRTcSQmtZ
			// 2MuVt8ZtHw1mTawgbru2SA5mH1Ubriyv97Q
			// 2N1CFREjXRetQXPcwk3zN5se7mZuUAJRVqb

			fmt.Println("Address-> ")
			s := ""
			for len(s) == 0 {
				s, _ = reader.ReadString('\n')
				s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			}

			// 3cdb999564d87eafaa2952c814418a891e3c9ae3dab6e1a0e9c724ba58a19e27
			//			a,_ := btcutil.DecodeAddress(s, &chaincfg.MainNetParams)
			a,_ := btcutil.DecodeAddress(s, &chaincfg.TestNet3Params)
			res, err := client.GetAccount(a)
			if err != nil {
				log.Print(err)
			}
			log.Printf("getaccount: %s", res)
			break
		case "validateaddress":	// "bitcoinaddress"
			fmt.Println("hello, Yourself")
			break
		case "dumpprivkey":	// "bitcoinaddress"
			// mjt7WtJzcrG8rcNdn8WC1UveLRpqP69cmp
			// mrKn4LYmDvRzB9Tkt6geUrBevokzBt9rnr

			a,_ := btcutil.DecodeAddress("mjt7WtJzcrG8rcNdn8WC1UveLRpqP69cmp", &chaincfg.TestNet3Params)

			res, err := client.DumpPrivKey(a)
			if err != nil {
				log.Print(err)
			}

			log.Printf("dumpprivkey for mjt7WtJzcrG8rcNdn8WC1UveLRpqP69cmp: %s", res)

			a,_ = btcutil.DecodeAddress("mrKn4LYmDvRzB9Tkt6geUrBevokzBt9rnr", &chaincfg.TestNet3Params)

			res, err = client.DumpPrivKey(a)
			if err != nil {
				log.Print(err)
			}

			log.Printf("dumpprivkey for mrKn4LYmDvRzB9Tkt6geUrBevokzBt9rnr: %s", res)
			break
/*
		case "setaccount":	// "bitcoinaddress" "account"
			// ms6HYbv1YGKbxgQEEHa7TZBQvKRTcSQmtZ
			// 2MuVt8ZtHw1mTawgbru2SA5mH1Ubriyv97Q
			// 2N1CFREjXRetQXPcwk3zN5se7mZuUAJRVqb
			// mrKn4LYmDvRzB9Tkt6geUrBevokzBt9rnr

			fmt.Println("Address-> ")
			s := ""
			for len(s) == 0 {
				s, _ = reader.ReadString('\n')
				s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			}

			// 3cdb999564d87eafaa2952c814418a891e3c9ae3dab6e1a0e9c724ba58a19e27
			//			a,_ := btcutil.DecodeAddress(s, &chaincfg.MainNetParams)
			a,_ := btcutil.DecodeAddress(s, &chaincfg.TestNet3Params)

			res := client.SetAccount(a, "default")

			log.Printf("setaccount: %s", res)
			break
*/
		case "getnewaddress":	// ( "account" )
			res, err := client.GetNewAddress("default")
			if err != nil {
				log.Print(err)
			}
			log.Printf("GetNewAddress: %s", res)
			break
		case "keypoolrefill":	// ( newsize )
			fmt.Println("hello, Yourself")
			break
		case "importprivkey":	// "bitcoinprivkey" ( "label" rescan )
			pk,err := btcutil.DecodeWIF("cQdPVU5KSzLkD1rhvLJztvpWBu9TrVAE2iPxfgEQrzWuS5xLNRX6")
			err = client.ImportPrivKey(pk)
			if err != nil {
				log.Print(err)
			} else {
				log.Printf("importprivkey success: %s", pk)
			}
			break
		case "createmultisig":	// nrequired ["key",...]
			fmt.Println("hello, Yourself")
			break
		case "addmultisigaddress":	// nrequired ["key",...] ( "account" )
			fmt.Println("hello, Yourself")
			break
		case "getbalance":	// ( "account" minconf )
			res, err := client.GetBalance("default")
			if err != nil {
				log.Print(err)
			}
			log.Printf("GetBalance: %V", res)
			break
		case "getasset":	// ( "account" minconf )
			res, err := client.GetAsset("*")
			if err != nil {
				log.Print(err)
			}
			log.Printf("GetAsset: %V", res)
			break
		case "getdb":	// ( "account" minconf )
			fmt.Println("Bucket -> ")
			s := ""
			for len(s) == 0 {
				s, _ = reader.ReadString('\n')
				s = strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "", -1)
			}

			res, err := client.GetDB(s)
			if err != nil {
				log.Print(err)
			}
			log.Printf("GetDB: %V", res)
			break
		case "getunconfirmedbalance":	//
			res, err := client.GetUnconfirmedBalance("default")
			if err != nil {
				log.Print(err)
			}
			log.Printf("Peer: %d", res)
			break
		case "getreceivedbyaccount":	// "account" ( minconf )
			fmt.Println("hello, Yourself")
			break
		case "listreceivedbyaccount":	// ( minconf includeempty )
			fmt.Println("hello, Yourself")
			break
		case "getreceivedbyaddress":	// "bitcoinaddress" ( minconf )
			fmt.Println("hello, Yourself")
			break
		case "listreceivedbyaddress":	// ( minconf includeempty )
			fmt.Println("hello, Yourself")
			break
		case "move":	// "fromaccount" "toaccount" amount ( minconf "comment" )
			fmt.Println("hello, Yourself")
			break
		case "listunspent":	// ( minconf maxconf  ["address",...] )
			b, err := client.ListUnspent()
			if err != nil {
				log.Print(err)
			}
			log.Printf("ListUnspent: %V", b)
			break
		case "listlockunspent":	//
			res, err := client.GetPeerInfo()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Peer: %d", res)
			break
		case "lockunspent":	// unlock [{"txid":"txid","vout":n},...]
			fmt.Println("hello, Yourself")
			break
		case "getrawchangeaddress":	//
			res, err := client.GetPeerInfo()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Peer: %d", res)
			break
		case "listaddressgroupings":	//
			res, err := client.GetPeerInfo()
			if err != nil {
				log.Print(err)
			}
			log.Printf("Peer: %d", res)
			break
		case "settxfee":	// amount
			fmt.Println("hello, Yourself")
			break
		case "sendtoaddress":	// "bitcoinaddress" amount ( "comment" "comment-to" )
			fmt.Println("hello, Yourself")
			break
		case "sendfrom":	// "fromaccount" "tobitcoinaddress" amount ( minconf "comment" "comment-to" )
			fmt.Println("hello, Yourself")
			break
		case "sendmany":	// "fromaccount" {"address":amount,...} ( minconf "comment" )
			fmt.Println("hello, Yourself")
			break
		case "signmessage":	// "bitcoinaddress" "message"
			fmt.Println("hello, Yourself")
			break
		case "verifymessage":	// "bitcoinaddress" "signature" "message"
			fmt.Println("hello, Yourself")
			break
		}
	}
}
