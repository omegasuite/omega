package main

import (
	"encoding/binary"
	"fmt"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/omega/ovm"
	"github.com/omegasuite/omega/token"
	"os"
	//	"path/filepath"
	//	"sort"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	flags "github.com/jessevdk/go-flags"
)

// config defines the configuration options for btcd.
//
// See loadConfig for details on the configuration load process.
type config struct {
	Code           string        `long:"code" description:"Path to code file"`
	Data           string        `short:"d" long:"data" description:"test data"`
}

var (
	cfg *config
)

func init() {
}

func main() {
	tcfg, err := loadConfig()
	if err != nil {
		os.Exit(1)
	}
	cfg = tcfg

	if len(cfg.Code) == 0 {
		os.Exit(2)
	}

	fp, err := os.Open(cfg.Code)
	if err != nil {
		fmt.Printf("%s", err.Error())
	}
	s := ""
	var b [4096]byte

	for err == nil {
		var n int
		if n, err = fp.Read(b[:]); n > 0 {
			s += string(b[:n])
		}
	}

	var caddr [20]byte
	copy(caddr[:], cfg.Code)

	txo :=  wire.TxOut{ PkScript: []byte {0x2, 0x78, 0x67, 0x87, 0x34 } }
	txo.Token = token.Token{
		TokenType: 0,
		Value: &token.NumToken{ Val: 0 },
		Rights: nil,
	}

	contract := ovm.NewContract(caddr, &txo.Token)
	contract.SetCallCode(caddr[:], chainhash.Hash{}, []byte(s))

	if !ovm.ByteCodeValidator(contract.Code) {
		fmt.Printf("byte code failed to parse\n")
		os.Exit(3)
	} else {
		fmt.Printf("byte code parsed successfully\n")
	}

	contract.Args = make([]byte, 4)

	binary.LittleEndian.PutUint32(contract.Args[:], uint32(0))

	cfg := ovm.Config{}
	vm := ovm.NewOVM(ovm.Context{
		GetUtxo: func(hash chainhash.Hash, u uint64) *wire.TxOut {
			return &txo
		},
		AddTxOutput: func(out wire.TxOut) bool {
			return true
		},
		AddRight: func(def *token.RightDef) bool {
			return true
		},
		GetCurrentOutput: func() *wire.TxOut {
			return wire.OutPoint{}, &txo
		},
		GetTx: func() *wire.MsgTx {
			return &wire.MsgTx {
				Version: 1,
				TxDef: []token.Definition{},
				TxIn: []*wire.TxIn{
					&wire.TxIn{
						PreviousOutPoint: wire.OutPoint{chainhash.Hash{5,7,89,65,24,0,5}, 0xFFFFFFFF},
						Sequence: 0xFFFFFFFF,
						SignatureIndex: 0,
					},
				},
				TxOut: []*wire.TxOut{
					&txo,
				},
				SignatureScripts: [][]byte{},
				LockTime: 0xFFFFFFFF,
			}
		},
	}, &chaincfg.Params{}, cfg, nil)
	vm.StateDB[contract.Address()] = ovm.NewStateDB(vm.DB, contract.Address())

	in := ovm.NewInterpreter(vm, cfg)
	ret, err := in.Run(contract, nil)	// ret)

	if err != nil {
		fmt.Printf("byte code failed to execute\n%s\n%s", err.Error(), ret)
		os.Exit(3)
	} else {
		fmt.Printf("byte code executed successfully\n")
	}
}

// loadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
// 	1) Start with a default config with sane settings
// 	2) Pre-parse the command line to check for an alternative config file
// 	3) Load configuration file overwriting defaults with any specified options
// 	4) Parse CLI options and overwrite/add any specified options
//
// The above results in btcd functioning properly without any config settings
// while still allowing the user to override settings with config files and
// command line options.  Command line options always take precedence.
func loadConfig() (*config, error) {
	// Default config.
	cfg := config{
		Code:           "",
		Data:        "",
	}

	parser := flags.NewParser(&cfg, flags.Default)
	parser.Parse()

	return &cfg, nil
}
