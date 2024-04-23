module github.com/omegasuite/omgd

go 1.22.1

replace (
	golang.org/x/crypto/ripemd160 => f:\Gopath\src\golang.org\x\crypto\ripemd160

	github.com/omegasuite/btcd/addrmgr => f:\Gopath\src\github.com\omegasuite\btcd\addrmgr
	github.com/omegasuite/btcd/blockchain => f:\Gopath\src\github.com\omegasuite\btcd\blockchain
	github.com/omegasuite/btcd/blockchain/chainutil => f:\Gopath\src\github.com\omegasuite\btcd\blockchain\chainutil
	github.com/omegasuite/btcd/blockchain/indexers => f:\Gopath\src\github.com\omegasuite\btcd\blockchain\indexers
	github.com/omegasuite/btcd/btcec => f:\Gopath\src\github.com\omegasuite\btcd\btcec
	github.com/omegasuite/btcd/btcjson => f:\Gopath\src\github.com\omegasuite\btcd\btcjson
	github.com/omegasuite/btcd/chaincfg => f:\Gopath\src\github.com\omegasuite\btcd\chaincfg
	github.com/omegasuite/btcd/chaincfg/chainhash => f:\Gopath\src\github.com\omegasuite\btcd\chaincfg\chainhash
	github.com/omegasuite/btcd/connmgr => f:\Gopath\src\github.com\omegasuite\btcd\connmgr
	github.com/omegasuite/btcd/database => f:\Gopath\src\github.com\omegasuite\btcd\database
	github.com/omegasuite/btcd/database/ffldb => f:\Gopath\src\github.com\omegasuite\btcd\database\ffldb
	github.com/omegasuite/btcd/limits => f:\Gopath\src\github.com\omegasuite\btcd\limits
	github.com/omegasuite/btcd/mempool => f:\Gopath\src\github.com\omegasuite\btcd\mempool
	github.com/omegasuite/btcd/mining => f:\Gopath\src\github.com\omegasuite\btcd\mining
	github.com/omegasuite/btcd/mining/cpuminer => f:\Gopath\src\github.com\omegasuite\btcd\mining\cpuminer
	github.com/omegasuite/btcd/netsync => f:\Gopath\src\github.com\omegasuite\btcd\netsync
	github.com/omegasuite/btcd/peer => f:\Gopath\src\github.com\omegasuite\btcd\peer
	github.com/omegasuite/btcd/wire => f:\Gopath\src\github.com\omegasuite\btcd\wire
	github.com/omegasuite/btcd/wire/common => f:\Gopath\src\github.com\omegasuite\btcd\wire\common
	github.com/omegasuite/btclog => f:\Gopath\src\github.com\omegasuite\btclog
	github.com/omegasuite/btcutil => f:\Gopath\src\github.com\omegasuite\btcutil
	github.com/omegasuite/btcutil/bloom => f:\Gopath\src\github.com\omegasuite\btcutil\bloom
	github.com/omegasuite/go-socks/socks => f:\Gopath\src\github.com\omegasuite\go-socks\socks
	github.com/omegasuite/omega/consensus => f:\Gopath\src\github.com\omegasuite\omega\consensus
	github.com/omegasuite/omega => f:\Gopath\src\github.com\omegasuite\omega
	github.com/omegasuite/omega/minerchain => f:\Gopath\src\github.com\omegasuite\omega\minerchain
	github.com/omegasuite/omega/ovm => f:\Gopath\src\github.com\omegasuite\omega\ovm
	github.com/omegasuite/omega/token => f:\Gopath\src\github.com\omegasuite\omega\token
	github.com/omegasuite/omega/viewpoint => f:\Gopath\src\github.com\omegasuite\omega\viewpoint
	github.com/omegasuite/websocket => f:\Gopath\src\github.com\omegasuite\websocket
	github.com/omegasuite/winsvc/eventlog => f:\Gopath\src\github.com\omegasuite\winsvc\eventlog
	github.com/omegasuite/winsvc/mgr => f:\Gopath\src\github.com\omegasuite\winsvc\mgr
	github.com/omegasuite/winsvc/svc => f:\Gopath\src\github.com\omegasuite\winsvc\svc

	github.com/aead/siphash => f:\Gopath\src\github.com\aead\siphash
	github.com/kkdai/bstream => f:\Gopath\src\github.com\kkdai\bstream
	github.com/goinggo/mapstructure => f:\Gopath\src\github.com\goinggo\mapstructure
	github.com/omegasuite/goleveldb/leveldb => f:\Gopath\src\github.com\omegasuite\goleveldb\leveldb
	github.com/omegasuite/goleveldb/leveldb/comparer => f:\Gopath\src\github.com\omegasuite\goleveldb\leveldb\comparer
	github.com/omegasuite/goleveldb/leveldb/errors => f:\Gopath\src\github.com\omegasuite\goleveldb\leveldb\errors
	github.com/omegasuite/goleveldb/leveldb/filter => f:\Gopath\src\github.com\omegasuite\goleveldb\leveldb\filter
	github.com/omegasuite/goleveldb/leveldb/iterator => f:\Gopath\src\github.com\omegasuite\goleveldb\leveldb\iterator
	github.com/omegasuite/goleveldb/leveldb/opt => f:\Gopath\src\github.com\omegasuite\goleveldb\leveldb\opt
	github.com/omegasuite/goleveldb/leveldb/util => f:\Gopath\src\github.com\omegasuite\goleveldb\leveldb\util
	github.com/omegasuite/winsvc/registry => f:\Gopath\src\github.com\omegasuite\winsvc\registry
	github.com/omegasuite/winsvc/winapi => f:\Gopath\src\github.com\omegasuite\winsvc\winapi
	github.com/omegasuite/snappy-go => f:\Gopath\src\github.com/omegasuite/snappy-go
	github.com/davecgh/go-spew => f:\Gopath\src\github.com\davecgh\go-spew
	github.com/jessevdk/go-flags => f:\Gopath\src\github.com\jessevdk\go-flags
	github.com/jrick/logrotate => f:\Gopath\src\github.com\jrick\logrotate
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jessevdk/go-flags v1.5.0 // indirect
	github.com/jrick/logrotate v1.0.0 // indirect
	golang.org/x/sys v0.0.0-20210320140829-1e4c9ba3b0c4 // indirect
	golang.org/x/crypto/ripemd160 v0.0.0 // indirect

	github.com/omegasuite/btcd/addrmgr v1.0.0 // indirect
	github.com/omegasuite/btcd/blockchain v1.0.0 // indirect
	github.com/omegasuite/btcd/blockchain/chainutil v1.0.0 // indirect
	github.com/omegasuite/btcd/blockchain/indexers v1.0.0 // indirect
	github.com/omegasuite/btcd/btcec v1.0.0 // indirect
	github.com/omegasuite/btcd/btcjson v1.0.0 // indirect
	github.com/omegasuite/btcd/chaincfg v1.0.0 // indirect
	github.com/omegasuite/btcd/chaincfg/chainhash v1.0.0 // indirect
	github.com/omegasuite/btcd/connmgr v1.0.0 // indirect
	github.com/omegasuite/btcd/database v1.0.0 // indirect
	github.com/omegasuite/btcd/database/ffldb v1.0.0 // indirect
	github.com/omegasuite/btcd/limits v1.0.0 // indirect
	github.com/omegasuite/btcd/mempool v1.0.0 // indirect
	github.com/omegasuite/btcd/mining v1.0.0 // indirect
	github.com/omegasuite/btcd/mining/cpuminer v1.0.0 // indirect
	github.com/omegasuite/btcd/netsync v1.0.0 // indirect
	github.com/omegasuite/btcd/peer v1.0.0 // indirect
	github.com/omegasuite/btcd/wire v1.0.0 // indirect
	github.com/omegasuite/btcd/wire/common v1.0.0 // indirect
	github.com/omegasuite/btclog v1.0.0 // indirect
	github.com/omegasuite/btcutil v1.0.0 // indirect
	github.com/omegasuite/btcutil/bloom v1.0.0 // indirect
	github.com/omegasuite/go-socks/socks v1.0.0 // indirect
	github.com/omegasuite/omega v1.0.0 // indirect
	github.com/omegasuite/omega/consensus v1.0.0 // indirect
	github.com/omegasuite/omega/minerchain v1.0.0 // indirect
	github.com/omegasuite/omega/ovm v1.0.0 // indirect
	github.com/omegasuite/omega/token v1.0.0 // indirect
	github.com/omegasuite/omega/viewpoint v1.0.0 // indirect
	github.com/omegasuite/websocket v1.0.0 // indirect
	github.com/omegasuite/winsvc/eventlog v1.0.0 // indirect
	github.com/omegasuite/winsvc/mgr v1.0.0 // indirect
	github.com/omegasuite/winsvc/svc v1.0.0 // indirect

	github.com/aead/siphash v1.0.0 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/goinggo/mapstructure v1.0.0 // indirect
	github.com/omegasuite/goleveldb/leveldb v1.0.0 // indirect
	github.com/omegasuite/goleveldb/leveldb/comparer v1.0.0 // indirect
	github.com/omegasuite/goleveldb/leveldb/errors v1.0.0 // indirect
	github.com/omegasuite/goleveldb/leveldb/filter v1.0.0 // indirect
	github.com/omegasuite/goleveldb/leveldb/iterator v1.0.0 // indirect
	github.com/omegasuite/goleveldb/leveldb/opt v1.0.0 // indirect
	github.com/omegasuite/goleveldb/leveldb/util v1.0.0 // indirect
	github.com/omegasuite/winsvc/registry v1.0.0 // indirect
	github.com/omegasuite/winsvc/winapi v1.0.0 // indirect
	github.com/omegasuite/snappy-go v1.0.0 // indirect
)
