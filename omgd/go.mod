module github.com/omegasuite/omgd

replace (
	btclog => f:/Gopath/src/github.com/omegasuite/btclog
	btcutil => f:/Gopath/src/github.com/omegasuite/btcutil
	crypto => f:/Gopath/src/golang.org/x/crypto
	go-flags => f:/Gopath/src/github.com/jessevdk/go-flags
	go-socks => f:/Gopath/src/github.com/omegasuite/go-socks
	goleveldb => f:/Gopath/src/github.com/omegasuite/goleveldb
	logrotate => f:/Gopath/src/github.com/jrick/logrotate
	lru => f:/Gopath/src/github.com/decred/dcrd/lru

	spew => f:/Gopath/src/github.com/davecgh/go-spew/spew
	websocket => f:/Gopath/src/github.com/omegasuite/websocket
	winsvc => f:/Gopath/src/github.com/omegasuite/winsvc
)

go 1.14
