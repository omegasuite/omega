set GOARCH=amd64
set GOOS=linux
set GOPATH=f:\Gopath;f:\Gopath\src\github.com\omegasuite\nexus

set CGO_ENABLED=0

go build -ldflags "-X 'main.CompileTime=`%date%`'"

copy omgd \nexus\nexus
