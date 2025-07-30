set GOARCH=amd64
set GOOS=linux
set GOPATH=f:\Gopath\src\github.com\omegasuite\gct;f:\Gopath

set CGO_ENABLED=0

go build -a -v -work -o gct -ldflags "-X 'main.CompileTime=`%date%`'"

copy gct \gct\gct
