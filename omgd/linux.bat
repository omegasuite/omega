set GOARCH=amd64
set GOOS=linux
set GOPATH=f:\Gopath

set CGO_ENABLED=0
@REM -race

go build -ldflags "-X 'main.CompileTime=`%date%`'"

@REM go build -i -v -ldflags "-X 'main.CompileTime=`%date%`'"

copy omgd \btctest

goto ALL_DONE

@REM -ldflags "-w -s -X main.Version=${VERSION}"
@REM -w 去掉DWARF调试信息，得到的程序就不能用gdb调试了。
@REM -s 去掉符号表,panic时候的stack trace就没有任何文件名/行号信息了，这个等价于普通C/C++程序被strip的效果，

:ALL_DONE
