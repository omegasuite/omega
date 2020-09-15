; define convention:
; use up case names with leading _ for storage,
; lower case names with leading _ for entry point,
; leading up case names for global vars,
; lower case names for local vars
; all up case names for consts

; contract construction

define RECEIVING xceddcbdf1bc15a0feb4473df6578ec61445a48cb	; public contract for receiving generic numeric money
define OMCHANDLER xceddcbdf1bc15a0feb4473df6578ec61445a48cb	; contract for optional handling 
define ORACLEKEY kx02068a7d7950e3fe76fd02c89d95d5a460240189d1c5887ddf6ccc4d7cde245c89		; regular
define ORACLEKEY2 kx02068a7d7950e3fe76fd02c89d95d5a460240189d1c5887ddf6ccc4d7cde245c89		; from investor
define OWNERKEY kx02d98961b3c23a8642e8a4e5779f48ffb04ffe2095766f591d97072097efd75ea1

define NETID x6f		; 0 for main net, x6f for test net

; use abi for simple storage, 32 bit
; use ABI for array storage, 64 bit with lower 32 bit for index
define _ORACLE abi("oracle")
define _ORACLE2 abi("oracle2")
define _OWNER abi("owner")
define _OMCHANDLER abi("omchandler")
define _SEQUENCE abi("sequence")
define _DESTROYED abi("destroyed")
define _OWNERISSUED abi("ownerissued")
define _ORACLEISSUED abi("oracleissued")

; these vars will also be used by RECEIVING. since we used old abi before and have deployed RECEIVING, so hard code them ...
define _UTXOTID x06030000
define _UTXOTSEQ x00060000
define _LASTID x02000205
define _LASTSEQ x00070000
define _BALANCE x01050705

STORE _ORACLE,ORACLEKEY,	; pub key (not address) of oracle
STORE _ORACLE2,ORACLEKEY2,	; pub key (not address) of oracle 2 (for investor)
STORE _OWNER,OWNERKEY,		; pub key (not address) of owner
STORE _OMCHANDLER,rOMCHANDLER,
STORE _SEQUENCE,D0,
STORE _UTXOTID,Hx0,
STORE _UTXOTSEQ,D0,
STORE _LASTID,Hx0,
STORE _LASTSEQ,D0,
STORE _BALANCE,Q0,
STORE _DESTROYED,Q0,		; coins destroyed
STORE _OWNERISSUED,Q0,		; coins issued by owner
STORE _ORACLEISSUED,Q0,		; coins issued by oracle

define BOE x454f4200

define function gi8
define tmp gii0"16
define tmp4 gii0"20

define RESULT gi4
define RESULTLEN gi0

STORE abi("sequence"),D0,
MALLOC gi0,8,		; len of store code
MINT gi0,BOE,0,	; BOE
EVAL32 i0,4,		; length of result
EVAL32 i4,BODY,		; result = the first instruction of contract body code.
STOP

; contract body
define BODY .
define pubkey gii0"260
define pubkeyd gii0"259
define contract gii0"8

MALLOC gii0"8,1032,	; storage to use. enough for all cases.

EVAL32 tmp,abi("suspended()bool"),function,=
IF tmp,.suspended,
EVAL32 tmp,abi("getsequence()uint32"),function,=
IF tmp,.getsequence,
EVAL32 tmp,abi("tokentype()uint64"),function,=
IF tmp,.tokentype,
EVAL32 tmp,abi("minted()uint64"),function,=
IF tmp,.minted,
EVAL32 tmp,abi("outstanding()uint64"),function,=
IF tmp,.outstanding,
EVAL32 tmp,abi("issuedby(bool)uint64"),function,=
IF tmp,.issuedby,

; above code are contract calls (except for suicide)
; codes below are transactions. do common work for txs

GETCOIN tokentype,		; must be a BOE token
EVAL64 tmp,tokentype,BOE,=
IF tmp,2
REVERT

LIBLOAD 0,RECEIVING,BOE,

define seq gii0"416
define seqtext gii0"420		; don't change this address w/o considering signature
define adr gii0"396
define func gii0"424
define ftext gii0"400
define issueto gii0"428
define amount gii0"449
define adrtext gii0"400

define hashed gii0"300

COPYIMM pubkey,OWNERKEY,			; issue([21]byte,uint64,[]byte)
EVAL8 pubkeyd,33,

; increase in all cases, if exec fails, it won't be saved anyway
LOAD seq,abi("sequence"),		; build text for hashing
EVAL32 seqtext,seqtext,1,+
STORE abi("sequence"),Dseqtext,		; contract address + seq + abi
META adr,7,"address",
EVAL32 func,function,

EVAL32 tmp,abi("suspend([]byte)"),function,=
IF tmp,.suspend,

EVAL32 tmp,abi("resume([]byte)"),function,=
IF tmp,.resume,
EVAL32 tmp,abi("suicide([]byte)"),function,=
IF tmp,.suicide,
EVAL32 tmp,abi("handler([]byte,[]byte)"),function,=
IF tmp,.handler,

EVAL32 tmp,abi("setoracle([33]byte,[]byte)"),function,=		; setoracle(pubkey, signature)
IF tmp,.setoracle,						; oracle func
EVAL32 tmp,abi("setowner([33]byte,[]byte)"),function,=		; setowner(pubkey, signature)
IF tmp,.setowner,						; oracle func

EVAL32 tmp,abi("oracle([21]byte,uint64,[]byte)"),function,=	; oracle(address, amount, signature)
IF tmp,.oracle,					; oracle func
EVAL32 tmp,abi("issue([21]byte,uint64,[]byte)"),function,=	; issue(address, amount, signature)
IF tmp,.issue,
CALL RECEIVING,abi("generic(bool,int64)byte"),0,0,		; receiveing money
STOP

define setoracle .
CALL 0,.sigcheck3,
STORE abi("oracle"),kgi12,	; pub key (not address) of oracle
CALL RECEIVING,abi("generic(bool,int64)byte"),0,0,
STOP

define setowner .
CALL 0,.sigcheck3,
STORE abi("owner"),kgi12,	; pub key (not address) of owner
CALL RECEIVING,abi("generic(bool,int64)byte"),0,0,
STOP

define sigcheck3 .
ALLOC i0,1024,			; sig verification
COPY i0,ftext,24,		; contract + seq
COPY i24,function,37,		; abi + pubkey
HASH i57,i0,61,
EVAL8 usekeyd,usekey,
SIGCHECK i0,i57,usekeyd,gi45,
IF i0,2,
REVERT
RETURN

; ---------------------- done -------------------------------

define usekey gii0"65
define usekeyd gii0"68

define issuetoken .
META i0,4,"mint",			; issue token
MINT i12,i4,gi33,
SPEND i20,i52,
EVAL64 i20,gi33,			; amount
EVAL32 i28,25,				; len of pkscript
COPY i32,gi12,21,			; pkscript: address
EVAL32 i53,x41,				; pkscript: func
ADDTXOUT tmp,i12,
CALL RECEIVING,abi("generic(bool,int64)byte"),0,0,
EVAL32 gi0,0,
RETURN

define issue .
LOAD usekey,abi("owner"),		; issue([21]byte,uint64,[]byte)
CALL 0,.suspendcheck,
CALL 0,.sigcheck,
CALL 0,.issuetoken,
STOP

define oracle .
LOAD usekey,abi("oracle"),	; oracle([21]byte,uint64,[]byte)
CALL 0,.suspendcheck,
CALL 0,.sigcheck,		; func call: lib = 0, pc offset = 2, param = abi("oraclesequence") note:
				; it would be treated as 64-bit val
CALL 0,.issuetoken,
STOP

define sigcheck .
ALLOC i0,1024,			; sig verification
COPY i0,ftext,24,		; contract + seq
COPY i24,gi8,33,		; abi + address + amount
HASH i57,i0,57,
EVAL8 usekeyd,usekey,
SIGCHECK i0,i57,usekeyd,gi41,
IF i0,2,
REVERT
RETURN

define minted .
define MINTED gi12
META RESULTLEN,4,"mint",			; minted()uint64
EVAL64 RESULT,MINTED,
EVAL32 RESULTLEN,8,
STOP

define outstanding .
define MINTED gi12
META RESULTLEN,4,"mint",			; minted()uint64
LOAD gi20,abi("destroyed"),
EVAL64 RESULT,MINTED,gi24,-
EVAL32 RESULTLEN,8,
STOP

define issuedby .
LOAD gi0,abi("ownerissued"),
IF gi12,2,
LOAD gi0,abi("oracleissued"),
STOP

define tokentype .
META RESULTLEN,4,"mint",			; tokentype()uint64
EVAL32 RESULTLEN,8,
STOP

define getsequence .
LOAD RESULTLEN,abi("sequence"),			; getsequence()uint32
STOP

define suspended .
EVAL8 RESULT,0,
LOAD RESULTLEN,abi("suspended"),		; suspended()bool
EVAL32 RESULTLEN,1,
STOP

define suspend .
CALL 0,.sigcheck2,@function,
CALL RECEIVING,abi("generic(bool,int64)byte"),0,0,
STORE abi("suspended"),B1,		; suspend()bool
EVAL32 gi0,0,
STOP

define resume .
CALL 0,.sigcheck2,@function,
CALL RECEIVING,abi("generic(bool,int64)byte"),0,0,
STORE abi("suspended"),B0,		; resume()bool
EVAL32 gi0,0,
STOP

define sigcheck2 .
EVAL32 func,ii8,
HASH hashed,ftext,28,
SIGCHECK tmp,hashed,pubkeyd,ii8,
IF tmp,2,
REVERT
RETURN

define suspendcheck .
EVAL8 tmp4,0				; clear result in case 'suspended' is undefined
LOAD tmp,abi("suspended"),		; suspendcheck()
IF tmp4,2,
RETURN
REVERT

define tokentype gii0"28
define tokenval gii0"36
define scriptlen gii0"44
define scriptver gii0"48
define scriptstr gii0"49
define scriptfunc gii0"69
define tmp gii0'80

define suicide .
GETCOIN tokentype,		; for suicide, must take no value in
EVAL64 tmp,tokentype,0,=
IF tmp,2,
REVERT
EVAL64 tmp,tokenval,0,=
IF tmp,2,
REVERT

CALL 0,.sigcheck2,@gi12,

LOAD LASTSEQ,abi("lastseq"),
LOAD LASTID,abi("lastid"),
LOAD UTXOTSEQ,abi("utxotseq"),
LOAD UTXOTID,abi("utxotid"),
LOAD BALANCE,abi("balance"),

EVAL64 tmp,BALANCEDATA,0,=		; no balance, go die directly
IF tmp,.kill,

define UTXOTID gii0"108
define UTXOTSEQ gii0"140
define LASTID gii0"144
define LASTSEQ gii0"176

define UTXOTIDDATA gii0"112
define UTXOTSEQDATA gii0"144
define LASTIDDATA gii0"148
define LASTSEQDATA gii0"180

EVAL64 tmp,UTXOTIDDATA,0,=		; spend all
IF tmp,2,
SPEND UTXOTIDDATA,UTXOTSEQDATA,
EVAL64 tmp,LASTIDDATA,0,=
IF tmp,2,
SPEND LASTIDDATA,LASTSEQDATA,

define txfees ii0"190
define outval ii0"198

TXFEE txfees,2,				; pay fees
EVAL64 outval,BALANCEDATA,txfees,-
EVAL64 tmp,outval,0,(
IF tmp,.kill,

COPYIMM pubkey,OWNERKEY,
HASH160 hashed,pubkey,33,
EVAL64 tokenval,outval,
EVAL32 scriptlen,25,
EVAL8 scriptver,NETID,
COPY scriptstr,hashed,20,
EVAL32 scriptfunc,x41,			; pkhpubkey
ADDTXOUT i232,tokentype,

define kill .				; die. delete storage
DEL abi("balance"),
DEL abi("utxotid"),
DEL abi("utxotseq"),
DEL abi("lastid"),
DEL abi("lastseq"),
DEL abi("sequence"),
SELFDESTRUCT





Ox02000209,kx02068a7d7950e3fe76fd02c89d95d5a460240189d1c5887ddf6ccc4d7cde245c89,
Ox00010004,kx02d98961b3c23a8642e8a4e5779f48ffb04ffe2095766f591d97072097efd75ea1,
Ox00000904,D0,
Ox00050402,D0,
Rgi0,8,
jgi0,x454f4200,0,
Ci0,4,
Ci4,9,
z
Rgii0"8,1032,
Cgii0"16,x01000000,gi8,=
Kgii0"16,80,
Cgii0"16,x06060007,gi8,=
Kgii0"16,81,
Cgii0"16,x09030604,gi8,=
Kgii0"16,82,
Cgii0"16,x00060200,gi8,=
Kgii0"16,62,
Cgii0"16,x00050000,gi8,=
Kgii0"16,30,
Cgii0"16,x02000400,gi8,=
Kgii0"16,23,
Cgii0"16,x00060400,gi8,=
Kgii0"16,18,
Cgii0"16,x00080400,gi8,=
Kgii0"16,13,
Cgii0"16,x04090408,gi8,=
Kgii0"16,8,
Cgii0"16,x00000800,gi8,=
Kgii0"16,2,
X
kgi4,4,x6d696e74,
Cgi0,8,
Dgi4,gi12,
z
kgi0,4,x6d696e74,
Cgi0,8,
z
Ngi0,x00050402,
Cgi0,4,
z
Ngi0,x00000904,
Cgi0,4,
z
Ngii0"65,x00010004,
L0,55,
L0,8,x00050402,
L0,19,
z
Ngii0"65,x02000209,
L0,50,
L0,3,x00000904,
L0,14,
z
Si0,1024,
Ni49,i8,
Ci57,i53,1,+
Oi8,Di57,
ki0,7,x61646472657373,
Ti24,gi8,29,
Gi57,i4,53,
Agii0"68,gii0"65,
Ii0,i57,gii0"68,gi37,
Ki0,2,
X
Y
ki0,4,x6d696e74,
ji12,i4,gi33,
ei20,i52,
Cgii0"16,x02000400,gi8,=
Kgii0"16,7,
Ci20,gi33,
Ci24,0,
Ci28,25,
Ti32,gi12,21,
Ci53,x41,
gi12,
Cgi0,0,
Y
Ngii0"65,x00010004,
Ngi49,x00010004,
Cgi57,gi53,1,+
Ogi8,Dgi57,
kgi0,7,x61646472657373,
Tgi24,ggi8,29,
Ggi57,gi4,53,
Agii0"68,gii0"65,
Igi0,gi57,gii0"68,gi37,
Kgi0,2,
X
W
Ngi0,x00020000,
Cgi0,1,
z
Ox00020000,B1,
Cgi0,0,
z
Ox00020000,B0,
Cgi0,0,
z
Ngi0,x00020000,
Kgi0,2
Y
X
