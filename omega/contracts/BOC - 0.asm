STORE abi("oracle"),kx02681a67e8ee100d2acd8e6b9eb708a0151b423229c9ebae4810dae6022085ca13,	; pub key (not address) of oracle
STORE abi("owner"),kx02681a67e8ee100d2acd8e6b9eb708a0151b423229c9ebae4810dae6022085ca13,	; pub key (not address) of owner
STORE abi("oracleseq"),D0,
STORE abi("ownerseq"),D0,
MALLOC gi0,2052,	; len of store code
MINT gi0,x434f4200,0,	; BOC
CODECOPY gi0,2,54,	; # of instructions
STOP
MALLOC gii0"8,1032,	; storage to use
EVAL32 gii0"16,abi("oracle([21]byte,uint64,[]byte)bool"),gi8,=
IF gii0"16,30,					; oracle func
EVAL32 gii0"16,abi("issue(uint64,[21]byte,[]byte)bool"),gi8,=
IF gii0"16,23,
EVAL32 gii0"16,abi("getoracleseq()uint64"),gi8,=
IF gii0"16,18,
EVAL32 gii0"16,abi("getownerseq()uint64"),gi8,=
IF gii0"16,13,
EVAL32 gii0"16,abi("tokentype()uint64"),gi8,=
IF gii0"16,8,
EVAL32 gii0"16,abi("minted()uint64"),gi8,=
IF gii0"16,2,
REVERT
META gi4,4,"mint",			; minted
EVAL32 gi0,8,
EVAL64 gi4,gi12,
STOP
META gi0,4,"mint",			; tokentype
EVAL32 gi0,8,
STOP
LOAD gi0,4,abi("ownerseq"),
EVAL32 gi0,4,
STOP
LOAD gi0,4,abi("oracleseq"),
EVAL32 gi0,4,
STOP
LOAD gii0"57,4,abi("ownerseq"),
EVAL32 gii0"8,gi0"61,1,+
STORE abi("ownerseq"),Dgii0"8,
LOAD gii0"65,4,abi("owner"),
IF 1,5,
LOAD gii0"57,4,abi("oracleseq"),
EVAL32 gii0"8,gi0"61,1,+
STORE abi("oracleseq"),Dgii0"8,
LOAD gii0"65,4,abi("oracle"),
EVAL8 gii0"68, gii0"65,
META gii0"8,7,"address",
COPY gii0"32,gi8,29,
HASH gii0"12,gii0"12,53,
SIGCHECK gii0"8,gii0"12,gii0"68,gi37,
IF gii0"8,2,
REVERT
META gii0"12,4,"mint",			; tokentype
MINT gii0"24,gii0"16,gi33,
SPEND gii0"32,gii0"64,
EVAL32 gii0"24,gi33,			; amount
EVAL32 gii0"28,0,			; amount
EVAL32 gii0"32,25,			; len of pkscript
COPY gii0"36,gi12,21,			; pkscript: address
EVAL32 gii0"57,x41,			; pkscript: func
ADDTXOUT gii0"16,
EVAL32 gi0,0,
STOP
