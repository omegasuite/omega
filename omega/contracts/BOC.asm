STORE abi("oracle"),kx02068a7d7950e3fe76fd02c89d95d5a460240189d1c5887ddf6ccc4d7cde245c89,	; pub key (not address) of oracle
STORE abi("owner"),kx02d98961b3c23a8642e8a4e5779f48ffb04ffe2095766f591d97072097efd75ea1,	; pub key (not address) of owner
STORE abi("oraclesequence"),D0,
STORE abi("ownersequence"),D0,
MALLOC gi0,8,		; len of store code
MINT gi0,x434f4200,0,	; BOC
EVAL32 i0,4,		; length of result
EVAL32 i4,9,		; result = the first instruction of regular code.
STOP
MALLOC gii0"8,1032,	; storage to use
EVAL32 gii0"16,abi("oracle([21]byte,uint64,[]byte)"),gi8,=	; func(address, amount, signature)
IF gii0"16,28,					; oracle func
EVAL32 gii0"16,abi("issue([21]byte,uint64,[]byte)"),gi8,=	; func(address, amount, signature)
IF gii0"16,23,
EVAL32 gii0"16,abi("getoracleseq()uint64"),gi8,=
IF gii0"16,18,
EVAL32 gii0"16,abi("getownerseq()uint64"),gi8,=
IF gii0"16,14,
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
LOAD gi0,abi("ownersequence"),
EVAL32 gi0,4,
STOP
LOAD gi0,abi("oraclesequence"),
EVAL32 gi0,4,
STOP
LOAD gii0"65,abi("owner"),
CALL 0,5,abi("ownersequence"),
STOP
LOAD gii0"65,abi("oracle"),
CALL 0,2,abi("oraclesequence"),
STOP
ALLOC i0,1024,
LOAD i49,i8,
EVAL32 i57,i53,1,+
STORE i8,Di57,
META i0,7,"address",
COPY i24,gi8,29,
HASH i57,i4,53,
EVAL8 gii0"68,gii0"65,
SIGCHECK i0,i57,gii0"68,gi37,
IF i0,2,
REVERT
META i0,4,"mint",			; tokentype
MINT i12,i4,gi33,
SPEND i20,i52,
EVAL32 gii0"16,abi("issue([21]byte,uint64,[]byte)"),gi8,=
IF gii0"16,7,
EVAL32 i20,gi33,			; amount
EVAL32 i24,0,				; amount
EVAL32 i28,25,				; len of pkscript
COPY i32,gi12,21,			; pkscript: address
EVAL32 i53,x41,				; pkscript: func
ADDTXOUT i12,
EVAL32 gi0,0,
RETURN
