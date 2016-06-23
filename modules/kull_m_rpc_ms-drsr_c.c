#include "kull_m_rpc_ms-drsr.h"
#include <string.h>

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable: 4211)  /* redefine extern to static */
#pragma warning(disable: 4232)  /* dllimport identity*/
#pragma warning(disable: 4024)  /* array to pointer mapping*/

#ifdef _M_X64
typedef struct _ms2Ddrsr_MIDL_TYPE_FORMAT_STRING
{
	short          Pad;
	unsigned char  Format[2071];
} ms2Ddrsr_MIDL_TYPE_FORMAT_STRING;

typedef struct _ms2Ddrsr_MIDL_PROC_FORMAT_STRING
{
	short          Pad;
	unsigned char  Format[621];
} ms2Ddrsr_MIDL_PROC_FORMAT_STRING;

extern const ms2Ddrsr_MIDL_TYPE_FORMAT_STRING ms2Ddrsr__MIDL_TypeFormatString;
extern const ms2Ddrsr_MIDL_PROC_FORMAT_STRING ms2Ddrsr__MIDL_ProcFormatString;
static const RPC_CLIENT_INTERFACE drsuapi___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0xe3514235, 0x4b06, 0x11d1, {0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}}, {4,0}}, {{0x8A885D04, 0x1CEB, 0x11C9, {0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
static RPC_BINDING_HANDLE drsuapi__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC drsuapi_StubDesc =  {(void *)& drsuapi___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &drsuapi__MIDL_AutoBindHandle, 0, 0, 0, 0, ms2Ddrsr__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};

ULONG IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs)
{
    return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[0], rpc_handle, puuidClientDsa, pextClient, ppextServer, phDrs).Simple;
}

ULONG IDL_DRSUnbind(DRS_HANDLE *phDrs)
{
	return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[60], phDrs).Simple;
}

ULONG IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut)
{
    return (ULONG) NdrClientCall2((PMIDL_STUB_DESC)&drsuapi_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[104], hDrs, dwInVersion, pmsgIn, pdwOutVersion, pmsgOut).Simple;
}

ULONG IDL_DRSCrackNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut)
{
	return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[172], hDrs, dwInVersion, pmsgIn, pdwOutVersion, pmsgOut).Simple;
}

ULONG IDL_DRSDomainControllerInfo(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut)
{
	return (ULONG) NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[240], hDrs, dwInVersion, pmsgIn, pdwOutVersion, pmsgOut).Simple;
}

#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif

static const ms2Ddrsr_MIDL_PROC_FORMAT_STRING ms2Ddrsr__MIDL_ProcFormatString = {
        0,
        {
	/* Procedure IDL_DRSBind - 0 */
			0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 14 */	NdrFcShort( 0x44 ),	/* 68 */
/* 16 */	NdrFcShort( 0x40 ),	/* 64 */
/* 18 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x5,		/* 5 */
/* 20 */	0xa,		/* 10 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 22 */	NdrFcShort( 0x1 ),	/* 1 */
/* 24 */	NdrFcShort( 0x1 ),	/* 1 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
/* 28 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter rpc_handle */
/* 30 */	NdrFcShort( 0xa ),	/* Flags:  must free, in, */
/* 32 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 34 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */
	/* Parameter puuidClientDsa */
/* 36 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 38 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 40 */	NdrFcShort( 0x18 ),	/* Type Offset=24 */
	/* Parameter pextClient */
/* 42 */	NdrFcShort( 0x2013 ),	/* Flags:  must size, must free, out, srv alloc size=8 */
/* 44 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 46 */	NdrFcShort( 0x40 ),	/* Type Offset=64 */
	/* Parameter ppextServer */
/* 48 */	NdrFcShort( 0x110 ),	/* Flags:  out, simple ref, */
/* 50 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 52 */	NdrFcShort( 0x48 ),	/* Type Offset=72 */
	/* Parameter phDrs */
/* 54 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 56 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 58 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure IDL_DRSUnbind - 60 */
/* 60 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 62 */	NdrFcLong( 0x0 ),	/* 0 */
/* 66 */	NdrFcShort( 0x1 ),	/* 1 */
/* 68 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 70 */	0x30,		/* FC_BIND_CONTEXT */
			0xe0,		/* Ctxt flags:  via ptr, in, out, */
/* 72 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 74 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 76 */	NdrFcShort( 0x38 ),	/* 56 */
/* 78 */	NdrFcShort( 0x40 ),	/* 64 */
/* 80 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x2,		/* 2 */
/* 82 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 84 */	NdrFcShort( 0x0 ),	/* 0 */
/* 86 */	NdrFcShort( 0x0 ),	/* 0 */
/* 88 */	NdrFcShort( 0x0 ),	/* 0 */
/* 90 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter phDrs */
/* 92 */	NdrFcShort( 0x118 ),	/* Flags:  in, out, simple ref, */
/* 94 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 96 */	NdrFcShort( 0x50 ),	/* Type Offset=80 */
	/* Return value */
/* 98 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 100 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 102 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure IDL_DRSGetNCChanges - 104 */
/* 130 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 132 */	NdrFcLong( 0x0 ),	/* 0 */
/* 136 */	NdrFcShort( 0x3 ),	/* 3 */
/* 138 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 140 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 142 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 144 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 146 */	NdrFcShort( 0x2c ),	/* 44 */
/* 148 */	NdrFcShort( 0x24 ),	/* 36 */
/* 150 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x6,		/* 6 */
/* 152 */	0xa,		/* 10 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 154 */	NdrFcShort( 0x1 ),	/* 1 */
/* 156 */	NdrFcShort( 0x1 ),	/* 1 */
/* 158 */	NdrFcShort( 0x0 ),	/* 0 */
/* 160 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter hDrs */
/* 162 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 164 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 166 */	NdrFcShort( 0x54 ),	/* Type Offset=84 */
	/* Parameter dwInVersion */
/* 168 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 170 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 172 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgIn */
/* 174 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 176 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 178 */	NdrFcShort( 0x5c ),	/* Type Offset=92 */
	/* Parameter pdwOutVersion */
/* 180 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 182 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 184 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgOut */
/* 186 */	NdrFcShort( 0x113 ),	/* Flags:  must size, must free, out, simple ref, */
/* 188 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 190 */	NdrFcShort( 0x2aa ),	/* Type Offset=682 */
	/* Return value */
/* 192 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 194 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 196 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure IDL_DRSCrackNames - 172 */
/* 406 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 408 */	NdrFcLong( 0x0 ),	/* 0 */
/* 412 */	NdrFcShort( 0xc ),	/* 12 */
/* 414 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 416 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 418 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 420 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 422 */	NdrFcShort( 0x2c ),	/* 44 */
/* 424 */	NdrFcShort( 0x24 ),	/* 36 */
/* 426 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x6,		/* 6 */
/* 428 */	0xa,		/* 10 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 430 */	NdrFcShort( 0x1 ),	/* 1 */
/* 432 */	NdrFcShort( 0x1 ),	/* 1 */
/* 434 */	NdrFcShort( 0x0 ),	/* 0 */
/* 436 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter hDrs */
/* 438 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 440 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 442 */	NdrFcShort( 0x54 ),	/* Type Offset=84 */
	/* Parameter dwInVersion */
/* 444 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 446 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 448 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgIn */
/* 450 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 452 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 454 */	NdrFcShort( 0x586 ),	/* Type Offset=1414 */
	/* Parameter pdwOutVersion */
/* 456 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 458 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 460 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgOut */
/* 462 */	NdrFcShort( 0x2113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=8 */
/* 464 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 466 */	NdrFcShort( 0x5d8 ),	/* Type Offset=1496 */
	/* Return value */
/* 468 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 470 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 472 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure IDL_DRSDomainControllerInfo - 240 */
/* 552 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 554 */	NdrFcLong( 0x0 ),	/* 0 */
/* 558 */	NdrFcShort( 0x10 ),	/* 16 */
/* 560 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 562 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 564 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 566 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 568 */	NdrFcShort( 0x2c ),	/* 44 */
/* 570 */	NdrFcShort( 0x24 ),	/* 36 */
/* 572 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x6,		/* 6 */
/* 574 */	0xa,		/* 10 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 576 */	NdrFcShort( 0x1 ),	/* 1 */
/* 578 */	NdrFcShort( 0x1 ),	/* 1 */
/* 580 */	NdrFcShort( 0x0 ),	/* 0 */
/* 582 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter hDrs */
/* 584 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 586 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 588 */	NdrFcShort( 0x54 ),	/* Type Offset=84 */
	/* Parameter dwInVersion */
/* 590 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 592 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 594 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgIn */
/* 596 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 598 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 600 */	NdrFcShort( 0x63c ),	/* Type Offset=1596 */
	/* Parameter pdwOutVersion */
/* 602 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 604 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 606 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgOut */
/* 608 */	NdrFcShort( 0x4113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=16 */
/* 610 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 612 */	NdrFcShort( 0x666 ),	/* Type Offset=1638 */
	/* Return value */
/* 614 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 616 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 618 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
    };

static const ms2Ddrsr_MIDL_TYPE_FORMAT_STRING ms2Ddrsr__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x0,	/* FC_UP */
/*  4 */	NdrFcShort( 0x8 ),	/* Offset= 8 (12) */
/*  6 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/*  8 */	NdrFcShort( 0x8 ),	/* 8 */
/* 10 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 12 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 14 */	NdrFcShort( 0x10 ),	/* 16 */
/* 16 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 18 */	0x6,		/* FC_SHORT */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 20 */	0x0,		/* 0 */
			NdrFcShort( 0xfff1 ),	/* Offset= -15 (6) */
			0x5b,		/* FC_END */
/* 24 */	
			0x12, 0x0,	/* FC_UP */
/* 26 */	NdrFcShort( 0x18 ),	/* Offset= 24 (50) */
/* 28 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 30 */	NdrFcLong( 0x1 ),	/* 1 */
/* 34 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 38 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 40 */	NdrFcShort( 0x1 ),	/* 1 */
/* 42 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 44 */	NdrFcShort( 0xfffc ),	/* -4 */
/* 46 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 48 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 50 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 52 */	NdrFcShort( 0x4 ),	/* 4 */
/* 54 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (38) */
/* 56 */	NdrFcShort( 0x0 ),	/* Offset= 0 (56) */
/* 58 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 60 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (28) */
/* 62 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 64 */	
			0x11, 0x14,	/* FC_RP [alloced_on_stack] [pointer_deref] */
/* 66 */	NdrFcShort( 0xffd6 ),	/* Offset= -42 (24) */
/* 68 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 70 */	NdrFcShort( 0x2 ),	/* Offset= 2 (72) */
/* 72 */	0x30,		/* FC_BIND_CONTEXT */
			0xa0,		/* Ctxt flags:  via ptr, out, */
/* 74 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 76 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 78 */	NdrFcShort( 0x2 ),	/* Offset= 2 (80) */
/* 80 */	0x30,		/* FC_BIND_CONTEXT */
			0xe1,		/* Ctxt flags:  via ptr, in, out, can't be null */
/* 82 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 84 */	0x30,		/* FC_BIND_CONTEXT */
			0x41,		/* Ctxt flags:  in, can't be null */
/* 86 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 88 */	
			0x11, 0x0,	/* FC_RP */
/* 90 */	NdrFcShort( 0x2 ),	/* Offset= 2 (92) */
/* 92 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 94 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x0,		/*  */
/* 96 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 98 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 100 */	NdrFcShort( 0x2 ),	/* Offset= 2 (102) */
/* 102 */	NdrFcShort( 0xa8 ),	/* 168 */
/* 104 */	NdrFcShort( 0x5 ),	/* 5 */
/* 106 */	NdrFcLong( 0x4 ),	/* 4 */
/* 110 */	NdrFcShort( 0x15e ),	/* Offset= 350 (460) */
/* 112 */	NdrFcLong( 0x5 ),	/* 5 */
/* 116 */	NdrFcShort( 0x174 ),	/* Offset= 372 (488) */
/* 118 */	NdrFcLong( 0x7 ),	/* 7 */
/* 122 */	NdrFcShort( 0x196 ),	/* Offset= 406 (528) */
/* 124 */	NdrFcLong( 0x8 ),	/* 8 */
/* 128 */	NdrFcShort( 0x1b4 ),	/* Offset= 436 (564) */
/* 130 */	NdrFcLong( 0xa ),	/* 10 */
/* 134 */	NdrFcShort( 0x1e4 ),	/* Offset= 484 (618) */
/* 136 */	NdrFcShort( 0xffff ),	/* Offset= -1 (135) */
/* 138 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 140 */	NdrFcShort( 0x18 ),	/* 24 */
/* 142 */	0xb,		/* FC_HYPER */
			0xb,		/* FC_HYPER */
/* 144 */	0xb,		/* FC_HYPER */
			0x5b,		/* FC_END */
/* 146 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 148 */	NdrFcLong( 0x0 ),	/* 0 */
/* 152 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 156 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 158 */	NdrFcLong( 0x0 ),	/* 0 */
/* 162 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 166 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 168 */	NdrFcShort( 0x1 ),	/* 1 */
/* 170 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 172 */	NdrFcShort( 0x0 ),	/* 0 */
/* 174 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 176 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 178 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 180 */	NdrFcShort( 0x10 ),	/* 16 */
/* 182 */	NdrFcShort( 0x0 ),	/* 0 */
/* 184 */	NdrFcShort( 0xa ),	/* Offset= 10 (194) */
/* 186 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 188 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (156) */
/* 190 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 192 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 194 */	
			0x12, 0x0,	/* FC_UP */
/* 196 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (166) */
/* 198 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 200 */	NdrFcShort( 0x18 ),	/* 24 */
/* 202 */	NdrFcShort( 0x0 ),	/* 0 */
/* 204 */	NdrFcShort( 0x0 ),	/* Offset= 0 (204) */
/* 206 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 208 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 210 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (178) */
/* 212 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 214 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 216 */	NdrFcShort( 0x0 ),	/* 0 */
/* 218 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 220 */	NdrFcShort( 0x0 ),	/* 0 */
/* 222 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 224 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 228 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 230 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 232 */	NdrFcShort( 0xffde ),	/* Offset= -34 (198) */
/* 234 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 236 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 238 */	NdrFcShort( 0x10 ),	/* 16 */
/* 240 */	NdrFcShort( 0x0 ),	/* 0 */
/* 242 */	NdrFcShort( 0xa ),	/* Offset= 10 (252) */
/* 244 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 246 */	NdrFcShort( 0xff9c ),	/* Offset= -100 (146) */
/* 248 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 250 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 252 */	
			0x12, 0x0,	/* FC_UP */
/* 254 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (214) */
/* 256 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 258 */	NdrFcShort( 0x1c ),	/* 28 */
/* 260 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 262 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 264 */	NdrFcShort( 0x1c ),	/* 28 */
/* 266 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 268 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (256) */
/* 270 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 272 */	
			0x1b,		/* FC_CARRAY */
			0x1,		/* 1 */
/* 274 */	NdrFcShort( 0x2 ),	/* 2 */
/* 276 */	0x9,		/* Corr desc: FC_ULONG */
			0x57,		/* FC_ADD_1 */
/* 278 */	NdrFcShort( 0xfffc ),	/* -4 */
/* 280 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 282 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 284 */	
			0x17,		/* FC_CSTRUCT */
			0x3,		/* 3 */
/* 286 */	NdrFcShort( 0x38 ),	/* 56 */
/* 288 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (272) */
/* 290 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 292 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 294 */	NdrFcShort( 0xfee6 ),	/* Offset= -282 (12) */
/* 296 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 298 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (262) */
/* 300 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 302 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 304 */	NdrFcLong( 0x0 ),	/* 0 */
/* 308 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 312 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 314 */	NdrFcShort( 0x18 ),	/* 24 */
/* 316 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 318 */	NdrFcShort( 0xfece ),	/* Offset= -306 (12) */
/* 320 */	0xb,		/* FC_HYPER */
			0x5b,		/* FC_END */
/* 322 */	
			0x1b,		/* FC_CARRAY */
			0x7,		/* 7 */
/* 324 */	NdrFcShort( 0x18 ),	/* 24 */
/* 326 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 328 */	NdrFcShort( 0xfff8 ),	/* -8 */
/* 330 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 332 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 334 */	NdrFcShort( 0xffea ),	/* Offset= -22 (312) */
/* 336 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 338 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 340 */	NdrFcShort( 0x10 ),	/* 16 */
/* 342 */	NdrFcShort( 0xffec ),	/* Offset= -20 (322) */
/* 344 */	NdrFcShort( 0x0 ),	/* Offset= 0 (344) */
/* 346 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 348 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 350 */	NdrFcShort( 0xffd0 ),	/* Offset= -48 (302) */
/* 352 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 354 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 356 */	NdrFcLong( 0x1 ),	/* 1 */
/* 360 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 364 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 366 */	NdrFcShort( 0x4 ),	/* 4 */
/* 368 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 370 */	NdrFcShort( 0xfffc ),	/* -4 */
/* 372 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 374 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 376 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 378 */	NdrFcShort( 0xc ),	/* 12 */
/* 380 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (364) */
/* 382 */	NdrFcShort( 0x0 ),	/* Offset= 0 (382) */
/* 384 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 386 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 388 */	NdrFcShort( 0xffde ),	/* Offset= -34 (354) */
/* 390 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 392 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 394 */	NdrFcShort( 0x70 ),	/* 112 */
/* 396 */	NdrFcShort( 0x0 ),	/* 0 */
/* 398 */	NdrFcShort( 0x1a ),	/* Offset= 26 (424) */
/* 400 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 402 */	NdrFcShort( 0xfe7a ),	/* Offset= -390 (12) */
/* 404 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 406 */	NdrFcShort( 0xfe76 ),	/* Offset= -394 (12) */
/* 408 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 410 */	0x0,		/* 0 */
			NdrFcShort( 0xfeef ),	/* Offset= -273 (138) */
			0x36,		/* FC_POINTER */
/* 414 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 416 */	0x0,		/* 0 */
			NdrFcShort( 0xff4b ),	/* Offset= -181 (236) */
			0x8,		/* FC_LONG */
/* 420 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 422 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 424 */	
			0x11, 0x0,	/* FC_RP */
/* 426 */	NdrFcShort( 0xff72 ),	/* Offset= -142 (284) */
/* 428 */	
			0x12, 0x0,	/* FC_UP */
/* 430 */	NdrFcShort( 0xffa4 ),	/* Offset= -92 (338) */
/* 432 */	
			0x12, 0x0,	/* FC_UP */
/* 434 */	NdrFcShort( 0xffc6 ),	/* Offset= -58 (376) */
/* 436 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 438 */	NdrFcLong( 0x1 ),	/* 1 */
/* 442 */	NdrFcLong( 0x100 ),	/* 256 */
/* 446 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 448 */	NdrFcShort( 0x4 ),	/* 4 */
/* 450 */	NdrFcShort( 0xfe64 ),	/* Offset= -412 (38) */
/* 452 */	NdrFcShort( 0x0 ),	/* Offset= 0 (452) */
/* 454 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 456 */	NdrFcShort( 0xffec ),	/* Offset= -20 (436) */
/* 458 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 460 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 462 */	NdrFcShort( 0x88 ),	/* 136 */
/* 464 */	NdrFcShort( 0x0 ),	/* 0 */
/* 466 */	NdrFcShort( 0xc ),	/* Offset= 12 (478) */
/* 468 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 470 */	NdrFcShort( 0xfe36 ),	/* Offset= -458 (12) */
/* 472 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 474 */	0x0,		/* 0 */
			NdrFcShort( 0xffad ),	/* Offset= -83 (392) */
			0x5b,		/* FC_END */
/* 478 */	
			0x11, 0x0,	/* FC_RP */
/* 480 */	NdrFcShort( 0xffde ),	/* Offset= -34 (446) */
/* 482 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 484 */	NdrFcShort( 0x8 ),	/* 8 */
/* 486 */	0xb,		/* FC_HYPER */
			0x5b,		/* FC_END */
/* 488 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 490 */	NdrFcShort( 0x60 ),	/* 96 */
/* 492 */	NdrFcShort( 0x0 ),	/* 0 */
/* 494 */	NdrFcShort( 0x1a ),	/* Offset= 26 (520) */
/* 496 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 498 */	NdrFcShort( 0xfe1a ),	/* Offset= -486 (12) */
/* 500 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 502 */	NdrFcShort( 0xfe16 ),	/* Offset= -490 (12) */
/* 504 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 506 */	0x0,		/* 0 */
			NdrFcShort( 0xfe8f ),	/* Offset= -369 (138) */
			0x36,		/* FC_POINTER */
/* 510 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 512 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 514 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 516 */	NdrFcShort( 0xffde ),	/* Offset= -34 (482) */
/* 518 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 520 */	
			0x11, 0x0,	/* FC_RP */
/* 522 */	NdrFcShort( 0xff12 ),	/* Offset= -238 (284) */
/* 524 */	
			0x12, 0x0,	/* FC_UP */
/* 526 */	NdrFcShort( 0xff44 ),	/* Offset= -188 (338) */
/* 528 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 530 */	NdrFcShort( 0xa8 ),	/* 168 */
/* 532 */	NdrFcShort( 0x0 ),	/* 0 */
/* 534 */	NdrFcShort( 0x12 ),	/* Offset= 18 (552) */
/* 536 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 538 */	NdrFcShort( 0xfdf2 ),	/* Offset= -526 (12) */
/* 540 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 542 */	0x0,		/* 0 */
			NdrFcShort( 0xff69 ),	/* Offset= -151 (392) */
			0x36,		/* FC_POINTER */
/* 546 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 548 */	0x0,		/* 0 */
			NdrFcShort( 0xfec7 ),	/* Offset= -313 (236) */
			0x5b,		/* FC_END */
/* 552 */	
			0x11, 0x0,	/* FC_RP */
/* 554 */	NdrFcShort( 0xff94 ),	/* Offset= -108 (446) */
/* 556 */	
			0x12, 0x0,	/* FC_UP */
/* 558 */	NdrFcShort( 0xff4a ),	/* Offset= -182 (376) */
/* 560 */	
			0x12, 0x0,	/* FC_UP */
/* 562 */	NdrFcShort( 0xff46 ),	/* Offset= -186 (376) */
/* 564 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 566 */	NdrFcShort( 0x80 ),	/* 128 */
/* 568 */	NdrFcShort( 0x0 ),	/* 0 */
/* 570 */	NdrFcShort( 0x20 ),	/* Offset= 32 (602) */
/* 572 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 574 */	NdrFcShort( 0xfdce ),	/* Offset= -562 (12) */
/* 576 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 578 */	NdrFcShort( 0xfdca ),	/* Offset= -566 (12) */
/* 580 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 582 */	0x0,		/* 0 */
			NdrFcShort( 0xfe43 ),	/* Offset= -445 (138) */
			0x36,		/* FC_POINTER */
/* 586 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 588 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 590 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 592 */	NdrFcShort( 0xff92 ),	/* Offset= -110 (482) */
/* 594 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 596 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 598 */	NdrFcShort( 0xfe96 ),	/* Offset= -362 (236) */
/* 600 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 602 */	
			0x11, 0x0,	/* FC_RP */
/* 604 */	NdrFcShort( 0xfec0 ),	/* Offset= -320 (284) */
/* 606 */	
			0x12, 0x0,	/* FC_UP */
/* 608 */	NdrFcShort( 0xfef2 ),	/* Offset= -270 (338) */
/* 610 */	
			0x12, 0x0,	/* FC_UP */
/* 612 */	NdrFcShort( 0xff14 ),	/* Offset= -236 (376) */
/* 614 */	
			0x12, 0x0,	/* FC_UP */
/* 616 */	NdrFcShort( 0xff10 ),	/* Offset= -240 (376) */
/* 618 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 620 */	NdrFcShort( 0x88 ),	/* 136 */
/* 622 */	NdrFcShort( 0x0 ),	/* 0 */
/* 624 */	NdrFcShort( 0x22 ),	/* Offset= 34 (658) */
/* 626 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 628 */	NdrFcShort( 0xfd98 ),	/* Offset= -616 (12) */
/* 630 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 632 */	NdrFcShort( 0xfd94 ),	/* Offset= -620 (12) */
/* 634 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 636 */	0x0,		/* 0 */
			NdrFcShort( 0xfe0d ),	/* Offset= -499 (138) */
			0x36,		/* FC_POINTER */
/* 640 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 642 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 644 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 646 */	NdrFcShort( 0xff5c ),	/* Offset= -164 (482) */
/* 648 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 650 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 652 */	NdrFcShort( 0xfe60 ),	/* Offset= -416 (236) */
/* 654 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 656 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 658 */	
			0x11, 0x0,	/* FC_RP */
/* 660 */	NdrFcShort( 0xfe88 ),	/* Offset= -376 (284) */
/* 662 */	
			0x12, 0x0,	/* FC_UP */
/* 664 */	NdrFcShort( 0xfeba ),	/* Offset= -326 (338) */
/* 666 */	
			0x12, 0x0,	/* FC_UP */
/* 668 */	NdrFcShort( 0xfedc ),	/* Offset= -292 (376) */
/* 670 */	
			0x12, 0x0,	/* FC_UP */
/* 672 */	NdrFcShort( 0xfed8 ),	/* Offset= -296 (376) */
/* 674 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/* 676 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */
/* 678 */	
			0x11, 0x0,	/* FC_RP */
/* 680 */	NdrFcShort( 0x2 ),	/* Offset= 2 (682) */
/* 682 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 684 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x54,		/* FC_DEREFERENCE */
/* 686 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 688 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 690 */	NdrFcShort( 0x2 ),	/* Offset= 2 (692) */
/* 692 */	NdrFcShort( 0xa8 ),	/* 168 */
/* 694 */	NdrFcShort( 0x5 ),	/* 5 */
/* 696 */	NdrFcLong( 0x1 ),	/* 1 */
/* 700 */	NdrFcShort( 0x11a ),	/* Offset= 282 (982) */
/* 702 */	NdrFcLong( 0x2 ),	/* 2 */
/* 706 */	NdrFcShort( 0x162 ),	/* Offset= 354 (1060) */
/* 708 */	NdrFcLong( 0x6 ),	/* 6 */
/* 712 */	NdrFcShort( 0x1e4 ),	/* Offset= 484 (1196) */
/* 714 */	NdrFcLong( 0x7 ),	/* 7 */
/* 718 */	NdrFcShort( 0x21c ),	/* Offset= 540 (1258) */
/* 720 */	NdrFcLong( 0x9 ),	/* 9 */
/* 724 */	NdrFcShort( 0x270 ),	/* Offset= 624 (1348) */
/* 726 */	NdrFcShort( 0xffff ),	/* Offset= -1 (725) */
/* 728 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 730 */	NdrFcLong( 0x0 ),	/* 0 */
/* 734 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 738 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 740 */	NdrFcLong( 0x0 ),	/* 0 */
/* 744 */	NdrFcLong( 0xa00000 ),	/* 10485760 */
/* 748 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 750 */	NdrFcLong( 0x0 ),	/* 0 */
/* 754 */	NdrFcLong( 0x1900000 ),	/* 26214400 */
/* 758 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 760 */	NdrFcShort( 0x10 ),	/* 16 */
/* 762 */	NdrFcShort( 0x0 ),	/* 0 */
/* 764 */	NdrFcShort( 0xa ),	/* Offset= 10 (774) */
/* 766 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 768 */	NdrFcShort( 0xffec ),	/* Offset= -20 (748) */
/* 770 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 772 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 774 */	
			0x12, 0x0,	/* FC_UP */
/* 776 */	NdrFcShort( 0xfd9e ),	/* Offset= -610 (166) */
/* 778 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 780 */	NdrFcShort( 0x0 ),	/* 0 */
/* 782 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 784 */	NdrFcShort( 0x0 ),	/* 0 */
/* 786 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 788 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 792 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 794 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 796 */	NdrFcShort( 0xffda ),	/* Offset= -38 (758) */
/* 798 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 800 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 802 */	NdrFcShort( 0x10 ),	/* 16 */
/* 804 */	NdrFcShort( 0x0 ),	/* 0 */
/* 806 */	NdrFcShort( 0xa ),	/* Offset= 10 (816) */
/* 808 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 810 */	NdrFcShort( 0xffb8 ),	/* Offset= -72 (738) */
/* 812 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 814 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 816 */	
			0x12, 0x0,	/* FC_UP */
/* 818 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (778) */
/* 820 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 822 */	NdrFcShort( 0x18 ),	/* 24 */
/* 824 */	NdrFcShort( 0x0 ),	/* 0 */
/* 826 */	NdrFcShort( 0x0 ),	/* Offset= 0 (826) */
/* 828 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 830 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 832 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (800) */
/* 834 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 836 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 838 */	NdrFcShort( 0x0 ),	/* 0 */
/* 840 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 842 */	NdrFcShort( 0x0 ),	/* 0 */
/* 844 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 846 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 850 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 852 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 854 */	NdrFcShort( 0xffde ),	/* Offset= -34 (820) */
/* 856 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 858 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 860 */	NdrFcShort( 0x10 ),	/* 16 */
/* 862 */	NdrFcShort( 0x0 ),	/* 0 */
/* 864 */	NdrFcShort( 0xa ),	/* Offset= 10 (874) */
/* 866 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 868 */	NdrFcShort( 0xff74 ),	/* Offset= -140 (728) */
/* 870 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 872 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 874 */	
			0x12, 0x0,	/* FC_UP */
/* 876 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (836) */
/* 878 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 880 */	NdrFcShort( 0x20 ),	/* 32 */
/* 882 */	NdrFcShort( 0x0 ),	/* 0 */
/* 884 */	NdrFcShort( 0xa ),	/* Offset= 10 (894) */
/* 886 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 888 */	0x40,		/* FC_STRUCTPAD4 */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 890 */	0x0,		/* 0 */
			NdrFcShort( 0xffdf ),	/* Offset= -33 (858) */
			0x5b,		/* FC_END */
/* 894 */	
			0x12, 0x0,	/* FC_UP */
/* 896 */	NdrFcShort( 0xfd9c ),	/* Offset= -612 (284) */
/* 898 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 900 */	NdrFcLong( 0x0 ),	/* 0 */
/* 904 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 908 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 910 */	NdrFcShort( 0x28 ),	/* 40 */
/* 912 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 914 */	0xb,		/* FC_HYPER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 916 */	0x0,		/* 0 */
			NdrFcShort( 0xfc77 ),	/* Offset= -905 (12) */
			0xb,		/* FC_HYPER */
/* 920 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 922 */	
			0x1b,		/* FC_CARRAY */
			0x7,		/* 7 */
/* 924 */	NdrFcShort( 0x28 ),	/* 40 */
/* 926 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 928 */	NdrFcShort( 0xfff8 ),	/* -8 */
/* 930 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 932 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 934 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (908) */
/* 936 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 938 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 940 */	NdrFcShort( 0x8 ),	/* 8 */
/* 942 */	NdrFcShort( 0xffec ),	/* Offset= -20 (922) */
/* 944 */	NdrFcShort( 0x0 ),	/* Offset= 0 (944) */
/* 946 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 948 */	NdrFcShort( 0xffce ),	/* Offset= -50 (898) */
/* 950 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 952 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 954 */	NdrFcShort( 0x40 ),	/* 64 */
/* 956 */	NdrFcShort( 0x0 ),	/* 0 */
/* 958 */	NdrFcShort( 0xc ),	/* Offset= 12 (970) */
/* 960 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 962 */	0x0,		/* 0 */
			NdrFcShort( 0xffab ),	/* Offset= -85 (878) */
			0x8,		/* FC_LONG */
/* 966 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 968 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 970 */	
			0x12, 0x0,	/* FC_UP */
/* 972 */	NdrFcShort( 0xffec ),	/* Offset= -20 (952) */
/* 974 */	
			0x12, 0x0,	/* FC_UP */
/* 976 */	NdrFcShort( 0xfc3c ),	/* Offset= -964 (12) */
/* 978 */	
			0x12, 0x0,	/* FC_UP */
/* 980 */	NdrFcShort( 0xffd6 ),	/* Offset= -42 (938) */
/* 982 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 984 */	NdrFcShort( 0x90 ),	/* 144 */
/* 986 */	NdrFcShort( 0x0 ),	/* 0 */
/* 988 */	NdrFcShort( 0x20 ),	/* Offset= 32 (1020) */
/* 990 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 992 */	NdrFcShort( 0xfc2c ),	/* Offset= -980 (12) */
/* 994 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 996 */	NdrFcShort( 0xfc28 ),	/* Offset= -984 (12) */
/* 998 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1000 */	0x0,		/* 0 */
			NdrFcShort( 0xfca1 ),	/* Offset= -863 (138) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1004 */	0x0,		/* 0 */
			NdrFcShort( 0xfc9d ),	/* Offset= -867 (138) */
			0x36,		/* FC_POINTER */
/* 1008 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1010 */	NdrFcShort( 0xfcfa ),	/* Offset= -774 (236) */
/* 1012 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1014 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 1016 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1018 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 1020 */	
			0x12, 0x0,	/* FC_UP */
/* 1022 */	NdrFcShort( 0xfd1e ),	/* Offset= -738 (284) */
/* 1024 */	
			0x12, 0x0,	/* FC_UP */
/* 1026 */	NdrFcShort( 0xfd50 ),	/* Offset= -688 (338) */
/* 1028 */	
			0x12, 0x0,	/* FC_UP */
/* 1030 */	NdrFcShort( 0xffb2 ),	/* Offset= -78 (952) */
/* 1032 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 1034 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1036 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1038 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1040 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1042 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 1044 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1046 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1048 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1050 */	NdrFcShort( 0x6 ),	/* Offset= 6 (1056) */
/* 1052 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1054 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 1056 */	
			0x12, 0x0,	/* FC_UP */
/* 1058 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (1032) */
/* 1060 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1062 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1064 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1066 */	NdrFcShort( 0x0 ),	/* Offset= 0 (1066) */
/* 1068 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1070 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (1044) */
/* 1072 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1074 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1076 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1080 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 1084 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1086 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1090 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 1094 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 1096 */	NdrFcShort( 0x20 ),	/* 32 */
/* 1098 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1100 */	NdrFcShort( 0xfbc0 ),	/* Offset= -1088 (12) */
/* 1102 */	0xb,		/* FC_HYPER */
			0xb,		/* FC_HYPER */
/* 1104 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1106 */	
			0x1b,		/* FC_CARRAY */
			0x7,		/* 7 */
/* 1108 */	NdrFcShort( 0x20 ),	/* 32 */
/* 1110 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 1112 */	NdrFcShort( 0xfff8 ),	/* -8 */
/* 1114 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1116 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1118 */	NdrFcShort( 0xffe8 ),	/* Offset= -24 (1094) */
/* 1120 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1122 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 1124 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1126 */	NdrFcShort( 0xffec ),	/* Offset= -20 (1106) */
/* 1128 */	NdrFcShort( 0x0 ),	/* Offset= 0 (1128) */
/* 1130 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1132 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1134 */	NdrFcShort( 0xffce ),	/* Offset= -50 (1084) */
/* 1136 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 1138 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 1140 */	NdrFcShort( 0x30 ),	/* 48 */
/* 1142 */	0xb,		/* FC_HYPER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1144 */	0x0,		/* 0 */
			NdrFcShort( 0xff13 ),	/* Offset= -237 (908) */
			0x5b,		/* FC_END */
/* 1148 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 1150 */	NdrFcShort( 0x58 ),	/* 88 */
/* 1152 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1154 */	NdrFcShort( 0x10 ),	/* Offset= 16 (1170) */
/* 1156 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1158 */	0x40,		/* FC_STRUCTPAD4 */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1160 */	0x0,		/* 0 */
			NdrFcShort( 0xfe6d ),	/* Offset= -403 (758) */
			0x8,		/* FC_LONG */
/* 1164 */	0x40,		/* FC_STRUCTPAD4 */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1166 */	0x0,		/* 0 */
			NdrFcShort( 0xffe3 ),	/* Offset= -29 (1138) */
			0x5b,		/* FC_END */
/* 1170 */	
			0x12, 0x0,	/* FC_UP */
/* 1172 */	NdrFcShort( 0xfc88 ),	/* Offset= -888 (284) */
/* 1174 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x7,		/* 7 */
/* 1176 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1178 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1180 */	NdrFcShort( 0x94 ),	/* 148 */
/* 1182 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1184 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1188 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 1190 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1192 */	NdrFcShort( 0xffd4 ),	/* Offset= -44 (1148) */
/* 1194 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1196 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 1198 */	NdrFcShort( 0xa8 ),	/* 168 */
/* 1200 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1202 */	NdrFcShort( 0x28 ),	/* Offset= 40 (1242) */
/* 1204 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1206 */	NdrFcShort( 0xfb56 ),	/* Offset= -1194 (12) */
/* 1208 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1210 */	NdrFcShort( 0xfb52 ),	/* Offset= -1198 (12) */
/* 1212 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1214 */	0x0,		/* 0 */
			NdrFcShort( 0xfbcb ),	/* Offset= -1077 (138) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1218 */	0x0,		/* 0 */
			NdrFcShort( 0xfbc7 ),	/* Offset= -1081 (138) */
			0x36,		/* FC_POINTER */
/* 1222 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1224 */	NdrFcShort( 0xfc24 ),	/* Offset= -988 (236) */
/* 1226 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1228 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 1230 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1232 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1234 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1236 */	NdrFcShort( 0xff5e ),	/* Offset= -162 (1074) */
/* 1238 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1240 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 1242 */	
			0x12, 0x0,	/* FC_UP */
/* 1244 */	NdrFcShort( 0xfc40 ),	/* Offset= -960 (284) */
/* 1246 */	
			0x12, 0x0,	/* FC_UP */
/* 1248 */	NdrFcShort( 0xff82 ),	/* Offset= -126 (1122) */
/* 1250 */	
			0x12, 0x0,	/* FC_UP */
/* 1252 */	NdrFcShort( 0xfed4 ),	/* Offset= -300 (952) */
/* 1254 */	
			0x12, 0x0,	/* FC_UP */
/* 1256 */	NdrFcShort( 0xffae ),	/* Offset= -82 (1174) */
/* 1258 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1260 */	NdrFcShort( 0x18 ),	/* 24 */
/* 1262 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1264 */	NdrFcShort( 0x0 ),	/* Offset= 0 (1264) */
/* 1266 */	0x8,		/* FC_LONG */
			0xd,		/* FC_ENUM16 */
/* 1268 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1270 */	NdrFcShort( 0xff1e ),	/* Offset= -226 (1044) */
/* 1272 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1274 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1276 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1280 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 1284 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 1286 */	NdrFcShort( 0x48 ),	/* 72 */
/* 1288 */	0xb,		/* FC_HYPER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1290 */	0x0,		/* 0 */
			NdrFcShort( 0xfe81 ),	/* Offset= -383 (908) */
			0x8,		/* FC_LONG */
/* 1294 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1296 */	0x40,		/* FC_STRUCTPAD4 */
			0xb,		/* FC_HYPER */
/* 1298 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1300 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 1302 */	NdrFcShort( 0x70 ),	/* 112 */
/* 1304 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1306 */	NdrFcShort( 0x10 ),	/* Offset= 16 (1322) */
/* 1308 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1310 */	0x40,		/* FC_STRUCTPAD4 */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1312 */	0x0,		/* 0 */
			NdrFcShort( 0xfdd5 ),	/* Offset= -555 (758) */
			0x8,		/* FC_LONG */
/* 1316 */	0x40,		/* FC_STRUCTPAD4 */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1318 */	0x0,		/* 0 */
			NdrFcShort( 0xffdd ),	/* Offset= -35 (1284) */
			0x5b,		/* FC_END */
/* 1322 */	
			0x12, 0x0,	/* FC_UP */
/* 1324 */	NdrFcShort( 0xfbf0 ),	/* Offset= -1040 (284) */
/* 1326 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x7,		/* 7 */
/* 1328 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1330 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1332 */	NdrFcShort( 0x94 ),	/* 148 */
/* 1334 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1336 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1340 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 1342 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1344 */	NdrFcShort( 0xffd4 ),	/* Offset= -44 (1300) */
/* 1346 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1348 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 1350 */	NdrFcShort( 0xa8 ),	/* 168 */
/* 1352 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1354 */	NdrFcShort( 0x28 ),	/* Offset= 40 (1394) */
/* 1356 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1358 */	NdrFcShort( 0xfabe ),	/* Offset= -1346 (12) */
/* 1360 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1362 */	NdrFcShort( 0xfaba ),	/* Offset= -1350 (12) */
/* 1364 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1366 */	0x0,		/* 0 */
			NdrFcShort( 0xfb33 ),	/* Offset= -1229 (138) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1370 */	0x0,		/* 0 */
			NdrFcShort( 0xfb2f ),	/* Offset= -1233 (138) */
			0x36,		/* FC_POINTER */
/* 1374 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1376 */	NdrFcShort( 0xfb8c ),	/* Offset= -1140 (236) */
/* 1378 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1380 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 1382 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1384 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1386 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1388 */	NdrFcShort( 0xff8e ),	/* Offset= -114 (1274) */
/* 1390 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1392 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 1394 */	
			0x12, 0x0,	/* FC_UP */
/* 1396 */	NdrFcShort( 0xfba8 ),	/* Offset= -1112 (284) */
/* 1398 */	
			0x12, 0x0,	/* FC_UP */
/* 1400 */	NdrFcShort( 0xfeea ),	/* Offset= -278 (1122) */
/* 1402 */	
			0x12, 0x0,	/* FC_UP */
/* 1404 */	NdrFcShort( 0xfe3c ),	/* Offset= -452 (952) */
/* 1406 */	
			0x12, 0x0,	/* FC_UP */
/* 1408 */	NdrFcShort( 0xffae ),	/* Offset= -82 (1326) */
/* 1410 */	
			0x11, 0x0,	/* FC_RP */
/* 1412 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1414) */
/* 1414 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 1416 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x0,		/*  */
/* 1418 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1420 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1422 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1424) */
/* 1424 */	NdrFcShort( 0x20 ),	/* 32 */
/* 1426 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1428 */	NdrFcLong( 0x1 ),	/* 1 */
/* 1432 */	NdrFcShort( 0x24 ),	/* Offset= 36 (1468) */
/* 1434 */	NdrFcShort( 0xffff ),	/* Offset= -1 (1433) */
/* 1436 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1438 */	NdrFcLong( 0x1 ),	/* 1 */
/* 1442 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 1446 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 1448 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1450 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1452 */	NdrFcShort( 0x14 ),	/* 20 */
/* 1454 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1456 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1460 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 1462 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1464 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1466 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1468 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1470 */	NdrFcShort( 0x20 ),	/* 32 */
/* 1472 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1474 */	NdrFcShort( 0xe ),	/* Offset= 14 (1488) */
/* 1476 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1478 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1480 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1482 */	0x0,		/* 0 */
			NdrFcShort( 0xffd1 ),	/* Offset= -47 (1436) */
			0x36,		/* FC_POINTER */
/* 1486 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1488 */	
			0x12, 0x0,	/* FC_UP */
/* 1490 */	NdrFcShort( 0xffd4 ),	/* Offset= -44 (1446) */
/* 1492 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 1494 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1496) */
/* 1496 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 1498 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x54,		/* FC_DEREFERENCE */
/* 1500 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 1502 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1504 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1506) */
/* 1506 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1508 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1510 */	NdrFcLong( 0x1 ),	/* 1 */
/* 1514 */	NdrFcShort( 0x40 ),	/* Offset= 64 (1578) */
/* 1516 */	NdrFcShort( 0xffff ),	/* Offset= -1 (1515) */
/* 1518 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1520 */	NdrFcShort( 0x18 ),	/* 24 */
/* 1522 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1524 */	NdrFcShort( 0x8 ),	/* Offset= 8 (1532) */
/* 1526 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 1528 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 1530 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1532 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1534 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1536 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1538 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1540 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 1542 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1544 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1546 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1548 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1550 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1554 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 1556 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1558 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (1518) */
/* 1560 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1562 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1564 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1566 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1568 */	NdrFcShort( 0x6 ),	/* Offset= 6 (1574) */
/* 1570 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 1572 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 1574 */	
			0x12, 0x0,	/* FC_UP */
/* 1576 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (1540) */
/* 1578 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1580 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1582 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1584 */	NdrFcShort( 0x4 ),	/* Offset= 4 (1588) */
/* 1586 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 1588 */	
			0x12, 0x0,	/* FC_UP */
/* 1590 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (1562) */
/* 1592 */	
			0x11, 0x0,	/* FC_RP */
/* 1594 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1596) */
/* 1596 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 1598 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x0,		/*  */
/* 1600 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 1602 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1604 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1606) */
/* 1606 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1608 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1610 */	NdrFcLong( 0x1 ),	/* 1 */
/* 1614 */	NdrFcShort( 0x4 ),	/* Offset= 4 (1618) */
/* 1616 */	NdrFcShort( 0xffff ),	/* Offset= -1 (1615) */
/* 1618 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1620 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1622 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1624 */	NdrFcShort( 0x6 ),	/* Offset= 6 (1630) */
/* 1626 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1628 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 1630 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1632 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1634 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 1636 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1638) */
/* 1638 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 1640 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x54,		/* FC_DEREFERENCE */
/* 1642 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 1644 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1646 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1648) */
/* 1648 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1650 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1652 */	NdrFcLong( 0x1 ),	/* 1 */
/* 1656 */	NdrFcShort( 0x5a ),	/* Offset= 90 (1746) */
/* 1658 */	NdrFcLong( 0x2 ),	/* 2 */
/* 1662 */	NdrFcShort( 0xc8 ),	/* Offset= 200 (1862) */
/* 1664 */	NdrFcLong( 0x3 ),	/* 3 */
/* 1668 */	NdrFcShort( 0x136 ),	/* Offset= 310 (1978) */
/* 1670 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1674 */	NdrFcShort( 0x178 ),	/* Offset= 376 (2050) */
/* 1676 */	NdrFcShort( 0xffff ),	/* Offset= -1 (1675) */
/* 1678 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1680 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1684 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 1688 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1690 */	NdrFcShort( 0x30 ),	/* 48 */
/* 1692 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1694 */	NdrFcShort( 0xa ),	/* Offset= 10 (1704) */
/* 1696 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 1698 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 1700 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1702 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 1704 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1706 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1708 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1710 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1712 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1714 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1716 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1718 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1720 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1722 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1724 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 1726 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1728 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1730 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1732 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1734 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1738 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 1740 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1742 */	NdrFcShort( 0xffca ),	/* Offset= -54 (1688) */
/* 1744 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1746 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1748 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1750 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1752 */	NdrFcShort( 0xa ),	/* Offset= 10 (1762) */
/* 1754 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1756 */	NdrFcShort( 0xffb2 ),	/* Offset= -78 (1678) */
/* 1758 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 1760 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1762 */	
			0x12, 0x0,	/* FC_UP */
/* 1764 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (1724) */
/* 1766 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1768 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1772 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 1776 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1778 */	NdrFcShort( 0x88 ),	/* 136 */
/* 1780 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1782 */	NdrFcShort( 0x1e ),	/* Offset= 30 (1812) */
/* 1784 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 1786 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 1788 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 1790 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1792 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1794 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1796 */	NdrFcShort( 0xf908 ),	/* Offset= -1784 (12) */
/* 1798 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1800 */	NdrFcShort( 0xf904 ),	/* Offset= -1788 (12) */
/* 1802 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1804 */	NdrFcShort( 0xf900 ),	/* Offset= -1792 (12) */
/* 1806 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1808 */	NdrFcShort( 0xf8fc ),	/* Offset= -1796 (12) */
/* 1810 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 1812 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1814 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1816 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1818 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1820 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1822 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1824 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1826 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1828 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1830 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1832 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1834 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1836 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1838 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1840 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 1842 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1844 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1846 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1848 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1850 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1854 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 1856 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1858 */	NdrFcShort( 0xffae ),	/* Offset= -82 (1776) */
/* 1860 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1862 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1864 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1866 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1868 */	NdrFcShort( 0xa ),	/* Offset= 10 (1878) */
/* 1870 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1872 */	NdrFcShort( 0xff96 ),	/* Offset= -106 (1766) */
/* 1874 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 1876 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1878 */	
			0x12, 0x0,	/* FC_UP */
/* 1880 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (1840) */
/* 1882 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1884 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1888 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 1892 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1894 */	NdrFcShort( 0x88 ),	/* 136 */
/* 1896 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1898 */	NdrFcShort( 0x1e ),	/* Offset= 30 (1928) */
/* 1900 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 1902 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 1904 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 1906 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1908 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1910 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1912 */	0x0,		/* 0 */
			NdrFcShort( 0xf893 ),	/* Offset= -1901 (12) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1916 */	0x0,		/* 0 */
			NdrFcShort( 0xf88f ),	/* Offset= -1905 (12) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1920 */	0x0,		/* 0 */
			NdrFcShort( 0xf88b ),	/* Offset= -1909 (12) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1924 */	0x0,		/* 0 */
			NdrFcShort( 0xf887 ),	/* Offset= -1913 (12) */
			0x5b,		/* FC_END */
/* 1928 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1930 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1932 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1934 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1936 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1938 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1940 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1942 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1944 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1946 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1948 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1950 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1952 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1954 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1956 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 1958 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1960 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1962 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1964 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1966 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1970 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 1972 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1974 */	NdrFcShort( 0xffae ),	/* Offset= -82 (1892) */
/* 1976 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1978 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1980 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1982 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1984 */	NdrFcShort( 0xa ),	/* Offset= 10 (1994) */
/* 1986 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1988 */	NdrFcShort( 0xff96 ),	/* Offset= -106 (1882) */
/* 1990 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 1992 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1994 */	
			0x12, 0x0,	/* FC_UP */
/* 1996 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (1956) */
/* 1998 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 2000 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2004 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 2008 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 2010 */	NdrFcShort( 0x20 ),	/* 32 */
/* 2012 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2014 */	NdrFcShort( 0xa ),	/* Offset= 10 (2024) */
/* 2016 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2018 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2020 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2022 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 2024 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2026 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2028 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 2030 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2032 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 2034 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2036 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 2038 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 2042 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 2044 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 2046 */	NdrFcShort( 0xffda ),	/* Offset= -38 (2008) */
/* 2048 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 2050 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 2052 */	NdrFcShort( 0x10 ),	/* 16 */
/* 2054 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2056 */	NdrFcShort( 0xa ),	/* Offset= 10 (2066) */
/* 2058 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 2060 */	NdrFcShort( 0xffc2 ),	/* Offset= -62 (1998) */
/* 2062 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 2064 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 2066 */	
			0x12, 0x0,	/* FC_UP */
/* 2068 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (2028) */

			0x0
        }
    };
#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

#elif defined _M_IX86
typedef struct _ms2Ddrsr_MIDL_TYPE_FORMAT_STRING
{
	short          Pad;
	unsigned char  Format[2411];
} ms2Ddrsr_MIDL_TYPE_FORMAT_STRING;

typedef struct _ms2Ddrsr_MIDL_PROC_FORMAT_STRING
{
	short          Pad;
	unsigned char  Format[587];
} ms2Ddrsr_MIDL_PROC_FORMAT_STRING;

extern const ms2Ddrsr_MIDL_TYPE_FORMAT_STRING ms2Ddrsr__MIDL_TypeFormatString;
extern const ms2Ddrsr_MIDL_PROC_FORMAT_STRING ms2Ddrsr__MIDL_ProcFormatString;
static const RPC_CLIENT_INTERFACE drsuapi___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0xe3514235, 0x4b06, 0x11d1, {0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}}, {4,0}}, {{0x8A885D04, 0x1CEB, 0x11C9, {0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
static RPC_BINDING_HANDLE drsuapi__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC drsuapi_StubDesc =  {(void *)& drsuapi___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &drsuapi__MIDL_AutoBindHandle, 0, 0, 0, 0, ms2Ddrsr__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};

#pragma optimize("", off )
ULONG IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs)
{
	return NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[0], (unsigned char *) &rpc_handle).Simple;
}

ULONG IDL_DRSUnbind(DRS_HANDLE *phDrs)
{
	return NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[58], (unsigned char *) &phDrs).Simple;
}

ULONG IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut)
{
	return NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[100], (unsigned char *) &hDrs).Simple;
}

ULONG IDL_DRSCrackNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut)
{
	return NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[166], (unsigned char *) &hDrs).Simple;
}

ULONG IDL_DRSDomainControllerInfo(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut)
{
	return NdrClientCall2((PMIDL_STUB_DESC) &drsuapi_StubDesc, (PFORMAT_STRING) &ms2Ddrsr__MIDL_ProcFormatString.Format[232], (unsigned char *) &hDrs).Simple;
}
#pragma optimize("", on )

#if !defined(__RPC_WIN32__)
#error  Invalid build platform for this stub.
#endif
#if !(TARGET_IS_NT51_OR_LATER)
#error You need Windows XP or later to run this stub because it uses these features:
#error   compiled for Windows XP.
#error However, your C/C++ compilation flags indicate you intend to run this app on earlier systems.
#error This app will fail with the RPC_X_WRONG_STUB_VERSION error.
#endif

static const ms2Ddrsr_MIDL_PROC_FORMAT_STRING ms2Ddrsr__MIDL_ProcFormatString = {
        0,
        {
	/* Procedure IDL_DRSBind - 0 */
			0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 14 */	NdrFcShort( 0x44 ),	/* 68 */
/* 16 */	NdrFcShort( 0x40 ),	/* 64 */
/* 18 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x5,		/* 5 */
/* 20 */	0x8,		/* 8 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 22 */	NdrFcShort( 0x1 ),	/* 1 */
/* 24 */	NdrFcShort( 0x1 ),	/* 1 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter rpc_handle */
/* 28 */	NdrFcShort( 0xa ),	/* Flags:  must free, in, */
/* 30 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 32 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */
	/* Parameter puuidClientDsa */
/* 34 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 36 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 38 */	NdrFcShort( 0x18 ),	/* Type Offset=24 */
	/* Parameter pextClient */
/* 40 */	NdrFcShort( 0x2013 ),	/* Flags:  must size, must free, out, srv alloc size=8 */
/* 42 */	NdrFcShort( 0xc ),	/* x86 Stack size/offset = 12 */
/* 44 */	NdrFcShort( 0x40 ),	/* Type Offset=64 */
	/* Parameter ppextServer */
/* 46 */	NdrFcShort( 0x110 ),	/* Flags:  out, simple ref, */
/* 48 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 50 */	NdrFcShort( 0x48 ),	/* Type Offset=72 */
	/* Parameter phDrs */
/* 52 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 54 */	NdrFcShort( 0x14 ),	/* x86 Stack size/offset = 20 */
/* 56 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure IDL_DRSUnbind - 58 */
/* 58 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 60 */	NdrFcLong( 0x0 ),	/* 0 */
/* 64 */	NdrFcShort( 0x1 ),	/* 1 */
/* 66 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 68 */	0x30,		/* FC_BIND_CONTEXT */
			0xe0,		/* Ctxt flags:  via ptr, in, out, */
/* 70 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 72 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 74 */	NdrFcShort( 0x38 ),	/* 56 */
/* 76 */	NdrFcShort( 0x40 ),	/* 64 */
/* 78 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x2,		/* 2 */
/* 80 */	0x8,		/* 8 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 82 */	NdrFcShort( 0x0 ),	/* 0 */
/* 84 */	NdrFcShort( 0x0 ),	/* 0 */
/* 86 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter phDrs */
/* 88 */	NdrFcShort( 0x118 ),	/* Flags:  in, out, simple ref, */
/* 90 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 92 */	NdrFcShort( 0x50 ),	/* Type Offset=80 */
	/* Return value */
/* 94 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 96 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 98 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure IDL_DRSGetNCChanges - 100 */
/* 124 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 126 */	NdrFcLong( 0x0 ),	/* 0 */
/* 130 */	NdrFcShort( 0x3 ),	/* 3 */
/* 132 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 134 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 136 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 138 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 140 */	NdrFcShort( 0x2c ),	/* 44 */
/* 142 */	NdrFcShort( 0x24 ),	/* 36 */
/* 144 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x6,		/* 6 */
/* 146 */	0x8,		/* 8 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 148 */	NdrFcShort( 0x1 ),	/* 1 */
/* 150 */	NdrFcShort( 0x1 ),	/* 1 */
/* 152 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter hDrs */
/* 154 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 156 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 158 */	NdrFcShort( 0x54 ),	/* Type Offset=84 */
	/* Parameter dwInVersion */
/* 160 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 162 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 164 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgIn */
/* 166 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 168 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 170 */	NdrFcShort( 0x5c ),	/* Type Offset=92 */
	/* Parameter pdwOutVersion */
/* 172 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 174 */	NdrFcShort( 0xc ),	/* x86 Stack size/offset = 12 */
/* 176 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgOut */
/* 178 */	NdrFcShort( 0x113 ),	/* Flags:  must size, must free, out, simple ref, */
/* 180 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 182 */	NdrFcShort( 0x2ba ),	/* Type Offset=698 */
	/* Return value */
/* 184 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 186 */	NdrFcShort( 0x14 ),	/* x86 Stack size/offset = 20 */
/* 188 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure IDL_DRSCrackNames - 166 */
/* 382 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 384 */	NdrFcLong( 0x0 ),	/* 0 */
/* 388 */	NdrFcShort( 0xc ),	/* 12 */
/* 390 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 392 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 394 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 396 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 398 */	NdrFcShort( 0x2c ),	/* 44 */
/* 400 */	NdrFcShort( 0x24 ),	/* 36 */
/* 402 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x6,		/* 6 */
/* 404 */	0x8,		/* 8 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 406 */	NdrFcShort( 0x1 ),	/* 1 */
/* 408 */	NdrFcShort( 0x1 ),	/* 1 */
/* 410 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter hDrs */
/* 412 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 414 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 416 */	NdrFcShort( 0x54 ),	/* Type Offset=84 */
	/* Parameter dwInVersion */
/* 418 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 420 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 422 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgIn */
/* 424 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 426 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 428 */	NdrFcShort( 0x586 ),	/* Type Offset=1414 */
	/* Parameter pdwOutVersion */
/* 430 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 432 */	NdrFcShort( 0xc ),	/* x86 Stack size/offset = 12 */
/* 434 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgOut */
/* 436 */	NdrFcShort( 0x2113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=8 */
/* 438 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 440 */	NdrFcShort( 0x5e2 ),	/* Type Offset=1506 */
	/* Return value */
/* 442 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 444 */	NdrFcShort( 0x14 ),	/* x86 Stack size/offset = 20 */
/* 446 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure IDL_DRSDomainControllerInfo - 232 */
/* 520 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 522 */	NdrFcLong( 0x0 ),	/* 0 */
/* 526 */	NdrFcShort( 0x10 ),	/* 16 */
/* 528 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 530 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 532 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 534 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 536 */	NdrFcShort( 0x2c ),	/* 44 */
/* 538 */	NdrFcShort( 0x24 ),	/* 36 */
/* 540 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x6,		/* 6 */
/* 542 */	0x8,		/* 8 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 544 */	NdrFcShort( 0x1 ),	/* 1 */
/* 546 */	NdrFcShort( 0x1 ),	/* 1 */
/* 548 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter hDrs */
/* 550 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 552 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 554 */	NdrFcShort( 0x54 ),	/* Type Offset=84 */
	/* Parameter dwInVersion */
/* 556 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 558 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 560 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgIn */
/* 562 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 564 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 566 */	NdrFcShort( 0x66e ),	/* Type Offset=1646 */
	/* Parameter pdwOutVersion */
/* 568 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 570 */	NdrFcShort( 0xc ),	/* x86 Stack size/offset = 12 */
/* 572 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pmsgOut */
/* 574 */	NdrFcShort( 0x2113 ),	/* Flags:  must size, must free, out, simple ref, srv alloc size=8 */
/* 576 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 578 */	NdrFcShort( 0x69c ),	/* Type Offset=1692 */
	/* Return value */
/* 580 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 582 */	NdrFcShort( 0x14 ),	/* x86 Stack size/offset = 20 */
/* 584 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
    };

static const ms2Ddrsr_MIDL_TYPE_FORMAT_STRING ms2Ddrsr__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x0,	/* FC_UP */
/*  4 */	NdrFcShort( 0x8 ),	/* Offset= 8 (12) */
/*  6 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/*  8 */	NdrFcShort( 0x8 ),	/* 8 */
/* 10 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 12 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 14 */	NdrFcShort( 0x10 ),	/* 16 */
/* 16 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 18 */	0x6,		/* FC_SHORT */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 20 */	0x0,		/* 0 */
			NdrFcShort( 0xfff1 ),	/* Offset= -15 (6) */
			0x5b,		/* FC_END */
/* 24 */	
			0x12, 0x0,	/* FC_UP */
/* 26 */	NdrFcShort( 0x18 ),	/* Offset= 24 (50) */
/* 28 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 30 */	NdrFcLong( 0x1 ),	/* 1 */
/* 34 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 38 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 40 */	NdrFcShort( 0x1 ),	/* 1 */
/* 42 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 44 */	NdrFcShort( 0xfffc ),	/* -4 */
/* 46 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 48 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 50 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 52 */	NdrFcShort( 0x4 ),	/* 4 */
/* 54 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (38) */
/* 56 */	NdrFcShort( 0x0 ),	/* Offset= 0 (56) */
/* 58 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 60 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (28) */
/* 62 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 64 */	
			0x11, 0x14,	/* FC_RP [alloced_on_stack] [pointer_deref] */
/* 66 */	NdrFcShort( 0xffd6 ),	/* Offset= -42 (24) */
/* 68 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 70 */	NdrFcShort( 0x2 ),	/* Offset= 2 (72) */
/* 72 */	0x30,		/* FC_BIND_CONTEXT */
			0xa0,		/* Ctxt flags:  via ptr, out, */
/* 74 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 76 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 78 */	NdrFcShort( 0x2 ),	/* Offset= 2 (80) */
/* 80 */	0x30,		/* FC_BIND_CONTEXT */
			0xe1,		/* Ctxt flags:  via ptr, in, out, can't be null */
/* 82 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 84 */	0x30,		/* FC_BIND_CONTEXT */
			0x41,		/* Ctxt flags:  in, can't be null */
/* 86 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 88 */	
			0x11, 0x0,	/* FC_RP */
/* 90 */	NdrFcShort( 0x2 ),	/* Offset= 2 (92) */
/* 92 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 94 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x0,		/*  */
/* 96 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 98 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 100 */	NdrFcShort( 0x2 ),	/* Offset= 2 (102) */
/* 102 */	NdrFcShort( 0x88 ),	/* 136 */
/* 104 */	NdrFcShort( 0x5 ),	/* 5 */
/* 106 */	NdrFcLong( 0x4 ),	/* 4 */
/* 110 */	NdrFcShort( 0x15a ),	/* Offset= 346 (456) */
/* 112 */	NdrFcLong( 0x5 ),	/* 5 */
/* 116 */	NdrFcShort( 0x172 ),	/* Offset= 370 (486) */
/* 118 */	NdrFcLong( 0x7 ),	/* 7 */
/* 122 */	NdrFcShort( 0x1a0 ),	/* Offset= 416 (538) */
/* 124 */	NdrFcLong( 0x8 ),	/* 8 */
/* 128 */	NdrFcShort( 0x1c0 ),	/* Offset= 448 (576) */
/* 130 */	NdrFcLong( 0xa ),	/* 10 */
/* 134 */	NdrFcShort( 0x1f2 ),	/* Offset= 498 (632) */
/* 136 */	NdrFcShort( 0xffff ),	/* Offset= -1 (135) */
/* 138 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 140 */	NdrFcShort( 0x18 ),	/* 24 */
/* 142 */	0xb,		/* FC_HYPER */
			0xb,		/* FC_HYPER */
/* 144 */	0xb,		/* FC_HYPER */
			0x5b,		/* FC_END */
/* 146 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 148 */	NdrFcLong( 0x0 ),	/* 0 */
/* 152 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 156 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 158 */	NdrFcLong( 0x0 ),	/* 0 */
/* 162 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 166 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 168 */	NdrFcShort( 0x1 ),	/* 1 */
/* 170 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 172 */	NdrFcShort( 0x0 ),	/* 0 */
/* 174 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 176 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 178 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 180 */	NdrFcShort( 0x8 ),	/* 8 */
/* 182 */	NdrFcShort( 0x0 ),	/* 0 */
/* 184 */	NdrFcShort( 0x8 ),	/* Offset= 8 (192) */
/* 186 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 188 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (156) */
/* 190 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 192 */	
			0x12, 0x0,	/* FC_UP */
/* 194 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (166) */
/* 196 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 198 */	NdrFcShort( 0xc ),	/* 12 */
/* 200 */	NdrFcShort( 0x0 ),	/* 0 */
/* 202 */	NdrFcShort( 0x0 ),	/* Offset= 0 (202) */
/* 204 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 206 */	0x0,		/* 0 */
			NdrFcShort( 0xffe3 ),	/* Offset= -29 (178) */
			0x5b,		/* FC_END */
/* 210 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 212 */	NdrFcShort( 0x0 ),	/* 0 */
/* 214 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 216 */	NdrFcShort( 0x0 ),	/* 0 */
/* 218 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 220 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 224 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 226 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 228 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (196) */
/* 230 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 232 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 234 */	NdrFcShort( 0x8 ),	/* 8 */
/* 236 */	NdrFcShort( 0x0 ),	/* 0 */
/* 238 */	NdrFcShort( 0x8 ),	/* Offset= 8 (246) */
/* 240 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 242 */	NdrFcShort( 0xffa0 ),	/* Offset= -96 (146) */
/* 244 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 246 */	
			0x12, 0x0,	/* FC_UP */
/* 248 */	NdrFcShort( 0xffda ),	/* Offset= -38 (210) */
/* 250 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 252 */	NdrFcShort( 0x1c ),	/* 28 */
/* 254 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 256 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 258 */	NdrFcShort( 0x1c ),	/* 28 */
/* 260 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 262 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (250) */
/* 264 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 266 */	
			0x1b,		/* FC_CARRAY */
			0x1,		/* 1 */
/* 268 */	NdrFcShort( 0x2 ),	/* 2 */
/* 270 */	0x9,		/* Corr desc: FC_ULONG */
			0x57,		/* FC_ADD_1 */
/* 272 */	NdrFcShort( 0xfffc ),	/* -4 */
/* 274 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 276 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 278 */	
			0x17,		/* FC_CSTRUCT */
			0x3,		/* 3 */
/* 280 */	NdrFcShort( 0x38 ),	/* 56 */
/* 282 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (266) */
/* 284 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 286 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 288 */	NdrFcShort( 0xfeec ),	/* Offset= -276 (12) */
/* 290 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 292 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (256) */
/* 294 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 296 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 298 */	NdrFcLong( 0x0 ),	/* 0 */
/* 302 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 306 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 308 */	NdrFcShort( 0x18 ),	/* 24 */
/* 310 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 312 */	NdrFcShort( 0xfed4 ),	/* Offset= -300 (12) */
/* 314 */	0xb,		/* FC_HYPER */
			0x5b,		/* FC_END */
/* 316 */	
			0x1b,		/* FC_CARRAY */
			0x7,		/* 7 */
/* 318 */	NdrFcShort( 0x18 ),	/* 24 */
/* 320 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 322 */	NdrFcShort( 0xfff8 ),	/* -8 */
/* 324 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 326 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 328 */	NdrFcShort( 0xffea ),	/* Offset= -22 (306) */
/* 330 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 332 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 334 */	NdrFcShort( 0x10 ),	/* 16 */
/* 336 */	NdrFcShort( 0xffec ),	/* Offset= -20 (316) */
/* 338 */	NdrFcShort( 0x0 ),	/* Offset= 0 (338) */
/* 340 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 342 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 344 */	NdrFcShort( 0xffd0 ),	/* Offset= -48 (296) */
/* 346 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 348 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 350 */	NdrFcLong( 0x1 ),	/* 1 */
/* 354 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 358 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 360 */	NdrFcShort( 0x4 ),	/* 4 */
/* 362 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 364 */	NdrFcShort( 0xfffc ),	/* -4 */
/* 366 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 368 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 370 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 372 */	NdrFcShort( 0xc ),	/* 12 */
/* 374 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (358) */
/* 376 */	NdrFcShort( 0x0 ),	/* Offset= 0 (376) */
/* 378 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 380 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 382 */	NdrFcShort( 0xffde ),	/* Offset= -34 (348) */
/* 384 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 386 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 388 */	NdrFcShort( 0x60 ),	/* 96 */
/* 390 */	NdrFcShort( 0x0 ),	/* 0 */
/* 392 */	NdrFcShort( 0x1c ),	/* Offset= 28 (420) */
/* 394 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 396 */	NdrFcShort( 0xfe80 ),	/* Offset= -384 (12) */
/* 398 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 400 */	NdrFcShort( 0xfe7c ),	/* Offset= -388 (12) */
/* 402 */	0x36,		/* FC_POINTER */
			0x40,		/* FC_STRUCTPAD4 */
/* 404 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 406 */	NdrFcShort( 0xfef4 ),	/* Offset= -268 (138) */
/* 408 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 410 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 412 */	NdrFcShort( 0xff4c ),	/* Offset= -180 (232) */
/* 414 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 416 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 418 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 420 */	
			0x11, 0x0,	/* FC_RP */
/* 422 */	NdrFcShort( 0xff70 ),	/* Offset= -144 (278) */
/* 424 */	
			0x12, 0x0,	/* FC_UP */
/* 426 */	NdrFcShort( 0xffa2 ),	/* Offset= -94 (332) */
/* 428 */	
			0x12, 0x0,	/* FC_UP */
/* 430 */	NdrFcShort( 0xffc4 ),	/* Offset= -60 (370) */
/* 432 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 434 */	NdrFcLong( 0x1 ),	/* 1 */
/* 438 */	NdrFcLong( 0x100 ),	/* 256 */
/* 442 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 444 */	NdrFcShort( 0x4 ),	/* 4 */
/* 446 */	NdrFcShort( 0xfe68 ),	/* Offset= -408 (38) */
/* 448 */	NdrFcShort( 0x0 ),	/* Offset= 0 (448) */
/* 450 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 452 */	NdrFcShort( 0xffec ),	/* Offset= -20 (432) */
/* 454 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 456 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 458 */	NdrFcShort( 0x78 ),	/* 120 */
/* 460 */	NdrFcShort( 0x0 ),	/* 0 */
/* 462 */	NdrFcShort( 0xe ),	/* Offset= 14 (476) */
/* 464 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 466 */	NdrFcShort( 0xfe3a ),	/* Offset= -454 (12) */
/* 468 */	0x36,		/* FC_POINTER */
			0x40,		/* FC_STRUCTPAD4 */
/* 470 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 472 */	NdrFcShort( 0xffaa ),	/* Offset= -86 (386) */
/* 474 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 476 */	
			0x11, 0x0,	/* FC_RP */
/* 478 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (442) */
/* 480 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 482 */	NdrFcShort( 0x8 ),	/* 8 */
/* 484 */	0xb,		/* FC_HYPER */
			0x5b,		/* FC_END */
/* 486 */	
			0x16,		/* FC_PSTRUCT */
			0x7,		/* 7 */
/* 488 */	NdrFcShort( 0x60 ),	/* 96 */
/* 490 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 492 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 494 */	NdrFcShort( 0x20 ),	/* 32 */
/* 496 */	NdrFcShort( 0x20 ),	/* 32 */
/* 498 */	0x11, 0x0,	/* FC_RP */
/* 500 */	NdrFcShort( 0xff22 ),	/* Offset= -222 (278) */
/* 502 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 504 */	NdrFcShort( 0x40 ),	/* 64 */
/* 506 */	NdrFcShort( 0x40 ),	/* 64 */
/* 508 */	0x12, 0x0,	/* FC_UP */
/* 510 */	NdrFcShort( 0xff4e ),	/* Offset= -178 (332) */
/* 512 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 514 */	0x0,		/* 0 */
			NdrFcShort( 0xfe09 ),	/* Offset= -503 (12) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 518 */	0x0,		/* 0 */
			NdrFcShort( 0xfe05 ),	/* Offset= -507 (12) */
			0x8,		/* FC_LONG */
/* 522 */	0x40,		/* FC_STRUCTPAD4 */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 524 */	0x0,		/* 0 */
			NdrFcShort( 0xfe7d ),	/* Offset= -387 (138) */
			0x8,		/* FC_LONG */
/* 528 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 530 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 532 */	0x40,		/* FC_STRUCTPAD4 */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 534 */	0x0,		/* 0 */
			NdrFcShort( 0xffc9 ),	/* Offset= -55 (480) */
			0x5b,		/* FC_END */
/* 538 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 540 */	NdrFcShort( 0x88 ),	/* 136 */
/* 542 */	NdrFcShort( 0x0 ),	/* 0 */
/* 544 */	NdrFcShort( 0x14 ),	/* Offset= 20 (564) */
/* 546 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 548 */	NdrFcShort( 0xfde8 ),	/* Offset= -536 (12) */
/* 550 */	0x36,		/* FC_POINTER */
			0x40,		/* FC_STRUCTPAD4 */
/* 552 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 554 */	NdrFcShort( 0xff58 ),	/* Offset= -168 (386) */
/* 556 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 558 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 560 */	NdrFcShort( 0xfeb8 ),	/* Offset= -328 (232) */
/* 562 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 564 */	
			0x11, 0x0,	/* FC_RP */
/* 566 */	NdrFcShort( 0xff84 ),	/* Offset= -124 (442) */
/* 568 */	
			0x12, 0x0,	/* FC_UP */
/* 570 */	NdrFcShort( 0xff38 ),	/* Offset= -200 (370) */
/* 572 */	
			0x12, 0x0,	/* FC_UP */
/* 574 */	NdrFcShort( 0xff34 ),	/* Offset= -204 (370) */
/* 576 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 578 */	NdrFcShort( 0x70 ),	/* 112 */
/* 580 */	NdrFcShort( 0x0 ),	/* 0 */
/* 582 */	NdrFcShort( 0x22 ),	/* Offset= 34 (616) */
/* 584 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 586 */	NdrFcShort( 0xfdc2 ),	/* Offset= -574 (12) */
/* 588 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 590 */	NdrFcShort( 0xfdbe ),	/* Offset= -578 (12) */
/* 592 */	0x36,		/* FC_POINTER */
			0x40,		/* FC_STRUCTPAD4 */
/* 594 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 596 */	NdrFcShort( 0xfe36 ),	/* Offset= -458 (138) */
/* 598 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 600 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 602 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 604 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 606 */	NdrFcShort( 0xff82 ),	/* Offset= -126 (480) */
/* 608 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 610 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 612 */	NdrFcShort( 0xfe84 ),	/* Offset= -380 (232) */
/* 614 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 616 */	
			0x11, 0x0,	/* FC_RP */
/* 618 */	NdrFcShort( 0xfeac ),	/* Offset= -340 (278) */
/* 620 */	
			0x12, 0x0,	/* FC_UP */
/* 622 */	NdrFcShort( 0xfede ),	/* Offset= -290 (332) */
/* 624 */	
			0x12, 0x0,	/* FC_UP */
/* 626 */	NdrFcShort( 0xff00 ),	/* Offset= -256 (370) */
/* 628 */	
			0x12, 0x0,	/* FC_UP */
/* 630 */	NdrFcShort( 0xfefc ),	/* Offset= -260 (370) */
/* 632 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 634 */	NdrFcShort( 0x78 ),	/* 120 */
/* 636 */	NdrFcShort( 0x0 ),	/* 0 */
/* 638 */	NdrFcShort( 0x24 ),	/* Offset= 36 (674) */
/* 640 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 642 */	NdrFcShort( 0xfd8a ),	/* Offset= -630 (12) */
/* 644 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 646 */	NdrFcShort( 0xfd86 ),	/* Offset= -634 (12) */
/* 648 */	0x36,		/* FC_POINTER */
			0x40,		/* FC_STRUCTPAD4 */
/* 650 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 652 */	NdrFcShort( 0xfdfe ),	/* Offset= -514 (138) */
/* 654 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 656 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 658 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 660 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 662 */	NdrFcShort( 0xff4a ),	/* Offset= -182 (480) */
/* 664 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 666 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 668 */	NdrFcShort( 0xfe4c ),	/* Offset= -436 (232) */
/* 670 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 672 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 674 */	
			0x11, 0x0,	/* FC_RP */
/* 676 */	NdrFcShort( 0xfe72 ),	/* Offset= -398 (278) */
/* 678 */	
			0x12, 0x0,	/* FC_UP */
/* 680 */	NdrFcShort( 0xfea4 ),	/* Offset= -348 (332) */
/* 682 */	
			0x12, 0x0,	/* FC_UP */
/* 684 */	NdrFcShort( 0xfec6 ),	/* Offset= -314 (370) */
/* 686 */	
			0x12, 0x0,	/* FC_UP */
/* 688 */	NdrFcShort( 0xfec2 ),	/* Offset= -318 (370) */
/* 690 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/* 692 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */
/* 694 */	
			0x11, 0x0,	/* FC_RP */
/* 696 */	NdrFcShort( 0x2 ),	/* Offset= 2 (698) */
/* 698 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 700 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x54,		/* FC_DEREFERENCE */
/* 702 */	NdrFcShort( 0xc ),	/* x86 Stack size/offset = 12 */
/* 704 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 706 */	NdrFcShort( 0x2 ),	/* Offset= 2 (708) */
/* 708 */	NdrFcShort( 0x90 ),	/* 144 */
/* 710 */	NdrFcShort( 0x5 ),	/* 5 */
/* 712 */	NdrFcLong( 0x1 ),	/* 1 */
/* 716 */	NdrFcShort( 0x112 ),	/* Offset= 274 (990) */
/* 718 */	NdrFcLong( 0x2 ),	/* 2 */
/* 722 */	NdrFcShort( 0x14a ),	/* Offset= 330 (1052) */
/* 724 */	NdrFcLong( 0x6 ),	/* 6 */
/* 728 */	NdrFcShort( 0x1d4 ),	/* Offset= 468 (1196) */
/* 730 */	NdrFcLong( 0x7 ),	/* 7 */
/* 734 */	NdrFcShort( 0x20c ),	/* Offset= 524 (1258) */
/* 736 */	NdrFcLong( 0x9 ),	/* 9 */
/* 740 */	NdrFcShort( 0x260 ),	/* Offset= 608 (1348) */
/* 742 */	NdrFcShort( 0xffff ),	/* Offset= -1 (741) */
/* 744 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 746 */	NdrFcLong( 0x0 ),	/* 0 */
/* 750 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 754 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 756 */	NdrFcLong( 0x0 ),	/* 0 */
/* 760 */	NdrFcLong( 0xa00000 ),	/* 10485760 */
/* 764 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 766 */	NdrFcLong( 0x0 ),	/* 0 */
/* 770 */	NdrFcLong( 0x1900000 ),	/* 26214400 */
/* 774 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 776 */	NdrFcShort( 0x8 ),	/* 8 */
/* 778 */	NdrFcShort( 0x0 ),	/* 0 */
/* 780 */	NdrFcShort( 0x8 ),	/* Offset= 8 (788) */
/* 782 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 784 */	NdrFcShort( 0xffec ),	/* Offset= -20 (764) */
/* 786 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 788 */	
			0x12, 0x0,	/* FC_UP */
/* 790 */	NdrFcShort( 0xfd90 ),	/* Offset= -624 (166) */
/* 792 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 794 */	NdrFcShort( 0x0 ),	/* 0 */
/* 796 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 798 */	NdrFcShort( 0x0 ),	/* 0 */
/* 800 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 802 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 806 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 808 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 810 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (774) */
/* 812 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 814 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 816 */	NdrFcShort( 0x8 ),	/* 8 */
/* 818 */	NdrFcShort( 0x0 ),	/* 0 */
/* 820 */	NdrFcShort( 0x8 ),	/* Offset= 8 (828) */
/* 822 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 824 */	NdrFcShort( 0xffba ),	/* Offset= -70 (754) */
/* 826 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 828 */	
			0x12, 0x0,	/* FC_UP */
/* 830 */	NdrFcShort( 0xffda ),	/* Offset= -38 (792) */
/* 832 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 834 */	NdrFcShort( 0xc ),	/* 12 */
/* 836 */	NdrFcShort( 0x0 ),	/* 0 */
/* 838 */	NdrFcShort( 0x0 ),	/* Offset= 0 (838) */
/* 840 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 842 */	0x0,		/* 0 */
			NdrFcShort( 0xffe3 ),	/* Offset= -29 (814) */
			0x5b,		/* FC_END */
/* 846 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 848 */	NdrFcShort( 0x0 ),	/* 0 */
/* 850 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 852 */	NdrFcShort( 0x0 ),	/* 0 */
/* 854 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 856 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 860 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 862 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 864 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (832) */
/* 866 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 868 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 870 */	NdrFcShort( 0x8 ),	/* 8 */
/* 872 */	NdrFcShort( 0x0 ),	/* 0 */
/* 874 */	NdrFcShort( 0x8 ),	/* Offset= 8 (882) */
/* 876 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 878 */	NdrFcShort( 0xff7a ),	/* Offset= -134 (744) */
/* 880 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 882 */	
			0x12, 0x0,	/* FC_UP */
/* 884 */	NdrFcShort( 0xffda ),	/* Offset= -38 (846) */
/* 886 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 888 */	NdrFcShort( 0x10 ),	/* 16 */
/* 890 */	NdrFcShort( 0x0 ),	/* 0 */
/* 892 */	NdrFcShort( 0xa ),	/* Offset= 10 (902) */
/* 894 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 896 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 898 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (868) */
/* 900 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 902 */	
			0x12, 0x0,	/* FC_UP */
/* 904 */	NdrFcShort( 0xfd8e ),	/* Offset= -626 (278) */
/* 906 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 908 */	NdrFcLong( 0x0 ),	/* 0 */
/* 912 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 916 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 918 */	NdrFcShort( 0x28 ),	/* 40 */
/* 920 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 922 */	0xb,		/* FC_HYPER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 924 */	0x0,		/* 0 */
			NdrFcShort( 0xfc6f ),	/* Offset= -913 (12) */
			0xb,		/* FC_HYPER */
/* 928 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 930 */	
			0x1b,		/* FC_CARRAY */
			0x7,		/* 7 */
/* 932 */	NdrFcShort( 0x28 ),	/* 40 */
/* 934 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 936 */	NdrFcShort( 0xfff8 ),	/* -8 */
/* 938 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 940 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 942 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (916) */
/* 944 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 946 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 948 */	NdrFcShort( 0x8 ),	/* 8 */
/* 950 */	NdrFcShort( 0xffec ),	/* Offset= -20 (930) */
/* 952 */	NdrFcShort( 0x0 ),	/* Offset= 0 (952) */
/* 954 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 956 */	NdrFcShort( 0xffce ),	/* Offset= -50 (906) */
/* 958 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 960 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 962 */	NdrFcShort( 0x20 ),	/* 32 */
/* 964 */	NdrFcShort( 0x0 ),	/* 0 */
/* 966 */	NdrFcShort( 0xc ),	/* Offset= 12 (978) */
/* 968 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 970 */	0x0,		/* 0 */
			NdrFcShort( 0xffab ),	/* Offset= -85 (886) */
			0x8,		/* FC_LONG */
/* 974 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 976 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 978 */	
			0x12, 0x0,	/* FC_UP */
/* 980 */	NdrFcShort( 0xffec ),	/* Offset= -20 (960) */
/* 982 */	
			0x12, 0x0,	/* FC_UP */
/* 984 */	NdrFcShort( 0xfc34 ),	/* Offset= -972 (12) */
/* 986 */	
			0x12, 0x0,	/* FC_UP */
/* 988 */	NdrFcShort( 0xffd6 ),	/* Offset= -42 (946) */
/* 990 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 992 */	NdrFcShort( 0x78 ),	/* 120 */
/* 994 */	NdrFcShort( 0x0 ),	/* 0 */
/* 996 */	NdrFcShort( 0x20 ),	/* Offset= 32 (1028) */
/* 998 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1000 */	NdrFcShort( 0xfc24 ),	/* Offset= -988 (12) */
/* 1002 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1004 */	NdrFcShort( 0xfc20 ),	/* Offset= -992 (12) */
/* 1006 */	0x36,		/* FC_POINTER */
			0x40,		/* FC_STRUCTPAD4 */
/* 1008 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1010 */	NdrFcShort( 0xfc98 ),	/* Offset= -872 (138) */
/* 1012 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1014 */	NdrFcShort( 0xfc94 ),	/* Offset= -876 (138) */
/* 1016 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1018 */	0x0,		/* 0 */
			NdrFcShort( 0xfced ),	/* Offset= -787 (232) */
			0x8,		/* FC_LONG */
/* 1022 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1024 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1026 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1028 */	
			0x12, 0x0,	/* FC_UP */
/* 1030 */	NdrFcShort( 0xfd10 ),	/* Offset= -752 (278) */
/* 1032 */	
			0x12, 0x0,	/* FC_UP */
/* 1034 */	NdrFcShort( 0xfd42 ),	/* Offset= -702 (332) */
/* 1036 */	
			0x12, 0x0,	/* FC_UP */
/* 1038 */	NdrFcShort( 0xffb2 ),	/* Offset= -78 (960) */
/* 1040 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 1042 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1044 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1046 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1048 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1050 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 1052 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 1054 */	NdrFcShort( 0xc ),	/* 12 */
/* 1056 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 1058 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1060 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1062 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1064 */	0x12, 0x0,	/* FC_UP */
/* 1066 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (1040) */
/* 1068 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 1070 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1072 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1074 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1076 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1080 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 1084 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1086 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1090 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 1094 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 1096 */	NdrFcShort( 0x20 ),	/* 32 */
/* 1098 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1100 */	NdrFcShort( 0xfbc0 ),	/* Offset= -1088 (12) */
/* 1102 */	0xb,		/* FC_HYPER */
			0xb,		/* FC_HYPER */
/* 1104 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1106 */	
			0x1b,		/* FC_CARRAY */
			0x7,		/* 7 */
/* 1108 */	NdrFcShort( 0x20 ),	/* 32 */
/* 1110 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 1112 */	NdrFcShort( 0xfff8 ),	/* -8 */
/* 1114 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1116 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1118 */	NdrFcShort( 0xffe8 ),	/* Offset= -24 (1094) */
/* 1120 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1122 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 1124 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1126 */	NdrFcShort( 0xffec ),	/* Offset= -20 (1106) */
/* 1128 */	NdrFcShort( 0x0 ),	/* Offset= 0 (1128) */
/* 1130 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1132 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1134 */	NdrFcShort( 0xffce ),	/* Offset= -50 (1084) */
/* 1136 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 1138 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 1140 */	NdrFcShort( 0x30 ),	/* 48 */
/* 1142 */	0xb,		/* FC_HYPER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1144 */	0x0,		/* 0 */
			NdrFcShort( 0xff1b ),	/* Offset= -229 (916) */
			0x5b,		/* FC_END */
/* 1148 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 1150 */	NdrFcShort( 0x48 ),	/* 72 */
/* 1152 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1154 */	NdrFcShort( 0x10 ),	/* Offset= 16 (1170) */
/* 1156 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1158 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1160 */	NdrFcShort( 0xfe7e ),	/* Offset= -386 (774) */
/* 1162 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 1164 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1166 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (1138) */
/* 1168 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1170 */	
			0x12, 0x0,	/* FC_UP */
/* 1172 */	NdrFcShort( 0xfc82 ),	/* Offset= -894 (278) */
/* 1174 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x7,		/* 7 */
/* 1176 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1178 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1180 */	NdrFcShort( 0x80 ),	/* 128 */
/* 1182 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1184 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1188 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 1190 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1192 */	NdrFcShort( 0xffd4 ),	/* Offset= -44 (1148) */
/* 1194 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1196 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 1198 */	NdrFcShort( 0x90 ),	/* 144 */
/* 1200 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1202 */	NdrFcShort( 0x28 ),	/* Offset= 40 (1242) */
/* 1204 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1206 */	NdrFcShort( 0xfb56 ),	/* Offset= -1194 (12) */
/* 1208 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1210 */	NdrFcShort( 0xfb52 ),	/* Offset= -1198 (12) */
/* 1212 */	0x36,		/* FC_POINTER */
			0x40,		/* FC_STRUCTPAD4 */
/* 1214 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1216 */	NdrFcShort( 0xfbca ),	/* Offset= -1078 (138) */
/* 1218 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1220 */	NdrFcShort( 0xfbc6 ),	/* Offset= -1082 (138) */
/* 1222 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1224 */	0x0,		/* 0 */
			NdrFcShort( 0xfc1f ),	/* Offset= -993 (232) */
			0x8,		/* FC_LONG */
/* 1228 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1230 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1232 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1234 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1236 */	NdrFcShort( 0xff5e ),	/* Offset= -162 (1074) */
/* 1238 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1240 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 1242 */	
			0x12, 0x0,	/* FC_UP */
/* 1244 */	NdrFcShort( 0xfc3a ),	/* Offset= -966 (278) */
/* 1246 */	
			0x12, 0x0,	/* FC_UP */
/* 1248 */	NdrFcShort( 0xff82 ),	/* Offset= -126 (1122) */
/* 1250 */	
			0x12, 0x0,	/* FC_UP */
/* 1252 */	NdrFcShort( 0xfedc ),	/* Offset= -292 (960) */
/* 1254 */	
			0x12, 0x0,	/* FC_UP */
/* 1256 */	NdrFcShort( 0xffae ),	/* Offset= -82 (1174) */
/* 1258 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1260 */	NdrFcShort( 0x14 ),	/* 20 */
/* 1262 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1264 */	NdrFcShort( 0x0 ),	/* Offset= 0 (1264) */
/* 1266 */	0x8,		/* FC_LONG */
			0xd,		/* FC_ENUM16 */
/* 1268 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1270 */	NdrFcShort( 0xff26 ),	/* Offset= -218 (1052) */
/* 1272 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1274 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1276 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1280 */	NdrFcLong( 0x100000 ),	/* 1048576 */
/* 1284 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 1286 */	NdrFcShort( 0x48 ),	/* 72 */
/* 1288 */	0xb,		/* FC_HYPER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1290 */	0x0,		/* 0 */
			NdrFcShort( 0xfe89 ),	/* Offset= -375 (916) */
			0x8,		/* FC_LONG */
/* 1294 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1296 */	0x40,		/* FC_STRUCTPAD4 */
			0xb,		/* FC_HYPER */
/* 1298 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1300 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 1302 */	NdrFcShort( 0x60 ),	/* 96 */
/* 1304 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1306 */	NdrFcShort( 0x10 ),	/* Offset= 16 (1322) */
/* 1308 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1310 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1312 */	NdrFcShort( 0xfde6 ),	/* Offset= -538 (774) */
/* 1314 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 1316 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1318 */	NdrFcShort( 0xffde ),	/* Offset= -34 (1284) */
/* 1320 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1322 */	
			0x12, 0x0,	/* FC_UP */
/* 1324 */	NdrFcShort( 0xfbea ),	/* Offset= -1046 (278) */
/* 1326 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x7,		/* 7 */
/* 1328 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1330 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1332 */	NdrFcShort( 0x80 ),	/* 128 */
/* 1334 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1336 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1340 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 1342 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1344 */	NdrFcShort( 0xffd4 ),	/* Offset= -44 (1300) */
/* 1346 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1348 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 1350 */	NdrFcShort( 0x90 ),	/* 144 */
/* 1352 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1354 */	NdrFcShort( 0x28 ),	/* Offset= 40 (1394) */
/* 1356 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1358 */	NdrFcShort( 0xfabe ),	/* Offset= -1346 (12) */
/* 1360 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1362 */	NdrFcShort( 0xfaba ),	/* Offset= -1350 (12) */
/* 1364 */	0x36,		/* FC_POINTER */
			0x40,		/* FC_STRUCTPAD4 */
/* 1366 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1368 */	NdrFcShort( 0xfb32 ),	/* Offset= -1230 (138) */
/* 1370 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1372 */	NdrFcShort( 0xfb2e ),	/* Offset= -1234 (138) */
/* 1374 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1376 */	0x0,		/* 0 */
			NdrFcShort( 0xfb87 ),	/* Offset= -1145 (232) */
			0x8,		/* FC_LONG */
/* 1380 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1382 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1384 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1386 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1388 */	NdrFcShort( 0xff8e ),	/* Offset= -114 (1274) */
/* 1390 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 1392 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 1394 */	
			0x12, 0x0,	/* FC_UP */
/* 1396 */	NdrFcShort( 0xfba2 ),	/* Offset= -1118 (278) */
/* 1398 */	
			0x12, 0x0,	/* FC_UP */
/* 1400 */	NdrFcShort( 0xfeea ),	/* Offset= -278 (1122) */
/* 1402 */	
			0x12, 0x0,	/* FC_UP */
/* 1404 */	NdrFcShort( 0xfe44 ),	/* Offset= -444 (960) */
/* 1406 */	
			0x12, 0x0,	/* FC_UP */
/* 1408 */	NdrFcShort( 0xffae ),	/* Offset= -82 (1326) */
/* 1410 */	
			0x11, 0x0,	/* FC_RP */
/* 1412 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1414) */
/* 1414 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 1416 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x0,		/*  */
/* 1418 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 1420 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1422 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1424) */
/* 1424 */	NdrFcShort( 0x1c ),	/* 28 */
/* 1426 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1428 */	NdrFcLong( 0x1 ),	/* 1 */
/* 1432 */	NdrFcShort( 0x2e ),	/* Offset= 46 (1478) */
/* 1434 */	NdrFcShort( 0xffff ),	/* Offset= -1 (1433) */
/* 1436 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1438 */	NdrFcLong( 0x1 ),	/* 1 */
/* 1442 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 1446 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 1448 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1450 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1452 */	NdrFcShort( 0x14 ),	/* 20 */
/* 1454 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1456 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 1458 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 1460 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1462 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1464 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1466 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1468 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1470 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1472 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1474 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 1476 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1478 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1480 */	NdrFcShort( 0x1c ),	/* 28 */
/* 1482 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1484 */	NdrFcShort( 0xe ),	/* Offset= 14 (1498) */
/* 1486 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1488 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1490 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1492 */	0x0,		/* 0 */
			NdrFcShort( 0xffc7 ),	/* Offset= -57 (1436) */
			0x36,		/* FC_POINTER */
/* 1496 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1498 */	
			0x12, 0x0,	/* FC_UP */
/* 1500 */	NdrFcShort( 0xffca ),	/* Offset= -54 (1446) */
/* 1502 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 1504 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1506) */
/* 1506 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 1508 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x54,		/* FC_DEREFERENCE */
/* 1510 */	NdrFcShort( 0xc ),	/* x86 Stack size/offset = 12 */
/* 1512 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1514 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1516) */
/* 1516 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1518 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1520 */	NdrFcLong( 0x1 ),	/* 1 */
/* 1524 */	NdrFcShort( 0x62 ),	/* Offset= 98 (1622) */
/* 1526 */	NdrFcShort( 0xffff ),	/* Offset= -1 (1525) */
/* 1528 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 1530 */	NdrFcShort( 0xc ),	/* 12 */
/* 1532 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 1534 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1536 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1538 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1540 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1542 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1544 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1546 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1548 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1550 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1552 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1554 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 1556 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1558 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1560 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 1562 */	NdrFcShort( 0xc ),	/* 12 */
/* 1564 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1566 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1568 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1570 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 1572 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 1574 */	NdrFcShort( 0xc ),	/* 12 */
/* 1576 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1578 */	NdrFcShort( 0x2 ),	/* 2 */
/* 1580 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1582 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1584 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1586 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1588 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1590 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1592 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1594 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1596 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1598 */	0x0,		/* 0 */
			NdrFcShort( 0xffb9 ),	/* Offset= -71 (1528) */
			0x5b,		/* FC_END */
/* 1602 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 1604 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1606 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 1608 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1610 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1612 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1614 */	0x12, 0x0,	/* FC_UP */
/* 1616 */	NdrFcShort( 0xffc8 ),	/* Offset= -56 (1560) */
/* 1618 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 1620 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 1622 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 1624 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1626 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 1628 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1630 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1632 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1634 */	0x12, 0x0,	/* FC_UP */
/* 1636 */	NdrFcShort( 0xffde ),	/* Offset= -34 (1602) */
/* 1638 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 1640 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1642 */	
			0x11, 0x0,	/* FC_RP */
/* 1644 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1646) */
/* 1646 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 1648 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x0,		/*  */
/* 1650 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 1652 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1654 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1656) */
/* 1656 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1658 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1660 */	NdrFcLong( 0x1 ),	/* 1 */
/* 1664 */	NdrFcShort( 0x4 ),	/* Offset= 4 (1668) */
/* 1666 */	NdrFcShort( 0xffff ),	/* Offset= -1 (1665) */
/* 1668 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 1670 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1672 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 1674 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1676 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1678 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1680 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1682 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1684 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 1686 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 1688 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 1690 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1692) */
/* 1692 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 1694 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x54,		/* FC_DEREFERENCE */
/* 1696 */	NdrFcShort( 0xc ),	/* x86 Stack size/offset = 12 */
/* 1698 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1700 */	NdrFcShort( 0x2 ),	/* Offset= 2 (1702) */
/* 1702 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1704 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1706 */	NdrFcLong( 0x1 ),	/* 1 */
/* 1710 */	NdrFcShort( 0xa4 ),	/* Offset= 164 (1874) */
/* 1712 */	NdrFcLong( 0x2 ),	/* 2 */
/* 1716 */	NdrFcShort( 0x174 ),	/* Offset= 372 (2088) */
/* 1718 */	NdrFcLong( 0x3 ),	/* 3 */
/* 1722 */	NdrFcShort( 0x246 ),	/* Offset= 582 (2304) */
/* 1724 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 1728 */	NdrFcShort( 0x298 ),	/* Offset= 664 (2392) */
/* 1730 */	NdrFcShort( 0xffff ),	/* Offset= -1 (1729) */
/* 1732 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1734 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1738 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 1742 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 1744 */	NdrFcShort( 0x1c ),	/* 28 */
/* 1746 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 1748 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1750 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1752 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1754 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1756 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1758 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1760 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1762 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1764 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1766 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1768 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1770 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1772 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1774 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1776 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1778 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1780 */	NdrFcShort( 0xc ),	/* 12 */
/* 1782 */	NdrFcShort( 0xc ),	/* 12 */
/* 1784 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1786 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1788 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1790 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1792 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1794 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1796 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1798 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 1800 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1802 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1804 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1806 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 1808 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 1810 */	NdrFcShort( 0x1c ),	/* 28 */
/* 1812 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 1814 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1816 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 1818 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 1820 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 1822 */	NdrFcShort( 0x1c ),	/* 28 */
/* 1824 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1826 */	NdrFcShort( 0x5 ),	/* 5 */
/* 1828 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1830 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1832 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1834 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1836 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1838 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1840 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1842 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1844 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1846 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1848 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1850 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1852 */	NdrFcShort( 0xc ),	/* 12 */
/* 1854 */	NdrFcShort( 0xc ),	/* 12 */
/* 1856 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1858 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1860 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1862 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1864 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1866 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1868 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1870 */	0x0,		/* 0 */
			NdrFcShort( 0xff7f ),	/* Offset= -129 (1742) */
			0x5b,		/* FC_END */
/* 1874 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 1876 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1878 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1880 */	NdrFcShort( 0x8 ),	/* Offset= 8 (1888) */
/* 1882 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 1884 */	NdrFcShort( 0xff68 ),	/* Offset= -152 (1732) */
/* 1886 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 1888 */	
			0x12, 0x0,	/* FC_UP */
/* 1890 */	NdrFcShort( 0xffae ),	/* Offset= -82 (1808) */
/* 1892 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 1894 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1898 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 1902 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 1904 */	NdrFcShort( 0x68 ),	/* 104 */
/* 1906 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 1908 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1910 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1912 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1914 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1916 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1918 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1920 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1922 */	NdrFcShort( 0x4 ),	/* 4 */
/* 1924 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1926 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1928 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1930 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1932 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1934 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1936 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1938 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1940 */	NdrFcShort( 0xc ),	/* 12 */
/* 1942 */	NdrFcShort( 0xc ),	/* 12 */
/* 1944 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1946 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1948 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1950 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1952 */	NdrFcShort( 0x10 ),	/* 16 */
/* 1954 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1956 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1958 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1960 */	NdrFcShort( 0x14 ),	/* 20 */
/* 1962 */	NdrFcShort( 0x14 ),	/* 20 */
/* 1964 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1966 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1968 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 1970 */	NdrFcShort( 0x18 ),	/* 24 */
/* 1972 */	NdrFcShort( 0x18 ),	/* 24 */
/* 1974 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 1976 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 1978 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 1980 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1982 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1984 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1986 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 1988 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1990 */	0x0,		/* 0 */
			NdrFcShort( 0xf845 ),	/* Offset= -1979 (12) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1994 */	0x0,		/* 0 */
			NdrFcShort( 0xf841 ),	/* Offset= -1983 (12) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 1998 */	0x0,		/* 0 */
			NdrFcShort( 0xf83d ),	/* Offset= -1987 (12) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 2002 */	0x0,		/* 0 */
			NdrFcShort( 0xf839 ),	/* Offset= -1991 (12) */
			0x5b,		/* FC_END */
/* 2006 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 2008 */	NdrFcShort( 0x68 ),	/* 104 */
/* 2010 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 2012 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2014 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 2016 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 2018 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 2020 */	NdrFcShort( 0x68 ),	/* 104 */
/* 2022 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2024 */	NdrFcShort( 0x7 ),	/* 7 */
/* 2026 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2028 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2030 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2032 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2034 */	NdrFcShort( 0x4 ),	/* 4 */
/* 2036 */	NdrFcShort( 0x4 ),	/* 4 */
/* 2038 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2040 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2042 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2044 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2046 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2048 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2050 */	NdrFcShort( 0xc ),	/* 12 */
/* 2052 */	NdrFcShort( 0xc ),	/* 12 */
/* 2054 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2056 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2058 */	NdrFcShort( 0x10 ),	/* 16 */
/* 2060 */	NdrFcShort( 0x10 ),	/* 16 */
/* 2062 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2064 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2066 */	NdrFcShort( 0x14 ),	/* 20 */
/* 2068 */	NdrFcShort( 0x14 ),	/* 20 */
/* 2070 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2072 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2074 */	NdrFcShort( 0x18 ),	/* 24 */
/* 2076 */	NdrFcShort( 0x18 ),	/* 24 */
/* 2078 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2080 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2082 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 2084 */	0x0,		/* 0 */
			NdrFcShort( 0xff49 ),	/* Offset= -183 (1902) */
			0x5b,		/* FC_END */
/* 2088 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 2090 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2092 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2094 */	NdrFcShort( 0x8 ),	/* Offset= 8 (2102) */
/* 2096 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 2098 */	NdrFcShort( 0xff32 ),	/* Offset= -206 (1892) */
/* 2100 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 2102 */	
			0x12, 0x0,	/* FC_UP */
/* 2104 */	NdrFcShort( 0xff9e ),	/* Offset= -98 (2006) */
/* 2106 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 2108 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2112 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 2116 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 2118 */	NdrFcShort( 0x6c ),	/* 108 */
/* 2120 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 2122 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 2124 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2126 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2128 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2130 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2132 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 2134 */	NdrFcShort( 0x4 ),	/* 4 */
/* 2136 */	NdrFcShort( 0x4 ),	/* 4 */
/* 2138 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2140 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2142 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 2144 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2146 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2148 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2150 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2152 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 2154 */	NdrFcShort( 0xc ),	/* 12 */
/* 2156 */	NdrFcShort( 0xc ),	/* 12 */
/* 2158 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2160 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2162 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 2164 */	NdrFcShort( 0x10 ),	/* 16 */
/* 2166 */	NdrFcShort( 0x10 ),	/* 16 */
/* 2168 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2170 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2172 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 2174 */	NdrFcShort( 0x14 ),	/* 20 */
/* 2176 */	NdrFcShort( 0x14 ),	/* 20 */
/* 2178 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2180 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2182 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 2184 */	NdrFcShort( 0x18 ),	/* 24 */
/* 2186 */	NdrFcShort( 0x18 ),	/* 24 */
/* 2188 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2190 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2192 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 2194 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2196 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2198 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2200 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2202 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2204 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 2206 */	NdrFcShort( 0xf76e ),	/* Offset= -2194 (12) */
/* 2208 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 2210 */	NdrFcShort( 0xf76a ),	/* Offset= -2198 (12) */
/* 2212 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 2214 */	NdrFcShort( 0xf766 ),	/* Offset= -2202 (12) */
/* 2216 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 2218 */	NdrFcShort( 0xf762 ),	/* Offset= -2206 (12) */
/* 2220 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 2222 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 2224 */	NdrFcShort( 0x6c ),	/* 108 */
/* 2226 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 2228 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2230 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 2232 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 2234 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 2236 */	NdrFcShort( 0x6c ),	/* 108 */
/* 2238 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2240 */	NdrFcShort( 0x7 ),	/* 7 */
/* 2242 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2244 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2246 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2248 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2250 */	NdrFcShort( 0x4 ),	/* 4 */
/* 2252 */	NdrFcShort( 0x4 ),	/* 4 */
/* 2254 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2256 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2258 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2260 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2262 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2264 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2266 */	NdrFcShort( 0xc ),	/* 12 */
/* 2268 */	NdrFcShort( 0xc ),	/* 12 */
/* 2270 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2272 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2274 */	NdrFcShort( 0x10 ),	/* 16 */
/* 2276 */	NdrFcShort( 0x10 ),	/* 16 */
/* 2278 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2280 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2282 */	NdrFcShort( 0x14 ),	/* 20 */
/* 2284 */	NdrFcShort( 0x14 ),	/* 20 */
/* 2286 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2288 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2290 */	NdrFcShort( 0x18 ),	/* 24 */
/* 2292 */	NdrFcShort( 0x18 ),	/* 24 */
/* 2294 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2296 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2298 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 2300 */	0x0,		/* 0 */
			NdrFcShort( 0xff47 ),	/* Offset= -185 (2116) */
			0x5b,		/* FC_END */
/* 2304 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 2306 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2308 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2310 */	NdrFcShort( 0x8 ),	/* Offset= 8 (2318) */
/* 2312 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 2314 */	NdrFcShort( 0xff30 ),	/* Offset= -208 (2106) */
/* 2316 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 2318 */	
			0x12, 0x0,	/* FC_UP */
/* 2320 */	NdrFcShort( 0xff9e ),	/* Offset= -98 (2222) */
/* 2322 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 2324 */	NdrFcLong( 0x0 ),	/* 0 */
/* 2328 */	NdrFcLong( 0x2710 ),	/* 10000 */
/* 2332 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 2334 */	NdrFcShort( 0x1c ),	/* 28 */
/* 2336 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 2338 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 2340 */	NdrFcShort( 0x18 ),	/* 24 */
/* 2342 */	NdrFcShort( 0x18 ),	/* 24 */
/* 2344 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2346 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2348 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 2350 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2352 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2354 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 2356 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 2358 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 2360 */	NdrFcShort( 0x1c ),	/* 28 */
/* 2362 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 2364 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2366 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 2368 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 2370 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 2372 */	NdrFcShort( 0x1c ),	/* 28 */
/* 2374 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2376 */	NdrFcShort( 0x1 ),	/* 1 */
/* 2378 */	NdrFcShort( 0x18 ),	/* 24 */
/* 2380 */	NdrFcShort( 0x18 ),	/* 24 */
/* 2382 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 2384 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 2386 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 2388 */	0x0,		/* 0 */
			NdrFcShort( 0xffc7 ),	/* Offset= -57 (2332) */
			0x5b,		/* FC_END */
/* 2392 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 2394 */	NdrFcShort( 0x8 ),	/* 8 */
/* 2396 */	NdrFcShort( 0x0 ),	/* 0 */
/* 2398 */	NdrFcShort( 0x8 ),	/* Offset= 8 (2406) */
/* 2400 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 2402 */	NdrFcShort( 0xffb0 ),	/* Offset= -80 (2322) */
/* 2404 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 2406 */	
			0x12, 0x0,	/* FC_UP */
/* 2408 */	NdrFcShort( 0xffce ),	/* Offset= -50 (2358) */

			0x0
        }
    };
#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

#endif