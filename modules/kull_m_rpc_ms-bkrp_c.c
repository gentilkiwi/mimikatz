#include "kull_m_rpc_ms-bkrp.h"

const GUID
	BACKUPKEY_BACKUP_GUID = {0x7f752b10, 0x178e, 0x11d1, {0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40}},
	BACKUPKEY_RESTORE_GUID_WIN2K = {0x7fe94d50, 0x178e, 0x11d1, {0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40}},
	BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID = {0x018ff48a, 0xeaba, 0x40c6, {0x8f, 0x6d, 0x72, 0x37, 0x02, 0x40, 0xe9, 0x67}},
	BACKUPKEY_RESTORE_GUID = {0x47270c64, 0x2fc7, 0x499b, {0xac, 0x5b, 0x0e, 0x37, 0xcd, 0xce, 0x89, 0x9a}};

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning( disable: 4211 )  /* redefine extern to static */
#pragma warning( disable: 4232 )  /* dllimport identity*/
#pragma warning( disable: 4024 )  /* array to pointer mapping*/

#ifdef _M_X64
typedef struct _ms2Dbkrp_MIDL_TYPE_FORMAT_STRING
{
	short          Pad;
	unsigned char  Format[65];
} ms2Dbkrp_MIDL_TYPE_FORMAT_STRING;

typedef struct _ms2Dbkrp_MIDL_PROC_FORMAT_STRING
{
	short          Pad;
	unsigned char  Format[73];
} ms2Dbkrp_MIDL_PROC_FORMAT_STRING;

extern const ms2Dbkrp_MIDL_TYPE_FORMAT_STRING ms2Dbkrp__MIDL_TypeFormatString;
extern const ms2Dbkrp_MIDL_PROC_FORMAT_STRING ms2Dbkrp__MIDL_ProcFormatString;
static const RPC_CLIENT_INTERFACE BackupKey___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0x3dde7c30, 0x165d, 0x11d1, {0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40}}, {1, 0}}, {{0x8A885D04, 0x1CEB, 0x11C9, {0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
static RPC_BINDING_HANDLE BackupKey__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC BackupKey_StubDesc = {(void *) &BackupKey___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &BackupKey__MIDL_AutoBindHandle, 0, 0, 0, 0, ms2Dbkrp__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};

NET_API_STATUS BackuprKey(handle_t h, GUID *pguidActionAgent, byte *pDataIn, DWORD cbDataIn, byte **ppDataOut, DWORD *pcbDataOut, DWORD dwParam)
{
	return (NET_API_STATUS) NdrClientCall2((PMIDL_STUB_DESC) &BackupKey_StubDesc, (PFORMAT_STRING) &ms2Dbkrp__MIDL_ProcFormatString.Format[0], h, pguidActionAgent, pDataIn, cbDataIn, ppDataOut, pcbDataOut, dwParam).Simple;
}

#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif

static const ms2Dbkrp_MIDL_PROC_FORMAT_STRING ms2Dbkrp__MIDL_ProcFormatString = {
        0,
        {
	/* Procedure BackuprKey */
			0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x40 ),	/* X64 Stack size/offset = 64 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 14 */	NdrFcShort( 0x54 ),	/* 84 */
/* 16 */	NdrFcShort( 0x24 ),	/* 36 */
/* 18 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x7,		/* 7 */
/* 20 */	0xa,		/* 10 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 22 */	NdrFcShort( 0x1 ),	/* 1 */
/* 24 */	NdrFcShort( 0x1 ),	/* 1 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
/* 28 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter h */
/* 30 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 32 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 34 */	NdrFcShort( 0xc ),	/* Type Offset=12 */
	/* Parameter pguidActionAgent */
/* 36 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 38 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 40 */	NdrFcShort( 0x1c ),	/* Type Offset=28 */
	/* Parameter pDataIn */
/* 42 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 44 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 46 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter cbDataIn */
/* 48 */	NdrFcShort( 0x2013 ),	/* Flags:  must size, must free, out, srv alloc size=8 */
/* 50 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 52 */	NdrFcShort( 0x28 ),	/* Type Offset=40 */
	/* Parameter ppDataOut */
/* 54 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 56 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 58 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pcbDataOut */
/* 60 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 62 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 64 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter dwParam */
/* 66 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 68 */	NdrFcShort( 0x38 ),	/* X64 Stack size/offset = 56 */
/* 70 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
    };

static const ms2Dbkrp_MIDL_TYPE_FORMAT_STRING ms2Dbkrp__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x11, 0x0,	/* FC_RP */
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
			0x11, 0x0,	/* FC_RP */
/* 26 */	NdrFcShort( 0x2 ),	/* Offset= 2 (28) */
/* 28 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 30 */	NdrFcShort( 0x1 ),	/* 1 */
/* 32 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x0,		/*  */
/* 34 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 36 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 38 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 40 */	
			0x11, 0x14,	/* FC_RP [alloced_on_stack] [pointer_deref] */
/* 42 */	NdrFcShort( 0x2 ),	/* Offset= 2 (44) */
/* 44 */	
			0x12, 0x0,	/* FC_UP */
/* 46 */	NdrFcShort( 0x2 ),	/* Offset= 2 (48) */
/* 48 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 50 */	NdrFcShort( 0x1 ),	/* 1 */
/* 52 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x54,		/* FC_DEREFERENCE */
/* 54 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 56 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 58 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 60 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/* 62 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */

			0x0
        }
    };

#elif defined _M_IX86
typedef struct _ms2Dbkrp_MIDL_TYPE_FORMAT_STRING
{
	short          Pad;
	unsigned char  Format[65];
} ms2Dbkrp_MIDL_TYPE_FORMAT_STRING;

typedef struct _ms2Dbkrp_MIDL_PROC_FORMAT_STRING
{
	short          Pad;
	unsigned char  Format[71];
} ms2Dbkrp_MIDL_PROC_FORMAT_STRING;

extern const ms2Dbkrp_MIDL_TYPE_FORMAT_STRING ms2Dbkrp__MIDL_TypeFormatString;
extern const ms2Dbkrp_MIDL_PROC_FORMAT_STRING ms2Dbkrp__MIDL_ProcFormatString;
static const RPC_CLIENT_INTERFACE BackupKey___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0x3dde7c30, 0x165d, 0x11d1, {0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40}}, {1, 0}}, {{0x8A885D04, 0x1CEB, 0x11C9, {0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
static RPC_BINDING_HANDLE BackupKey__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC BackupKey_StubDesc = {(void *) &BackupKey___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &BackupKey__MIDL_AutoBindHandle, 0, 0, 0, 0, ms2Dbkrp__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};

#pragma optimize("", off ) 
NET_API_STATUS BackuprKey(handle_t h, GUID *pguidActionAgent, byte *pDataIn, DWORD cbDataIn, byte **ppDataOut, DWORD *pcbDataOut, DWORD dwParam)
{
    return (NET_API_STATUS) NdrClientCall2((PMIDL_STUB_DESC) &BackupKey_StubDesc, (PFORMAT_STRING) &ms2Dbkrp__MIDL_ProcFormatString.Format[0], (unsigned char *) &h).Simple;
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

static const ms2Dbkrp_MIDL_PROC_FORMAT_STRING ms2Dbkrp__MIDL_ProcFormatString = {
        0,
        {
	/* Procedure BackuprKey */
			0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x20 ),	/* x86 Stack size/offset = 32 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 14 */	NdrFcShort( 0x54 ),	/* 84 */
/* 16 */	NdrFcShort( 0x24 ),	/* 36 */
/* 18 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x7,		/* 7 */
/* 20 */	0x8,		/* 8 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 22 */	NdrFcShort( 0x1 ),	/* 1 */
/* 24 */	NdrFcShort( 0x1 ),	/* 1 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
	/* Parameter h */
/* 28 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 30 */	NdrFcShort( 0x4 ),	/* x86 Stack size/offset = 4 */
/* 32 */	NdrFcShort( 0xc ),	/* Type Offset=12 */
	/* Parameter pguidActionAgent */
/* 34 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 36 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 38 */	NdrFcShort( 0x1c ),	/* Type Offset=28 */
	/* Parameter pDataIn */
/* 40 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 42 */	NdrFcShort( 0xc ),	/* x86 Stack size/offset = 12 */
/* 44 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter cbDataIn */
/* 46 */	NdrFcShort( 0x2013 ),	/* Flags:  must size, must free, out, srv alloc size=8 */
/* 48 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 50 */	NdrFcShort( 0x28 ),	/* Type Offset=40 */
	/* Parameter ppDataOut */
/* 52 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 54 */	NdrFcShort( 0x14 ),	/* x86 Stack size/offset = 20 */
/* 56 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter pcbDataOut */
/* 58 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 60 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 62 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */
	/* Parameter dwParam */
/* 64 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 66 */	NdrFcShort( 0x1c ),	/* x86 Stack size/offset = 28 */
/* 68 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
};

static const ms2Dbkrp_MIDL_TYPE_FORMAT_STRING ms2Dbkrp__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x11, 0x0,	/* FC_RP */
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
			0x11, 0x0,	/* FC_RP */
/* 26 */	NdrFcShort( 0x2 ),	/* Offset= 2 (28) */
/* 28 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 30 */	NdrFcShort( 0x1 ),	/* 1 */
/* 32 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x0,		/*  */
/* 34 */	NdrFcShort( 0xc ),	/* x86 Stack size/offset = 12 */
/* 36 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 38 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 40 */	
			0x11, 0x14,	/* FC_RP [alloced_on_stack] [pointer_deref] */
/* 42 */	NdrFcShort( 0x2 ),	/* Offset= 2 (44) */
/* 44 */	
			0x12, 0x0,	/* FC_UP */
/* 46 */	NdrFcShort( 0x2 ),	/* Offset= 2 (48) */
/* 48 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 50 */	NdrFcShort( 0x1 ),	/* 1 */
/* 52 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x54,		/* FC_DEREFERENCE */
/* 54 */	NdrFcShort( 0x14 ),	/* x86 Stack size/offset = 20 */
/* 56 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 58 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 60 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/* 62 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */

			0x0
        }
    };
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif