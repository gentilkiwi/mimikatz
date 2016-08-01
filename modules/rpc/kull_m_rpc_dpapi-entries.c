#include "kull_m_rpc_dpapi-entries.h"

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable: 4211)  /* redefine extern to static */
#pragma warning(disable: 4232)  /* dllimport identity*/
#pragma warning(disable: 4024)  /* array to pointer mapping*/

#ifdef _M_X64
#define _dpapi2Dentries_MIDL_TYPE_FORMAT_STRING_SIZE	219
#define _dpapi2Dentries_MIDL_TYPE_FORMAT_OFFSET			188
#elif defined _M_IX86
#define _dpapi2Dentries_MIDL_TYPE_FORMAT_STRING_SIZE	273
#define _dpapi2Dentries_MIDL_TYPE_FORMAT_OFFSET			228
#endif

typedef struct _dpapi2Dentries_MIDL_TYPE_FORMAT_STRING {
	short          Pad;
	unsigned char  Format[ _dpapi2Dentries_MIDL_TYPE_FORMAT_STRING_SIZE ];
} dpapi2Dentries_MIDL_TYPE_FORMAT_STRING;

extern const dpapi2Dentries_MIDL_TYPE_FORMAT_STRING dpapi2Dentries__MIDL_TypeFormatString;
static const RPC_CLIENT_INTERFACE DPAPIEntries___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0xa89c7745, 0x786b, 0x4d4e, {0x8d, 0x34, 0xc6, 0x8e, 0x8e, 0xc6, 0xc5, 0xfb}}, {1, 0}}, {{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
static const MIDL_TYPE_PICKLING_INFO __MIDL_TypePicklingInfo = {0x33205054, 0x3, 0, 0, 0,};
static RPC_BINDING_HANDLE DPAPIEntries__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC DPAPIEntries_StubDesc = {(void *) &DPAPIEntries___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &DPAPIEntries__MIDL_AutoBindHandle, 0, 0, 0, 0, dpapi2Dentries__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};

size_t KUHL_M_DPAPI_ENTRIES_AlignSize(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType)
{
    return NdrMesTypeAlignSize2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &DPAPIEntries_StubDesc, (PFORMAT_STRING) &dpapi2Dentries__MIDL_TypeFormatString.Format[_dpapi2Dentries_MIDL_TYPE_FORMAT_OFFSET], _pType);
}

void KUHL_M_DPAPI_ENTRIES_Encode(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType)
{
    NdrMesTypeEncode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &DPAPIEntries_StubDesc, (PFORMAT_STRING) &dpapi2Dentries__MIDL_TypeFormatString.Format[_dpapi2Dentries_MIDL_TYPE_FORMAT_OFFSET], _pType);
}

void KUHL_M_DPAPI_ENTRIES_Decode(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType)
{
    NdrMesTypeDecode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &DPAPIEntries_StubDesc, (PFORMAT_STRING) &dpapi2Dentries__MIDL_TypeFormatString.Format[_dpapi2Dentries_MIDL_TYPE_FORMAT_OFFSET], _pType);
}

void KUHL_M_DPAPI_ENTRIES_Free(handle_t _MidlEsHandle, KUHL_M_DPAPI_ENTRIES * _pType)
{
    NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &DPAPIEntries_StubDesc, (PFORMAT_STRING) &dpapi2Dentries__MIDL_TypeFormatString.Format[_dpapi2Dentries_MIDL_TYPE_FORMAT_OFFSET], _pType);
}
#ifdef _M_X64
static const dpapi2Dentries_MIDL_TYPE_FORMAT_STRING dpapi2Dentries__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/*  4 */	NdrFcShort( 0x8 ),	/* 8 */
/*  6 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/*  8 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 10 */	NdrFcShort( 0x10 ),	/* 16 */
/* 12 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 14 */	0x6,		/* FC_SHORT */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 16 */	0x0,		/* 0 */
			NdrFcShort( 0xfff1 ),	/* Offset= -15 (2) */
			0x5b,		/* FC_END */
/* 20 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 22 */	NdrFcShort( 0x14 ),	/* 20 */
/* 24 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 26 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 28 */	NdrFcShort( 0x24 ),	/* 36 */
/* 30 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 32 */	NdrFcShort( 0xffe8 ),	/* Offset= -24 (8) */
/* 34 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 36 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (20) */
/* 38 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 40 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 42 */	NdrFcShort( 0x0 ),	/* 0 */
/* 44 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 46 */	NdrFcShort( 0x0 ),	/* 0 */
/* 48 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 50 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 54 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 56 */	
			0x12, 0x0,	/* FC_UP */
/* 58 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (26) */
/* 60 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 62 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 64 */	NdrFcShort( 0x10 ),	/* 16 */
/* 66 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 68 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 70 */	NdrFcShort( 0x90 ),	/* 144 */
/* 72 */	NdrFcShort( 0x0 ),	/* 0 */
/* 74 */	NdrFcShort( 0x22 ),	/* Offset= 34 (108) */
/* 76 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 78 */	0x0,		/* 0 */
			NdrFcShort( 0xffb9 ),	/* Offset= -71 (8) */
			0x40,		/* FC_STRUCTPAD4 */
/* 82 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 84 */	0x0,		/* 0 */
			NdrFcShort( 0xffe9 ),	/* Offset= -23 (62) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 88 */	0x0,		/* 0 */
			NdrFcShort( 0xffbb ),	/* Offset= -69 (20) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 92 */	0x0,		/* 0 */
			NdrFcShort( 0xffb7 ),	/* Offset= -73 (20) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 96 */	0x0,		/* 0 */
			NdrFcShort( 0xffb3 ),	/* Offset= -77 (20) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 100 */	0x0,		/* 0 */
			NdrFcShort( 0xffd9 ),	/* Offset= -39 (62) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 104 */	0x0,		/* 0 */
			NdrFcShort( 0xffab ),	/* Offset= -85 (20) */
			0x5b,		/* FC_END */
/* 108 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 110 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 112 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 114 */	NdrFcShort( 0x0 ),	/* 0 */
/* 116 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 118 */	NdrFcShort( 0x10 ),	/* 16 */
/* 120 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 122 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 126 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 128 */	
			0x12, 0x0,	/* FC_UP */
/* 130 */	NdrFcShort( 0xffc2 ),	/* Offset= -62 (68) */
/* 132 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 134 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 136 */	NdrFcShort( 0x1 ),	/* 1 */
/* 138 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 140 */	NdrFcShort( 0x14 ),	/* 20 */
/* 142 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 144 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 146 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 148 */	NdrFcShort( 0x20 ),	/* 32 */
/* 150 */	NdrFcShort( 0x0 ),	/* 0 */
/* 152 */	NdrFcShort( 0xa ),	/* Offset= 10 (162) */
/* 154 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 156 */	NdrFcShort( 0xff6c ),	/* Offset= -148 (8) */
/* 158 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 160 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 162 */	
			0x12, 0x0,	/* FC_UP */
/* 164 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (134) */
/* 166 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 168 */	NdrFcShort( 0x0 ),	/* 0 */
/* 170 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 172 */	NdrFcShort( 0x20 ),	/* 32 */
/* 174 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 176 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 180 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 182 */	
			0x12, 0x0,	/* FC_UP */
/* 184 */	NdrFcShort( 0xffda ),	/* Offset= -38 (146) */
/* 186 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 188 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 190 */	NdrFcShort( 0x30 ),	/* 48 */
/* 192 */	NdrFcShort( 0x0 ),	/* 0 */
/* 194 */	NdrFcShort( 0xc ),	/* Offset= 12 (206) */
/* 196 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 198 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 200 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 202 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 204 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 206 */	
			0x12, 0x0,	/* FC_UP */
/* 208 */	NdrFcShort( 0xff58 ),	/* Offset= -168 (40) */
/* 210 */	
			0x12, 0x0,	/* FC_UP */
/* 212 */	NdrFcShort( 0xff9c ),	/* Offset= -100 (112) */
/* 214 */	
			0x12, 0x0,	/* FC_UP */
/* 216 */	NdrFcShort( 0xffce ),	/* Offset= -50 (166) */

			0x0
        }
    };
#elif defined _M_IX86
static const dpapi2Dentries_MIDL_TYPE_FORMAT_STRING dpapi2Dentries__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/*  4 */	NdrFcShort( 0x8 ),	/* 8 */
/*  6 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/*  8 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 10 */	NdrFcShort( 0x10 ),	/* 16 */
/* 12 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 14 */	0x6,		/* FC_SHORT */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 16 */	0x0,		/* 0 */
			NdrFcShort( 0xfff1 ),	/* Offset= -15 (2) */
			0x5b,		/* FC_END */
/* 20 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 22 */	NdrFcShort( 0x14 ),	/* 20 */
/* 24 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 26 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 28 */	NdrFcShort( 0x24 ),	/* 36 */
/* 30 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 32 */	NdrFcShort( 0xffe8 ),	/* Offset= -24 (8) */
/* 34 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 36 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (20) */
/* 38 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 40 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 42 */	NdrFcShort( 0x4 ),	/* 4 */
/* 44 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 46 */	NdrFcShort( 0x0 ),	/* 0 */
/* 48 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 50 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 52 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 54 */	NdrFcShort( 0x4 ),	/* 4 */
/* 56 */	NdrFcShort( 0x0 ),	/* 0 */
/* 58 */	NdrFcShort( 0x1 ),	/* 1 */
/* 60 */	NdrFcShort( 0x0 ),	/* 0 */
/* 62 */	NdrFcShort( 0x0 ),	/* 0 */
/* 64 */	0x12, 0x0,	/* FC_UP */
/* 66 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (26) */
/* 68 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 70 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 72 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 74 */	NdrFcShort( 0x10 ),	/* 16 */
/* 76 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 78 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 80 */	NdrFcShort( 0x88 ),	/* 136 */
/* 82 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 84 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 86 */	NdrFcShort( 0x14 ),	/* 20 */
/* 88 */	NdrFcShort( 0x14 ),	/* 20 */
/* 90 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 92 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 94 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 96 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 98 */	NdrFcShort( 0xffa6 ),	/* Offset= -90 (8) */
/* 100 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 102 */	0x0,		/* 0 */
			NdrFcShort( 0xffe1 ),	/* Offset= -31 (72) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 106 */	0x0,		/* 0 */
			NdrFcShort( 0xffa9 ),	/* Offset= -87 (20) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 110 */	0x0,		/* 0 */
			NdrFcShort( 0xffa5 ),	/* Offset= -91 (20) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 114 */	0x0,		/* 0 */
			NdrFcShort( 0xffa1 ),	/* Offset= -95 (20) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 118 */	0x0,		/* 0 */
			NdrFcShort( 0xffd1 ),	/* Offset= -47 (72) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 122 */	0x0,		/* 0 */
			NdrFcShort( 0xff99 ),	/* Offset= -103 (20) */
			0x5b,		/* FC_END */
/* 126 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 128 */	NdrFcShort( 0x4 ),	/* 4 */
/* 130 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 132 */	NdrFcShort( 0x8 ),	/* 8 */
/* 134 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 136 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 138 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 140 */	NdrFcShort( 0x4 ),	/* 4 */
/* 142 */	NdrFcShort( 0x0 ),	/* 0 */
/* 144 */	NdrFcShort( 0x1 ),	/* 1 */
/* 146 */	NdrFcShort( 0x0 ),	/* 0 */
/* 148 */	NdrFcShort( 0x0 ),	/* 0 */
/* 150 */	0x12, 0x0,	/* FC_UP */
/* 152 */	NdrFcShort( 0xffb6 ),	/* Offset= -74 (78) */
/* 154 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 156 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 158 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 160 */	NdrFcShort( 0x1 ),	/* 1 */
/* 162 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 164 */	NdrFcShort( 0x14 ),	/* 20 */
/* 166 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 168 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 170 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 172 */	NdrFcShort( 0x1c ),	/* 28 */
/* 174 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 176 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 178 */	NdrFcShort( 0x18 ),	/* 24 */
/* 180 */	NdrFcShort( 0x18 ),	/* 24 */
/* 182 */	0x12, 0x0,	/* FC_UP */
/* 184 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (158) */
/* 186 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 188 */	0x0,		/* 0 */
			NdrFcShort( 0xff4b ),	/* Offset= -181 (8) */
			0x8,		/* FC_LONG */
/* 192 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 194 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 196 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 198 */	NdrFcShort( 0x4 ),	/* 4 */
/* 200 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 202 */	NdrFcShort( 0x10 ),	/* 16 */
/* 204 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 206 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 208 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 210 */	NdrFcShort( 0x4 ),	/* 4 */
/* 212 */	NdrFcShort( 0x0 ),	/* 0 */
/* 214 */	NdrFcShort( 0x1 ),	/* 1 */
/* 216 */	NdrFcShort( 0x0 ),	/* 0 */
/* 218 */	NdrFcShort( 0x0 ),	/* 0 */
/* 220 */	0x12, 0x0,	/* FC_UP */
/* 222 */	NdrFcShort( 0xffcc ),	/* Offset= -52 (170) */
/* 224 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 226 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 228 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 230 */	NdrFcShort( 0x18 ),	/* 24 */
/* 232 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 234 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 236 */	NdrFcShort( 0x4 ),	/* 4 */
/* 238 */	NdrFcShort( 0x4 ),	/* 4 */
/* 240 */	0x12, 0x0,	/* FC_UP */
/* 242 */	NdrFcShort( 0xff36 ),	/* Offset= -202 (40) */
/* 244 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 246 */	NdrFcShort( 0xc ),	/* 12 */
/* 248 */	NdrFcShort( 0xc ),	/* 12 */
/* 250 */	0x12, 0x0,	/* FC_UP */
/* 252 */	NdrFcShort( 0xff82 ),	/* Offset= -126 (126) */
/* 254 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 256 */	NdrFcShort( 0x14 ),	/* 20 */
/* 258 */	NdrFcShort( 0x14 ),	/* 20 */
/* 260 */	0x12, 0x0,	/* FC_UP */
/* 262 */	NdrFcShort( 0xffbe ),	/* Offset= -66 (196) */
/* 264 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 266 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 268 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 270 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */

			0x0
        }
    };
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif