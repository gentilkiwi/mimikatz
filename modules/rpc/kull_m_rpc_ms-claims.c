#include "kull_m_rpc_ms-claims.h"

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable: 4211)  /* redefine extern to static */
#pragma warning(disable: 4232)  /* dllimport identity*/
#pragma warning(disable: 4024)  /* array to pointer mapping*/

#ifdef _M_X64
#define _Claims_MIDL_TYPE_FORMAT_STRING_SIZE	371
#define _Claims_MIDL_TYPE_FORMAT_OFFSET			316
#elif defined _M_IX86
#define _Claims_MIDL_TYPE_FORMAT_STRING_SIZE	383
#define _Claims_MIDL_TYPE_FORMAT_OFFSET			328
#endif

typedef struct _Claims_MIDL_TYPE_FORMAT_STRING {
	short          Pad;
	unsigned char  Format[ _Claims_MIDL_TYPE_FORMAT_STRING_SIZE ];
} Claims_MIDL_TYPE_FORMAT_STRING;

extern const Claims_MIDL_TYPE_FORMAT_STRING Claims__MIDL_TypeFormatString;
static const RPC_CLIENT_INTERFACE Claims___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0xbba9cb76, 0xeb0c, 0x462c, {0xaa, 0x1b, 0x5d, 0x8c, 0x34, 0x41, 0x57, 0x01}}, {1, 0}}, {{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
static const MIDL_TYPE_PICKLING_INFO __MIDL_TypePicklingInfo = {0x33205054, 0x3, 0, 0, 0,};
static RPC_BINDING_HANDLE Claims__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC Claims_StubDesc = {(void *) &Claims___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &Claims__MIDL_AutoBindHandle, 0, 0, 0, 0, Claims__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};

size_t PCLAIMS_SET_AlignSize(handle_t _MidlEsHandle, PCLAIMS_SET * _pType)
{
    return NdrMesTypeAlignSize2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &Claims_StubDesc, (PFORMAT_STRING ) &Claims__MIDL_TypeFormatString.Format[2], _pType);
}

void PCLAIMS_SET_Encode(handle_t _MidlEsHandle, PCLAIMS_SET * _pType)
{
    NdrMesTypeEncode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &Claims_StubDesc, (PFORMAT_STRING) &Claims__MIDL_TypeFormatString.Format[2], _pType);
}

void PCLAIMS_SET_Decode(handle_t _MidlEsHandle, PCLAIMS_SET * _pType)
{
    NdrMesTypeDecode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &Claims_StubDesc, (PFORMAT_STRING) &Claims__MIDL_TypeFormatString.Format[2], _pType);
}

void PCLAIMS_SET_Free(handle_t _MidlEsHandle, PCLAIMS_SET * _pType)
{
    NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &Claims_StubDesc, (PFORMAT_STRING) &Claims__MIDL_TypeFormatString.Format[2], _pType);
}

size_t PCLAIMS_SET_METADATA_AlignSize(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType)
{
    return NdrMesTypeAlignSize2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &Claims_StubDesc, (PFORMAT_STRING) &Claims__MIDL_TypeFormatString.Format[_Claims_MIDL_TYPE_FORMAT_OFFSET], _pType);
}

void PCLAIMS_SET_METADATA_Encode(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType)
{
    NdrMesTypeEncode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &Claims_StubDesc, (PFORMAT_STRING) &Claims__MIDL_TypeFormatString.Format[_Claims_MIDL_TYPE_FORMAT_OFFSET], _pType);
}

void PCLAIMS_SET_METADATA_Decode(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType)
{
    NdrMesTypeDecode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &Claims_StubDesc, (PFORMAT_STRING) &Claims__MIDL_TypeFormatString.Format[_Claims_MIDL_TYPE_FORMAT_OFFSET], _pType);
}

void PCLAIMS_SET_METADATA_Free(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType)
{
    NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &Claims_StubDesc, (PFORMAT_STRING) &Claims__MIDL_TypeFormatString.Format[_Claims_MIDL_TYPE_FORMAT_OFFSET], _pType);
}
#ifdef _M_X64
static const Claims_MIDL_TYPE_FORMAT_STRING Claims__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x0,	/* FC_UP */
/*  4 */	NdrFcShort( 0x120 ),	/* Offset= 288 (292) */
/*  6 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0xd,		/* FC_ENUM16 */
/*  8 */	0x6,		/* Corr desc: FC_SHORT */
			0x0,		/*  */
/* 10 */	NdrFcShort( 0xfff8 ),	/* -8 */
/* 12 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 14 */	NdrFcShort( 0x2 ),	/* Offset= 2 (16) */
/* 16 */	NdrFcShort( 0x10 ),	/* 16 */
/* 18 */	NdrFcShort( 0x4 ),	/* 4 */
/* 20 */	NdrFcLong( 0x1 ),	/* 1 */
/* 24 */	NdrFcShort( 0x2c ),	/* Offset= 44 (68) */
/* 26 */	NdrFcLong( 0x2 ),	/* 2 */
/* 30 */	NdrFcShort( 0x44 ),	/* Offset= 68 (98) */
/* 32 */	NdrFcLong( 0x3 ),	/* 3 */
/* 36 */	NdrFcShort( 0x72 ),	/* Offset= 114 (150) */
/* 38 */	NdrFcLong( 0x6 ),	/* 6 */
/* 42 */	NdrFcShort( 0x8a ),	/* Offset= 138 (180) */
/* 44 */	NdrFcShort( 0x0 ),	/* Offset= 0 (44) */
/* 46 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 48 */	NdrFcLong( 0x1 ),	/* 1 */
/* 52 */	NdrFcLong( 0xa00000 ),	/* 10485760 */
/* 56 */	
			0x1b,		/* FC_CARRAY */
			0x7,		/* 7 */
/* 58 */	NdrFcShort( 0x8 ),	/* 8 */
/* 60 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 62 */	NdrFcShort( 0x0 ),	/* 0 */
/* 64 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 66 */	0xb,		/* FC_HYPER */
			0x5b,		/* FC_END */
/* 68 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 70 */	NdrFcShort( 0x10 ),	/* 16 */
/* 72 */	NdrFcShort( 0x0 ),	/* 0 */
/* 74 */	NdrFcShort( 0xa ),	/* Offset= 10 (84) */
/* 76 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 78 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (46) */
/* 80 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 82 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 84 */	
			0x12, 0x0,	/* FC_UP */
/* 86 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (56) */
/* 88 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 90 */	NdrFcLong( 0x1 ),	/* 1 */
/* 94 */	NdrFcLong( 0xa00000 ),	/* 10485760 */
/* 98 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 100 */	NdrFcShort( 0x10 ),	/* 16 */
/* 102 */	NdrFcShort( 0x0 ),	/* 0 */
/* 104 */	NdrFcShort( 0xa ),	/* Offset= 10 (114) */
/* 106 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 108 */	NdrFcShort( 0xffec ),	/* Offset= -20 (88) */
/* 110 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 112 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 114 */	
			0x12, 0x0,	/* FC_UP */
/* 116 */	NdrFcShort( 0xffc4 ),	/* Offset= -60 (56) */
/* 118 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 120 */	NdrFcLong( 0x1 ),	/* 1 */
/* 124 */	NdrFcLong( 0xa00000 ),	/* 10485760 */
/* 128 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 130 */	NdrFcShort( 0x0 ),	/* 0 */
/* 132 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 134 */	NdrFcShort( 0x0 ),	/* 0 */
/* 136 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 138 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 142 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 144 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 146 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 148 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 150 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 152 */	NdrFcShort( 0x10 ),	/* 16 */
/* 154 */	NdrFcShort( 0x0 ),	/* 0 */
/* 156 */	NdrFcShort( 0xa ),	/* Offset= 10 (166) */
/* 158 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 160 */	NdrFcShort( 0xffd6 ),	/* Offset= -42 (118) */
/* 162 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 164 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 166 */	
			0x12, 0x0,	/* FC_UP */
/* 168 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (128) */
/* 170 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 172 */	NdrFcLong( 0x1 ),	/* 1 */
/* 176 */	NdrFcLong( 0xa00000 ),	/* 10485760 */
/* 180 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 182 */	NdrFcShort( 0x10 ),	/* 16 */
/* 184 */	NdrFcShort( 0x0 ),	/* 0 */
/* 186 */	NdrFcShort( 0xa ),	/* Offset= 10 (196) */
/* 188 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 190 */	NdrFcShort( 0xffec ),	/* Offset= -20 (170) */
/* 192 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 194 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 196 */	
			0x12, 0x0,	/* FC_UP */
/* 198 */	NdrFcShort( 0xff72 ),	/* Offset= -142 (56) */
/* 200 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 202 */	NdrFcShort( 0x20 ),	/* 32 */
/* 204 */	NdrFcShort( 0x0 ),	/* 0 */
/* 206 */	NdrFcShort( 0xa ),	/* Offset= 10 (216) */
/* 208 */	0x36,		/* FC_POINTER */
			0xd,		/* FC_ENUM16 */
/* 210 */	0x40,		/* FC_STRUCTPAD4 */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 212 */	0x0,		/* 0 */
			NdrFcShort( 0xff31 ),	/* Offset= -207 (6) */
			0x5b,		/* FC_END */
/* 216 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 218 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 220 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 222 */	NdrFcShort( 0x0 ),	/* 0 */
/* 224 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 226 */	NdrFcShort( 0x4 ),	/* 4 */
/* 228 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 230 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 234 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 236 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 238 */	NdrFcShort( 0xffda ),	/* Offset= -38 (200) */
/* 240 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 242 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 244 */	NdrFcShort( 0x10 ),	/* 16 */
/* 246 */	NdrFcShort( 0x0 ),	/* 0 */
/* 248 */	NdrFcShort( 0x6 ),	/* Offset= 6 (254) */
/* 250 */	0xd,		/* FC_ENUM16 */
			0x8,		/* FC_LONG */
/* 252 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 254 */	
			0x12, 0x0,	/* FC_UP */
/* 256 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (220) */
/* 258 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 260 */	NdrFcShort( 0x0 ),	/* 0 */
/* 262 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 264 */	NdrFcShort( 0x0 ),	/* 0 */
/* 266 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 268 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 272 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 274 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 276 */	NdrFcShort( 0xffde ),	/* Offset= -34 (242) */
/* 278 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 280 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 282 */	NdrFcShort( 0x1 ),	/* 1 */
/* 284 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 286 */	NdrFcShort( 0x14 ),	/* 20 */
/* 288 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 290 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 292 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 294 */	NdrFcShort( 0x20 ),	/* 32 */
/* 296 */	NdrFcShort( 0x0 ),	/* 0 */
/* 298 */	NdrFcShort( 0xa ),	/* Offset= 10 (308) */
/* 300 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 302 */	0x36,		/* FC_POINTER */
			0x6,		/* FC_SHORT */
/* 304 */	0x3e,		/* FC_STRUCTPAD2 */
			0x8,		/* FC_LONG */
/* 306 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 308 */	
			0x12, 0x0,	/* FC_UP */
/* 310 */	NdrFcShort( 0xffcc ),	/* Offset= -52 (258) */
/* 312 */	
			0x12, 0x0,	/* FC_UP */
/* 314 */	NdrFcShort( 0xffde ),	/* Offset= -34 (280) */
/* 316 */	
			0x12, 0x0,	/* FC_UP */
/* 318 */	NdrFcShort( 0x1a ),	/* Offset= 26 (344) */
/* 320 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 322 */	NdrFcShort( 0x1 ),	/* 1 */
/* 324 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 326 */	NdrFcShort( 0x0 ),	/* 0 */
/* 328 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 330 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 332 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 334 */	NdrFcShort( 0x1 ),	/* 1 */
/* 336 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 338 */	NdrFcShort( 0x1c ),	/* 28 */
/* 340 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 342 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 344 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 346 */	NdrFcShort( 0x28 ),	/* 40 */
/* 348 */	NdrFcShort( 0x0 ),	/* 0 */
/* 350 */	NdrFcShort( 0xc ),	/* Offset= 12 (362) */
/* 352 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 354 */	0x36,		/* FC_POINTER */
			0xd,		/* FC_ENUM16 */
/* 356 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 358 */	0x3e,		/* FC_STRUCTPAD2 */
			0x8,		/* FC_LONG */
/* 360 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 362 */	
			0x12, 0x0,	/* FC_UP */
/* 364 */	NdrFcShort( 0xffd4 ),	/* Offset= -44 (320) */
/* 366 */	
			0x12, 0x0,	/* FC_UP */
/* 368 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (332) */

			0x0
        }
    };
#elif defined _M_IX86
static const Claims_MIDL_TYPE_FORMAT_STRING Claims__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x0,	/* FC_UP */
/*  4 */	NdrFcShort( 0x122 ),	/* Offset= 290 (294) */
/*  6 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0xd,		/* FC_ENUM16 */
/*  8 */	0x6,		/* Corr desc: FC_SHORT */
			0x0,		/*  */
/* 10 */	NdrFcShort( 0xfffc ),	/* -4 */
/* 12 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 14 */	NdrFcShort( 0x2 ),	/* Offset= 2 (16) */
/* 16 */	NdrFcShort( 0x8 ),	/* 8 */
/* 18 */	NdrFcShort( 0x4 ),	/* 4 */
/* 20 */	NdrFcLong( 0x1 ),	/* 1 */
/* 24 */	NdrFcShort( 0x2c ),	/* Offset= 44 (68) */
/* 26 */	NdrFcLong( 0x2 ),	/* 2 */
/* 30 */	NdrFcShort( 0x42 ),	/* Offset= 66 (96) */
/* 32 */	NdrFcLong( 0x3 ),	/* 3 */
/* 36 */	NdrFcShort( 0x78 ),	/* Offset= 120 (156) */
/* 38 */	NdrFcLong( 0x6 ),	/* 6 */
/* 42 */	NdrFcShort( 0x8e ),	/* Offset= 142 (184) */
/* 44 */	NdrFcShort( 0x0 ),	/* Offset= 0 (44) */
/* 46 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 48 */	NdrFcLong( 0x1 ),	/* 1 */
/* 52 */	NdrFcLong( 0xa00000 ),	/* 10485760 */
/* 56 */	
			0x1b,		/* FC_CARRAY */
			0x7,		/* 7 */
/* 58 */	NdrFcShort( 0x8 ),	/* 8 */
/* 60 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 62 */	NdrFcShort( 0x0 ),	/* 0 */
/* 64 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 66 */	0xb,		/* FC_HYPER */
			0x5b,		/* FC_END */
/* 68 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 70 */	NdrFcShort( 0x8 ),	/* 8 */
/* 72 */	NdrFcShort( 0x0 ),	/* 0 */
/* 74 */	NdrFcShort( 0x8 ),	/* Offset= 8 (82) */
/* 76 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 78 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (46) */
/* 80 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 82 */	
			0x12, 0x0,	/* FC_UP */
/* 84 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (56) */
/* 86 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 88 */	NdrFcLong( 0x1 ),	/* 1 */
/* 92 */	NdrFcLong( 0xa00000 ),	/* 10485760 */
/* 96 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 98 */	NdrFcShort( 0x8 ),	/* 8 */
/* 100 */	NdrFcShort( 0x0 ),	/* 0 */
/* 102 */	NdrFcShort( 0x8 ),	/* Offset= 8 (110) */
/* 104 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 106 */	NdrFcShort( 0xffec ),	/* Offset= -20 (86) */
/* 108 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 110 */	
			0x12, 0x0,	/* FC_UP */
/* 112 */	NdrFcShort( 0xffc8 ),	/* Offset= -56 (56) */
/* 114 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 116 */	NdrFcLong( 0x1 ),	/* 1 */
/* 120 */	NdrFcLong( 0xa00000 ),	/* 10485760 */
/* 124 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 126 */	NdrFcShort( 0x4 ),	/* 4 */
/* 128 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 130 */	NdrFcShort( 0x0 ),	/* 0 */
/* 132 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 134 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 136 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 138 */	NdrFcShort( 0x4 ),	/* 4 */
/* 140 */	NdrFcShort( 0x0 ),	/* 0 */
/* 142 */	NdrFcShort( 0x1 ),	/* 1 */
/* 144 */	NdrFcShort( 0x0 ),	/* 0 */
/* 146 */	NdrFcShort( 0x0 ),	/* 0 */
/* 148 */	0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 150 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 152 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 154 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 156 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 158 */	NdrFcShort( 0x8 ),	/* 8 */
/* 160 */	NdrFcShort( 0x0 ),	/* 0 */
/* 162 */	NdrFcShort( 0x8 ),	/* Offset= 8 (170) */
/* 164 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 166 */	NdrFcShort( 0xffcc ),	/* Offset= -52 (114) */
/* 168 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 170 */	
			0x12, 0x0,	/* FC_UP */
/* 172 */	NdrFcShort( 0xffd0 ),	/* Offset= -48 (124) */
/* 174 */	0xb7,		/* FC_RANGE */
			0x8,		/* 8 */
/* 176 */	NdrFcLong( 0x1 ),	/* 1 */
/* 180 */	NdrFcLong( 0xa00000 ),	/* 10485760 */
/* 184 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 186 */	NdrFcShort( 0x8 ),	/* 8 */
/* 188 */	NdrFcShort( 0x0 ),	/* 0 */
/* 190 */	NdrFcShort( 0x8 ),	/* Offset= 8 (198) */
/* 192 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 194 */	NdrFcShort( 0xffec ),	/* Offset= -20 (174) */
/* 196 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 198 */	
			0x12, 0x0,	/* FC_UP */
/* 200 */	NdrFcShort( 0xff70 ),	/* Offset= -144 (56) */
/* 202 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 204 */	NdrFcShort( 0x10 ),	/* 16 */
/* 206 */	NdrFcShort( 0x0 ),	/* 0 */
/* 208 */	NdrFcShort( 0xa ),	/* Offset= 10 (218) */
/* 210 */	0x36,		/* FC_POINTER */
			0xd,		/* FC_ENUM16 */
/* 212 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 214 */	NdrFcShort( 0xff30 ),	/* Offset= -208 (6) */
/* 216 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 218 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 220 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/* 222 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 224 */	NdrFcShort( 0x0 ),	/* 0 */
/* 226 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 228 */	NdrFcShort( 0x4 ),	/* 4 */
/* 230 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 232 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 236 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 238 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 240 */	NdrFcShort( 0xffda ),	/* Offset= -38 (202) */
/* 242 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 244 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 246 */	NdrFcShort( 0xc ),	/* 12 */
/* 248 */	NdrFcShort( 0x0 ),	/* 0 */
/* 250 */	NdrFcShort( 0x6 ),	/* Offset= 6 (256) */
/* 252 */	0xd,		/* FC_ENUM16 */
			0x8,		/* FC_LONG */
/* 254 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 256 */	
			0x12, 0x0,	/* FC_UP */
/* 258 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (222) */
/* 260 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 262 */	NdrFcShort( 0x0 ),	/* 0 */
/* 264 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 266 */	NdrFcShort( 0x0 ),	/* 0 */
/* 268 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 270 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 274 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 276 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 278 */	NdrFcShort( 0xffde ),	/* Offset= -34 (244) */
/* 280 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 282 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 284 */	NdrFcShort( 0x1 ),	/* 1 */
/* 286 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 288 */	NdrFcShort( 0xc ),	/* 12 */
/* 290 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 292 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 294 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 296 */	NdrFcShort( 0x14 ),	/* 20 */
/* 298 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 300 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 302 */	NdrFcShort( 0x4 ),	/* 4 */
/* 304 */	NdrFcShort( 0x4 ),	/* 4 */
/* 306 */	0x12, 0x0,	/* FC_UP */
/* 308 */	NdrFcShort( 0xffd0 ),	/* Offset= -48 (260) */
/* 310 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 312 */	NdrFcShort( 0x10 ),	/* 16 */
/* 314 */	NdrFcShort( 0x10 ),	/* 16 */
/* 316 */	0x12, 0x0,	/* FC_UP */
/* 318 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (282) */
/* 320 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 322 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 324 */	0x3e,		/* FC_STRUCTPAD2 */
			0x8,		/* FC_LONG */
/* 326 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 328 */	
			0x12, 0x0,	/* FC_UP */
/* 330 */	NdrFcShort( 0x1a ),	/* Offset= 26 (356) */
/* 332 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 334 */	NdrFcShort( 0x1 ),	/* 1 */
/* 336 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 338 */	NdrFcShort( 0x0 ),	/* 0 */
/* 340 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 342 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 344 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 346 */	NdrFcShort( 0x1 ),	/* 1 */
/* 348 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 350 */	NdrFcShort( 0x14 ),	/* 20 */
/* 352 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 354 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 356 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 358 */	NdrFcShort( 0x1c ),	/* 28 */
/* 360 */	NdrFcShort( 0x0 ),	/* 0 */
/* 362 */	NdrFcShort( 0xc ),	/* Offset= 12 (374) */
/* 364 */	0x8,		/* FC_LONG */
			0x36,		/* FC_POINTER */
/* 366 */	0xd,		/* FC_ENUM16 */
			0x8,		/* FC_LONG */
/* 368 */	0x6,		/* FC_SHORT */
			0x3e,		/* FC_STRUCTPAD2 */
/* 370 */	0x8,		/* FC_LONG */
			0x36,		/* FC_POINTER */
/* 372 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 374 */	
			0x12, 0x0,	/* FC_UP */
/* 376 */	NdrFcShort( 0xffd4 ),	/* Offset= -44 (332) */
/* 378 */	
			0x12, 0x0,	/* FC_UP */
/* 380 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (344) */

			0x0
        }
    };
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif