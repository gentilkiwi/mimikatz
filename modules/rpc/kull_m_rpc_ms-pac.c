#include "kull_m_rpc_ms-pac.h"

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable: 4211)  /* redefine extern to static */
#pragma warning(disable: 4232)  /* dllimport identity*/
#pragma warning(disable: 4024)  /* array to pointer mapping*/

#ifdef _M_X64
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE	409
#define _ms_pac_PPAC_CREDENTIAL_DATA_idx		2
#define _ms_pac_PKERB_VALIDATION_INFO_idx		108
#elif defined _M_IX86
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE	669
#define _ms_pac_PPAC_CREDENTIAL_DATA_idx		2
#define _ms_pac_PKERB_VALIDATION_INFO_idx		122
#endif

typedef struct _ms_pac_MIDL_TYPE_FORMAT_STRING {
	short          Pad;
	unsigned char  Format[_ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE];
} ms_pac_MIDL_TYPE_FORMAT_STRING;

extern const ms_pac_MIDL_TYPE_FORMAT_STRING ms_pac__MIDL_TypeFormatString;
static const RPC_CLIENT_INTERFACE msKrbPac___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0x00000001, 0x0001, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71}}, {1, 0}}, {{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
static const MIDL_TYPE_PICKLING_INFO __MIDL_TypePicklingInfo = {0x33205054, 0x3, 0, 0, 0,};
static RPC_BINDING_HANDLE msKrbPac__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC msKrbPac_StubDesc = {(void *) &msKrbPac___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &msKrbPac__MIDL_AutoBindHandle, 0, 0, 0, 0, ms_pac__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};

void PPAC_CREDENTIAL_DATA_Decode(handle_t _MidlEsHandle, PPAC_CREDENTIAL_DATA * _pType)
{
    NdrMesTypeDecode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[_ms_pac_PPAC_CREDENTIAL_DATA_idx], _pType);
}

void PPAC_CREDENTIAL_DATA_Free(handle_t _MidlEsHandle, PPAC_CREDENTIAL_DATA * _pType)
{
    NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[_ms_pac_PPAC_CREDENTIAL_DATA_idx], _pType);
}

size_t PKERB_VALIDATION_INFO_AlignSize(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
{
	return NdrMesTypeAlignSize2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[_ms_pac_PKERB_VALIDATION_INFO_idx], _pType);
}

void PKERB_VALIDATION_INFO_Encode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
{
	NdrMesTypeEncode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[_ms_pac_PKERB_VALIDATION_INFO_idx], _pType);
}

void PKERB_VALIDATION_INFO_Decode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
{
	NdrMesTypeDecode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[_ms_pac_PKERB_VALIDATION_INFO_idx], _pType);
}

void PKERB_VALIDATION_INFO_Free(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
{
	NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[_ms_pac_PKERB_VALIDATION_INFO_idx], _pType);
}
#ifdef _M_X64
static const ms_pac_MIDL_TYPE_FORMAT_STRING ms_pac__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x0,	/* FC_UP */
/*  4 */	NdrFcShort( 0x5c ),	/* Offset= 92 (96) */
/*  6 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/*  8 */	NdrFcShort( 0x2 ),	/* 2 */
/* 10 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 12 */	NdrFcShort( 0x2 ),	/* 2 */
/* 14 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 16 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 18 */	NdrFcShort( 0x0 ),	/* 0 */
/* 20 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 22 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 24 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 26 */	NdrFcShort( 0x10 ),	/* 16 */
/* 28 */	NdrFcShort( 0x0 ),	/* 0 */
/* 30 */	NdrFcShort( 0x8 ),	/* Offset= 8 (38) */
/* 32 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 34 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 36 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 38 */	
			0x12, 0x0,	/* FC_UP */
/* 40 */	NdrFcShort( 0xffde ),	/* Offset= -34 (6) */
/* 42 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 44 */	NdrFcShort( 0x1 ),	/* 1 */
/* 46 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 48 */	NdrFcShort( 0x10 ),	/* 16 */
/* 50 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 52 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 54 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 56 */	NdrFcShort( 0x20 ),	/* 32 */
/* 58 */	NdrFcShort( 0x0 ),	/* 0 */
/* 60 */	NdrFcShort( 0xa ),	/* Offset= 10 (70) */
/* 62 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 64 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (24) */
/* 66 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 68 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 70 */	
			0x12, 0x0,	/* FC_UP */
/* 72 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (42) */
/* 74 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 76 */	NdrFcShort( 0x0 ),	/* 0 */
/* 78 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 80 */	NdrFcShort( 0xfff8 ),	/* -8 */
/* 82 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 84 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 88 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 90 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 92 */	NdrFcShort( 0xffda ),	/* Offset= -38 (54) */
/* 94 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 96 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 98 */	NdrFcShort( 0x8 ),	/* 8 */
/* 100 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (74) */
/* 102 */	NdrFcShort( 0x0 ),	/* Offset= 0 (102) */
/* 104 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 106 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 108 */	
			0x12, 0x0,	/* FC_UP */
/* 110 */	NdrFcShort( 0xb0 ),	/* Offset= 176 (286) */
/* 112 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 114 */	NdrFcShort( 0x8 ),	/* 8 */
/* 116 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 118 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 120 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 122 */	NdrFcShort( 0x8 ),	/* 8 */
/* 124 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 126 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 128 */	NdrFcShort( 0x8 ),	/* 8 */
/* 130 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 132 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (120) */
/* 134 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 136 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 138 */	NdrFcShort( 0x10 ),	/* 16 */
/* 140 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 142 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (126) */
/* 144 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 146 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 148 */	NdrFcShort( 0x10 ),	/* 16 */
/* 150 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 152 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (136) */
/* 154 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 156 */	
			0x1d,		/* FC_SMFARRAY */
			0x3,		/* 3 */
/* 158 */	NdrFcShort( 0x8 ),	/* 8 */
/* 160 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 162 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 164 */	NdrFcShort( 0x0 ),	/* 0 */
/* 166 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 168 */	NdrFcShort( 0x9c ),	/* 156 */
/* 170 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 172 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 176 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 178 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 180 */	NdrFcShort( 0xffbc ),	/* Offset= -68 (112) */
/* 182 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 184 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 186 */	NdrFcShort( 0x6 ),	/* 6 */
/* 188 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 190 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 192 */	NdrFcShort( 0x6 ),	/* 6 */
/* 194 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 196 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (184) */
/* 198 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 200 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 202 */	NdrFcShort( 0x4 ),	/* 4 */
/* 204 */	0x4,		/* Corr desc: FC_USMALL */
			0x0,		/*  */
/* 206 */	NdrFcShort( 0xfff9 ),	/* -7 */
/* 208 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 210 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 212 */	
			0x17,		/* FC_CSTRUCT */
			0x3,		/* 3 */
/* 214 */	NdrFcShort( 0x8 ),	/* 8 */
/* 216 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (200) */
/* 218 */	0x2,		/* FC_CHAR */
			0x2,		/* FC_CHAR */
/* 220 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 222 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (190) */
/* 224 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 226 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 228 */	NdrFcShort( 0x10 ),	/* 16 */
/* 230 */	NdrFcShort( 0x0 ),	/* 0 */
/* 232 */	NdrFcShort( 0x6 ),	/* Offset= 6 (238) */
/* 234 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 236 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 238 */	
			0x12, 0x0,	/* FC_UP */
/* 240 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (212) */
/* 242 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 244 */	NdrFcShort( 0x0 ),	/* 0 */
/* 246 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 248 */	NdrFcShort( 0x110 ),	/* 272 */
/* 250 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 252 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 256 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 258 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 260 */	NdrFcShort( 0xffde ),	/* Offset= -34 (226) */
/* 262 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 264 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 266 */	NdrFcShort( 0x0 ),	/* 0 */
/* 268 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 270 */	NdrFcShort( 0x128 ),	/* 296 */
/* 272 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 274 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 278 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 280 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 282 */	NdrFcShort( 0xff56 ),	/* Offset= -170 (112) */
/* 284 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 286 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 288 */	NdrFcShort( 0x138 ),	/* 312 */
/* 290 */	NdrFcShort( 0x0 ),	/* 0 */
/* 292 */	NdrFcShort( 0x60 ),	/* Offset= 96 (388) */
/* 294 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 296 */	NdrFcShort( 0xff48 ),	/* Offset= -184 (112) */
/* 298 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 300 */	NdrFcShort( 0xff44 ),	/* Offset= -188 (112) */
/* 302 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 304 */	NdrFcShort( 0xff40 ),	/* Offset= -192 (112) */
/* 306 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 308 */	NdrFcShort( 0xff3c ),	/* Offset= -196 (112) */
/* 310 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 312 */	NdrFcShort( 0xff38 ),	/* Offset= -200 (112) */
/* 314 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 316 */	NdrFcShort( 0xff34 ),	/* Offset= -204 (112) */
/* 318 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 320 */	NdrFcShort( 0xfed8 ),	/* Offset= -296 (24) */
/* 322 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 324 */	NdrFcShort( 0xfed4 ),	/* Offset= -300 (24) */
/* 326 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 328 */	NdrFcShort( 0xfed0 ),	/* Offset= -304 (24) */
/* 330 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 332 */	NdrFcShort( 0xfecc ),	/* Offset= -308 (24) */
/* 334 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 336 */	NdrFcShort( 0xfec8 ),	/* Offset= -312 (24) */
/* 338 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 340 */	NdrFcShort( 0xfec4 ),	/* Offset= -316 (24) */
/* 342 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 344 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 346 */	0x8,		/* FC_LONG */
			0x36,		/* FC_POINTER */
/* 348 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 350 */	0x0,		/* 0 */
			NdrFcShort( 0xff33 ),	/* Offset= -205 (146) */
			0x40,		/* FC_STRUCTPAD4 */
/* 354 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 356 */	NdrFcShort( 0xfeb4 ),	/* Offset= -332 (24) */
/* 358 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 360 */	NdrFcShort( 0xfeb0 ),	/* Offset= -336 (24) */
/* 362 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 364 */	0x0,		/* 0 */
			NdrFcShort( 0xff2f ),	/* Offset= -209 (156) */
			0x8,		/* FC_LONG */
/* 368 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 370 */	0x0,		/* 0 */
			NdrFcShort( 0xfefd ),	/* Offset= -259 (112) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 374 */	0x0,		/* 0 */
			NdrFcShort( 0xfef9 ),	/* Offset= -263 (112) */
			0x8,		/* FC_LONG */
/* 378 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 380 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 382 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 384 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 386 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 388 */	
			0x12, 0x0,	/* FC_UP */
/* 390 */	NdrFcShort( 0xff1c ),	/* Offset= -228 (162) */
/* 392 */	
			0x12, 0x0,	/* FC_UP */
/* 394 */	NdrFcShort( 0xff4a ),	/* Offset= -182 (212) */
/* 396 */	
			0x12, 0x0,	/* FC_UP */
/* 398 */	NdrFcShort( 0xff64 ),	/* Offset= -156 (242) */
/* 400 */	
			0x12, 0x0,	/* FC_UP */
/* 402 */	NdrFcShort( 0xff42 ),	/* Offset= -190 (212) */
/* 404 */	
			0x12, 0x0,	/* FC_UP */
/* 406 */	NdrFcShort( 0xff72 ),	/* Offset= -142 (264) */

			0x0
        }
    };
#elif defined _M_IX86
static const ms_pac_MIDL_TYPE_FORMAT_STRING ms_pac__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x0,	/* FC_UP */
/*  4 */	NdrFcShort( 0x52 ),	/* Offset= 82 (86) */
/*  6 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/*  8 */	NdrFcShort( 0x2 ),	/* 2 */
/* 10 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 12 */	NdrFcShort( 0x2 ),	/* 2 */
/* 14 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 16 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 18 */	NdrFcShort( 0x0 ),	/* 0 */
/* 20 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 22 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 24 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 26 */	NdrFcShort( 0x1 ),	/* 1 */
/* 28 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 30 */	NdrFcShort( 0x8 ),	/* 8 */
/* 32 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 34 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 36 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 38 */	NdrFcShort( 0x10 ),	/* 16 */
/* 40 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 42 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 44 */	NdrFcShort( 0x4 ),	/* 4 */
/* 46 */	NdrFcShort( 0x4 ),	/* 4 */
/* 48 */	0x12, 0x0,	/* FC_UP */
/* 50 */	NdrFcShort( 0xffd4 ),	/* Offset= -44 (6) */
/* 52 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 54 */	NdrFcShort( 0xc ),	/* 12 */
/* 56 */	NdrFcShort( 0xc ),	/* 12 */
/* 58 */	0x12, 0x0,	/* FC_UP */
/* 60 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (24) */
/* 62 */	
			0x5b,		/* FC_END */

			0x6,		/* FC_SHORT */
/* 64 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 66 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 68 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 70 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 72 */	NdrFcShort( 0x10 ),	/* 16 */
/* 74 */	0x9,		/* Corr desc: FC_ULONG */
			0x0,		/*  */
/* 76 */	NdrFcShort( 0xfffc ),	/* -4 */
/* 78 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 80 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 82 */	NdrFcShort( 0xffd2 ),	/* Offset= -46 (36) */
/* 84 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 86 */	
			0x18,		/* FC_CPSTRUCT */
			0x3,		/* 3 */
/* 88 */	NdrFcShort( 0x4 ),	/* 4 */
/* 90 */	NdrFcShort( 0xffec ),	/* Offset= -20 (70) */
/* 92 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 94 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 96 */	NdrFcShort( 0x10 ),	/* 16 */
/* 98 */	NdrFcShort( 0x4 ),	/* 4 */
/* 100 */	NdrFcShort( 0x2 ),	/* 2 */
/* 102 */	NdrFcShort( 0x8 ),	/* 8 */
/* 104 */	NdrFcShort( 0x8 ),	/* 8 */
/* 106 */	0x12, 0x0,	/* FC_UP */
/* 108 */	NdrFcShort( 0xff9a ),	/* Offset= -102 (6) */
/* 110 */	NdrFcShort( 0x10 ),	/* 16 */
/* 112 */	NdrFcShort( 0x10 ),	/* 16 */
/* 114 */	0x12, 0x0,	/* FC_UP */
/* 116 */	NdrFcShort( 0xffa4 ),	/* Offset= -92 (24) */
/* 118 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 120 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 122 */	
			0x12, 0x0,	/* FC_UP */
/* 124 */	NdrFcShort( 0x144 ),	/* Offset= 324 (448) */
/* 126 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 128 */	NdrFcShort( 0x8 ),	/* 8 */
/* 130 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 132 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 134 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 136 */	NdrFcShort( 0x8 ),	/* 8 */
/* 138 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 140 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 142 */	NdrFcShort( 0x8 ),	/* 8 */
/* 144 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 146 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (134) */
/* 148 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 150 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 152 */	NdrFcShort( 0x10 ),	/* 16 */
/* 154 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 156 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (140) */
/* 158 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 160 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 162 */	NdrFcShort( 0x10 ),	/* 16 */
/* 164 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 166 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (150) */
/* 168 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 170 */	
			0x1d,		/* FC_SMFARRAY */
			0x3,		/* 3 */
/* 172 */	NdrFcShort( 0x8 ),	/* 8 */
/* 174 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 176 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 178 */	NdrFcShort( 0x2 ),	/* 2 */
/* 180 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 182 */	NdrFcShort( 0x32 ),	/* 50 */
/* 184 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 186 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 188 */	NdrFcShort( 0x30 ),	/* 48 */
/* 190 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 192 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 194 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 196 */	NdrFcShort( 0x2 ),	/* 2 */
/* 198 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 200 */	NdrFcShort( 0x3a ),	/* 58 */
/* 202 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 204 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 206 */	NdrFcShort( 0x38 ),	/* 56 */
/* 208 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 210 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 212 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 214 */	NdrFcShort( 0x2 ),	/* 2 */
/* 216 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 218 */	NdrFcShort( 0x42 ),	/* 66 */
/* 220 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 222 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 224 */	NdrFcShort( 0x40 ),	/* 64 */
/* 226 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 228 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 230 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 232 */	NdrFcShort( 0x2 ),	/* 2 */
/* 234 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 236 */	NdrFcShort( 0x4a ),	/* 74 */
/* 238 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 240 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 242 */	NdrFcShort( 0x48 ),	/* 72 */
/* 244 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 246 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 248 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 250 */	NdrFcShort( 0x2 ),	/* 2 */
/* 252 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 254 */	NdrFcShort( 0x52 ),	/* 82 */
/* 256 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 258 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 260 */	NdrFcShort( 0x50 ),	/* 80 */
/* 262 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 264 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 266 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 268 */	NdrFcShort( 0x2 ),	/* 2 */
/* 270 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 272 */	NdrFcShort( 0x5a ),	/* 90 */
/* 274 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 276 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 278 */	NdrFcShort( 0x58 ),	/* 88 */
/* 280 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 282 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 284 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 286 */	NdrFcShort( 0x8 ),	/* 8 */
/* 288 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 290 */	NdrFcShort( 0x6c ),	/* 108 */
/* 292 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 294 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 296 */	NdrFcShort( 0xff56 ),	/* Offset= -170 (126) */
/* 298 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 300 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 302 */	NdrFcShort( 0x2 ),	/* 2 */
/* 304 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 306 */	NdrFcShort( 0x8a ),	/* 138 */
/* 308 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 310 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 312 */	NdrFcShort( 0x88 ),	/* 136 */
/* 314 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 316 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 318 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 320 */	NdrFcShort( 0x2 ),	/* 2 */
/* 322 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 324 */	NdrFcShort( 0x92 ),	/* 146 */
/* 326 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 328 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 330 */	NdrFcShort( 0x90 ),	/* 144 */
/* 332 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 334 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 336 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 338 */	NdrFcShort( 0x6 ),	/* 6 */
/* 340 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 342 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 344 */	NdrFcShort( 0x6 ),	/* 6 */
/* 346 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 348 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (336) */
/* 350 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 352 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 354 */	NdrFcShort( 0x4 ),	/* 4 */
/* 356 */	0x4,		/* Corr desc: FC_USMALL */
			0x0,		/*  */
/* 358 */	NdrFcShort( 0xfff9 ),	/* -7 */
/* 360 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 362 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 364 */	
			0x17,		/* FC_CSTRUCT */
			0x3,		/* 3 */
/* 366 */	NdrFcShort( 0x8 ),	/* 8 */
/* 368 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (352) */
/* 370 */	0x2,		/* FC_CHAR */
			0x2,		/* FC_CHAR */
/* 372 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 374 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (342) */
/* 376 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 378 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 380 */	NdrFcShort( 0x8 ),	/* 8 */
/* 382 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 384 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 386 */	NdrFcShort( 0x0 ),	/* 0 */
/* 388 */	NdrFcShort( 0x0 ),	/* 0 */
/* 390 */	0x12, 0x0,	/* FC_UP */
/* 392 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (364) */
/* 394 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 396 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 398 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 400 */	NdrFcShort( 0x8 ),	/* 8 */
/* 402 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 404 */	NdrFcShort( 0xc4 ),	/* 196 */
/* 406 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 408 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 410 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 412 */	NdrFcShort( 0x8 ),	/* 8 */
/* 414 */	NdrFcShort( 0x0 ),	/* 0 */
/* 416 */	NdrFcShort( 0x1 ),	/* 1 */
/* 418 */	NdrFcShort( 0x0 ),	/* 0 */
/* 420 */	NdrFcShort( 0x0 ),	/* 0 */
/* 422 */	0x12, 0x0,	/* FC_UP */
/* 424 */	NdrFcShort( 0xffc4 ),	/* Offset= -60 (364) */
/* 426 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 428 */	0x0,		/* 0 */
			NdrFcShort( 0xffcd ),	/* Offset= -51 (378) */
			0x5b,		/* FC_END */
/* 432 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 434 */	NdrFcShort( 0x8 ),	/* 8 */
/* 436 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 438 */	NdrFcShort( 0xd0 ),	/* 208 */
/* 440 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 442 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 444 */	NdrFcShort( 0xfec2 ),	/* Offset= -318 (126) */
/* 446 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 448 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 450 */	NdrFcShort( 0xd8 ),	/* 216 */
/* 452 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 454 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 456 */	NdrFcShort( 0x34 ),	/* 52 */
/* 458 */	NdrFcShort( 0x34 ),	/* 52 */
/* 460 */	0x12, 0x0,	/* FC_UP */
/* 462 */	NdrFcShort( 0xfee2 ),	/* Offset= -286 (176) */
/* 464 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 466 */	NdrFcShort( 0x3c ),	/* 60 */
/* 468 */	NdrFcShort( 0x3c ),	/* 60 */
/* 470 */	0x12, 0x0,	/* FC_UP */
/* 472 */	NdrFcShort( 0xfeea ),	/* Offset= -278 (194) */
/* 474 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 476 */	NdrFcShort( 0x44 ),	/* 68 */
/* 478 */	NdrFcShort( 0x44 ),	/* 68 */
/* 480 */	0x12, 0x0,	/* FC_UP */
/* 482 */	NdrFcShort( 0xfef2 ),	/* Offset= -270 (212) */
/* 484 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 486 */	NdrFcShort( 0x4c ),	/* 76 */
/* 488 */	NdrFcShort( 0x4c ),	/* 76 */
/* 490 */	0x12, 0x0,	/* FC_UP */
/* 492 */	NdrFcShort( 0xfefa ),	/* Offset= -262 (230) */
/* 494 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 496 */	NdrFcShort( 0x54 ),	/* 84 */
/* 498 */	NdrFcShort( 0x54 ),	/* 84 */
/* 500 */	0x12, 0x0,	/* FC_UP */
/* 502 */	NdrFcShort( 0xff02 ),	/* Offset= -254 (248) */
/* 504 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 506 */	NdrFcShort( 0x5c ),	/* 92 */
/* 508 */	NdrFcShort( 0x5c ),	/* 92 */
/* 510 */	0x12, 0x0,	/* FC_UP */
/* 512 */	NdrFcShort( 0xff0a ),	/* Offset= -246 (266) */
/* 514 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 516 */	NdrFcShort( 0x70 ),	/* 112 */
/* 518 */	NdrFcShort( 0x70 ),	/* 112 */
/* 520 */	0x12, 0x0,	/* FC_UP */
/* 522 */	NdrFcShort( 0xff12 ),	/* Offset= -238 (284) */
/* 524 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 526 */	NdrFcShort( 0x8c ),	/* 140 */
/* 528 */	NdrFcShort( 0x8c ),	/* 140 */
/* 530 */	0x12, 0x0,	/* FC_UP */
/* 532 */	NdrFcShort( 0xff18 ),	/* Offset= -232 (300) */
/* 534 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 536 */	NdrFcShort( 0x94 ),	/* 148 */
/* 538 */	NdrFcShort( 0x94 ),	/* 148 */
/* 540 */	0x12, 0x0,	/* FC_UP */
/* 542 */	NdrFcShort( 0xff20 ),	/* Offset= -224 (318) */
/* 544 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 546 */	NdrFcShort( 0x98 ),	/* 152 */
/* 548 */	NdrFcShort( 0x98 ),	/* 152 */
/* 550 */	0x12, 0x0,	/* FC_UP */
/* 552 */	NdrFcShort( 0xff44 ),	/* Offset= -188 (364) */
/* 554 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 556 */	NdrFcShort( 0xc8 ),	/* 200 */
/* 558 */	NdrFcShort( 0xc8 ),	/* 200 */
/* 560 */	0x12, 0x0,	/* FC_UP */
/* 562 */	NdrFcShort( 0xff5c ),	/* Offset= -164 (398) */
/* 564 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 566 */	NdrFcShort( 0xcc ),	/* 204 */
/* 568 */	NdrFcShort( 0xcc ),	/* 204 */
/* 570 */	0x12, 0x0,	/* FC_UP */
/* 572 */	NdrFcShort( 0xff30 ),	/* Offset= -208 (364) */
/* 574 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 576 */	NdrFcShort( 0xd4 ),	/* 212 */
/* 578 */	NdrFcShort( 0xd4 ),	/* 212 */
/* 580 */	0x12, 0x0,	/* FC_UP */
/* 582 */	NdrFcShort( 0xff6a ),	/* Offset= -150 (432) */
/* 584 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 586 */	0x0,		/* 0 */
			NdrFcShort( 0xfe33 ),	/* Offset= -461 (126) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 590 */	0x0,		/* 0 */
			NdrFcShort( 0xfe2f ),	/* Offset= -465 (126) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 594 */	0x0,		/* 0 */
			NdrFcShort( 0xfe2b ),	/* Offset= -469 (126) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 598 */	0x0,		/* 0 */
			NdrFcShort( 0xfe27 ),	/* Offset= -473 (126) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 602 */	0x0,		/* 0 */
			NdrFcShort( 0xfe23 ),	/* Offset= -477 (126) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 606 */	0x0,		/* 0 */
			NdrFcShort( 0xfe1f ),	/* Offset= -481 (126) */
			0x6,		/* FC_SHORT */
/* 610 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 612 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 614 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 616 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 618 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 620 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 622 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 624 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 626 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 628 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 630 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 632 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 634 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 636 */	NdrFcShort( 0xfe24 ),	/* Offset= -476 (160) */
/* 638 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 640 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 642 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 644 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 646 */	0x0,		/* 0 */
			NdrFcShort( 0xfe23 ),	/* Offset= -477 (170) */
			0x8,		/* FC_LONG */
/* 650 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 652 */	0x0,		/* 0 */
			NdrFcShort( 0xfdf1 ),	/* Offset= -527 (126) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 656 */	0x0,		/* 0 */
			NdrFcShort( 0xfded ),	/* Offset= -531 (126) */
			0x8,		/* FC_LONG */
/* 660 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 662 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 664 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 666 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */

			0x0
        }
    };
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif