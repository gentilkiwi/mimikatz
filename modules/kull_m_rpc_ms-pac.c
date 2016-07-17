#include "kull_m_rpc_ms-pac.h"

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable: 4211)  /* redefine extern to static */
#pragma warning(disable: 4232)  /* dllimport identity*/
#pragma warning(disable: 4024)  /* array to pointer mapping*/

#ifdef _M_X64
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE	351
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_PKERB_VALIDATION_INFO_Offset	346
#elif defined _M_IX86
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE	561
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_PKERB_VALIDATION_INFO_Offset	556
#endif

typedef struct _ms_pac_MIDL_TYPE_FORMAT_STRING
{
	short          Pad;
	unsigned char  Format[_ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE];
} ms_pac_MIDL_TYPE_FORMAT_STRING;

extern const ms_pac_MIDL_TYPE_FORMAT_STRING ms_pac__MIDL_TypeFormatString;
static const RPC_CLIENT_INTERFACE msKrbPac___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0x3dde7c30, 0x0000, 0x11d1, {0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40}}, {1, 0}}, {{0x8A885D04, 0x1CEB, 0x11C9, {0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
static const MIDL_TYPE_PICKLING_INFO __MIDL_TypePicklingInfo = {0x33205054, 0x3, 0, 0, 0,};
static RPC_BINDING_HANDLE msKrbPac__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC msKrbPac_StubDesc = {(void *)& msKrbPac___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &msKrbPac__MIDL_AutoBindHandle, 0, 0, 0, 0, ms_pac__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};

size_t PKERB_VALIDATION_INFO_AlignSize(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
{
	return NdrMesTypeAlignSize2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[_ms_pac_MIDL_TYPE_FORMAT_STRING_PKERB_VALIDATION_INFO_Offset], _pType);
}

void PKERB_VALIDATION_INFO_Encode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
{
	NdrMesTypeEncode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[_ms_pac_MIDL_TYPE_FORMAT_STRING_PKERB_VALIDATION_INFO_Offset], _pType);
}

//void PKERB_VALIDATION_INFO_Decode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
//{
//	NdrMesTypeDecode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[_ms_pac_MIDL_TYPE_FORMAT_STRING_PKERB_VALIDATION_INFO_Offset], _pType);
//}
//
//void PKERB_VALIDATION_INFO_Free(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
//{
//	NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[_ms_pac_MIDL_TYPE_FORMAT_STRING_PKERB_VALIDATION_INFO_Offset], _pType);
//}
#ifdef _M_X64
static const ms_pac_MIDL_TYPE_FORMAT_STRING ms_pac__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x0,	/* FC_UP */
/*  4 */	NdrFcShort( 0x1e ),	/* Offset= 30 (34) */
/*  6 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/*  8 */	NdrFcShort( 0x6 ),	/* 6 */
/* 10 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 12 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 14 */	NdrFcShort( 0x6 ),	/* 6 */
/* 16 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 18 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (6) */
/* 20 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 22 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 24 */	NdrFcShort( 0x4 ),	/* 4 */
/* 26 */	0x4,		/* Corr desc: FC_USMALL */
			0x0,		/*  */
/* 28 */	NdrFcShort( 0xfff9 ),	/* -7 */
/* 30 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 32 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 34 */	
			0x17,		/* FC_CSTRUCT */
			0x3,		/* 3 */
/* 36 */	NdrFcShort( 0x8 ),	/* 8 */
/* 38 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (22) */
/* 40 */	0x2,		/* FC_CHAR */
			0x2,		/* FC_CHAR */
/* 42 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 44 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (12) */
/* 46 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 48 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 50 */	NdrFcShort( 0x8 ),	/* 8 */
/* 52 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 54 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 56 */	NdrFcShort( 0x8 ),	/* 8 */
/* 58 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 60 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (48) */
/* 62 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 64 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 66 */	NdrFcShort( 0x10 ),	/* 16 */
/* 68 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 70 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (54) */
/* 72 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 74 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 76 */	NdrFcShort( 0x10 ),	/* 16 */
/* 78 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 80 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (64) */
/* 82 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 84 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 86 */	NdrFcShort( 0x10 ),	/* 16 */
/* 88 */	NdrFcShort( 0x0 ),	/* 0 */
/* 90 */	NdrFcShort( 0x6 ),	/* Offset= 6 (96) */
/* 92 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 94 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 96 */	
			0x12, 0x0,	/* FC_UP */
/* 98 */	NdrFcShort( 0xffc0 ),	/* Offset= -64 (34) */
/* 100 */	
			0x12, 0x0,	/* FC_UP */
/* 102 */	NdrFcShort( 0xffee ),	/* Offset= -18 (84) */
/* 104 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 106 */	NdrFcShort( 0x8 ),	/* 8 */
/* 108 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 110 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 112 */	
			0x12, 0x0,	/* FC_UP */
/* 114 */	NdrFcShort( 0xfff6 ),	/* Offset= -10 (104) */
/* 116 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 118 */	NdrFcShort( 0x2 ),	/* 2 */
/* 120 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 122 */	NdrFcShort( 0x2 ),	/* 2 */
/* 124 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 126 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 128 */	NdrFcShort( 0x0 ),	/* 0 */
/* 130 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 132 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 134 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 136 */	NdrFcShort( 0x10 ),	/* 16 */
/* 138 */	NdrFcShort( 0x0 ),	/* 0 */
/* 140 */	NdrFcShort( 0x8 ),	/* Offset= 8 (148) */
/* 142 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 144 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 146 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 148 */	
			0x12, 0x0,	/* FC_UP */
/* 150 */	NdrFcShort( 0xffde ),	/* Offset= -34 (116) */
/* 152 */	
			0x1d,		/* FC_SMFARRAY */
			0x3,		/* 3 */
/* 154 */	NdrFcShort( 0x8 ),	/* 8 */
/* 156 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 158 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 160 */	NdrFcShort( 0x0 ),	/* 0 */
/* 162 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 164 */	NdrFcShort( 0x9c ),	/* 156 */
/* 166 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 168 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 172 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 174 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 176 */	NdrFcShort( 0xffb8 ),	/* Offset= -72 (104) */
/* 178 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 180 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 182 */	NdrFcShort( 0x0 ),	/* 0 */
/* 184 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 186 */	NdrFcShort( 0x110 ),	/* 272 */
/* 188 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 190 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 194 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 196 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 198 */	NdrFcShort( 0xff8e ),	/* Offset= -114 (84) */
/* 200 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 202 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 204 */	NdrFcShort( 0x0 ),	/* 0 */
/* 206 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 208 */	NdrFcShort( 0x128 ),	/* 296 */
/* 210 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 212 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 216 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 218 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 220 */	NdrFcShort( 0xff8c ),	/* Offset= -116 (104) */
/* 222 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 224 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 226 */	NdrFcShort( 0x138 ),	/* 312 */
/* 228 */	NdrFcShort( 0x0 ),	/* 0 */
/* 230 */	NdrFcShort( 0x60 ),	/* Offset= 96 (326) */
/* 232 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 234 */	NdrFcShort( 0xff7e ),	/* Offset= -130 (104) */
/* 236 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 238 */	NdrFcShort( 0xff7a ),	/* Offset= -134 (104) */
/* 240 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 242 */	NdrFcShort( 0xff76 ),	/* Offset= -138 (104) */
/* 244 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 246 */	NdrFcShort( 0xff72 ),	/* Offset= -142 (104) */
/* 248 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 250 */	NdrFcShort( 0xff6e ),	/* Offset= -146 (104) */
/* 252 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 254 */	NdrFcShort( 0xff6a ),	/* Offset= -150 (104) */
/* 256 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 258 */	NdrFcShort( 0xff84 ),	/* Offset= -124 (134) */
/* 260 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 262 */	NdrFcShort( 0xff80 ),	/* Offset= -128 (134) */
/* 264 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 266 */	NdrFcShort( 0xff7c ),	/* Offset= -132 (134) */
/* 268 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 270 */	NdrFcShort( 0xff78 ),	/* Offset= -136 (134) */
/* 272 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 274 */	NdrFcShort( 0xff74 ),	/* Offset= -140 (134) */
/* 276 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 278 */	NdrFcShort( 0xff70 ),	/* Offset= -144 (134) */
/* 280 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 282 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 284 */	0x8,		/* FC_LONG */
			0x36,		/* FC_POINTER */
/* 286 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 288 */	0x0,		/* 0 */
			NdrFcShort( 0xff29 ),	/* Offset= -215 (74) */
			0x40,		/* FC_STRUCTPAD4 */
/* 292 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 294 */	NdrFcShort( 0xff60 ),	/* Offset= -160 (134) */
/* 296 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 298 */	NdrFcShort( 0xff5c ),	/* Offset= -164 (134) */
/* 300 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 302 */	0x0,		/* 0 */
			NdrFcShort( 0xff69 ),	/* Offset= -151 (152) */
			0x8,		/* FC_LONG */
/* 306 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 308 */	0x0,		/* 0 */
			NdrFcShort( 0xff33 ),	/* Offset= -205 (104) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 312 */	0x0,		/* 0 */
			NdrFcShort( 0xff2f ),	/* Offset= -209 (104) */
			0x8,		/* FC_LONG */
/* 316 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 318 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 320 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 322 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 324 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 326 */	
			0x12, 0x0,	/* FC_UP */
/* 328 */	NdrFcShort( 0xff56 ),	/* Offset= -170 (158) */
/* 330 */	
			0x12, 0x0,	/* FC_UP */
/* 332 */	NdrFcShort( 0xfed6 ),	/* Offset= -298 (34) */
/* 334 */	
			0x12, 0x0,	/* FC_UP */
/* 336 */	NdrFcShort( 0xff64 ),	/* Offset= -156 (180) */
/* 338 */	
			0x12, 0x0,	/* FC_UP */
/* 340 */	NdrFcShort( 0xfece ),	/* Offset= -306 (34) */
/* 342 */	
			0x12, 0x0,	/* FC_UP */
/* 344 */	NdrFcShort( 0xff72 ),	/* Offset= -142 (202) */
/* 346 */	
			0x12, 0x0,	/* FC_UP */
/* 348 */	NdrFcShort( 0xff84 ),	/* Offset= -124 (224) */

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
/*  4 */	NdrFcShort( 0x1e ),	/* Offset= 30 (34) */
/*  6 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/*  8 */	NdrFcShort( 0x6 ),	/* 6 */
/* 10 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 12 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 14 */	NdrFcShort( 0x6 ),	/* 6 */
/* 16 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 18 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (6) */
/* 20 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 22 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 24 */	NdrFcShort( 0x4 ),	/* 4 */
/* 26 */	0x4,		/* Corr desc: FC_USMALL */
			0x0,		/*  */
/* 28 */	NdrFcShort( 0xfff9 ),	/* -7 */
/* 30 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 32 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 34 */	
			0x17,		/* FC_CSTRUCT */
			0x3,		/* 3 */
/* 36 */	NdrFcShort( 0x8 ),	/* 8 */
/* 38 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (22) */
/* 40 */	0x2,		/* FC_CHAR */
			0x2,		/* FC_CHAR */
/* 42 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 44 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (12) */
/* 46 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 48 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 50 */	NdrFcShort( 0x8 ),	/* 8 */
/* 52 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 54 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 56 */	NdrFcShort( 0x8 ),	/* 8 */
/* 58 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 60 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (48) */
/* 62 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 64 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 66 */	NdrFcShort( 0x10 ),	/* 16 */
/* 68 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 70 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (54) */
/* 72 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 74 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 76 */	NdrFcShort( 0x10 ),	/* 16 */
/* 78 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 80 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (64) */
/* 82 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 84 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 86 */	NdrFcShort( 0x8 ),	/* 8 */
/* 88 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 90 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 92 */	NdrFcShort( 0x0 ),	/* 0 */
/* 94 */	NdrFcShort( 0x0 ),	/* 0 */
/* 96 */	0x12, 0x0,	/* FC_UP */
/* 98 */	NdrFcShort( 0xffc0 ),	/* Offset= -64 (34) */
/* 100 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 102 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 104 */	
			0x12, 0x0,	/* FC_UP */
/* 106 */	NdrFcShort( 0xffea ),	/* Offset= -22 (84) */
/* 108 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 110 */	NdrFcShort( 0x8 ),	/* 8 */
/* 112 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 114 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 116 */	
			0x12, 0x0,	/* FC_UP */
/* 118 */	NdrFcShort( 0xfff6 ),	/* Offset= -10 (108) */
/* 120 */	
			0x1d,		/* FC_SMFARRAY */
			0x3,		/* 3 */
/* 122 */	NdrFcShort( 0x8 ),	/* 8 */
/* 124 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 126 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 128 */	NdrFcShort( 0x2 ),	/* 2 */
/* 130 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 132 */	NdrFcShort( 0x32 ),	/* 50 */
/* 134 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 136 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 138 */	NdrFcShort( 0x30 ),	/* 48 */
/* 140 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 142 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 144 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 146 */	NdrFcShort( 0x2 ),	/* 2 */
/* 148 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 150 */	NdrFcShort( 0x3a ),	/* 58 */
/* 152 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 154 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 156 */	NdrFcShort( 0x38 ),	/* 56 */
/* 158 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 160 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 162 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 164 */	NdrFcShort( 0x2 ),	/* 2 */
/* 166 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 168 */	NdrFcShort( 0x42 ),	/* 66 */
/* 170 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 172 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 174 */	NdrFcShort( 0x40 ),	/* 64 */
/* 176 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 178 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 180 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 182 */	NdrFcShort( 0x2 ),	/* 2 */
/* 184 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 186 */	NdrFcShort( 0x4a ),	/* 74 */
/* 188 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 190 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 192 */	NdrFcShort( 0x48 ),	/* 72 */
/* 194 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 196 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 198 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 200 */	NdrFcShort( 0x2 ),	/* 2 */
/* 202 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 204 */	NdrFcShort( 0x52 ),	/* 82 */
/* 206 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 208 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 210 */	NdrFcShort( 0x50 ),	/* 80 */
/* 212 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 214 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 216 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 218 */	NdrFcShort( 0x2 ),	/* 2 */
/* 220 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 222 */	NdrFcShort( 0x5a ),	/* 90 */
/* 224 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 226 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 228 */	NdrFcShort( 0x58 ),	/* 88 */
/* 230 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 232 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 234 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 236 */	NdrFcShort( 0x8 ),	/* 8 */
/* 238 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 240 */	NdrFcShort( 0x6c ),	/* 108 */
/* 242 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 244 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 246 */	NdrFcShort( 0xff76 ),	/* Offset= -138 (108) */
/* 248 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 250 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 252 */	NdrFcShort( 0x2 ),	/* 2 */
/* 254 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 256 */	NdrFcShort( 0x8a ),	/* 138 */
/* 258 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 260 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 262 */	NdrFcShort( 0x88 ),	/* 136 */
/* 264 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 266 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 268 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 270 */	NdrFcShort( 0x2 ),	/* 2 */
/* 272 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 274 */	NdrFcShort( 0x92 ),	/* 146 */
/* 276 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 278 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 280 */	NdrFcShort( 0x90 ),	/* 144 */
/* 282 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 284 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 286 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 288 */	NdrFcShort( 0x8 ),	/* 8 */
/* 290 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 292 */	NdrFcShort( 0xc4 ),	/* 196 */
/* 294 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 296 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 298 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 300 */	NdrFcShort( 0x8 ),	/* 8 */
/* 302 */	NdrFcShort( 0x0 ),	/* 0 */
/* 304 */	NdrFcShort( 0x1 ),	/* 1 */
/* 306 */	NdrFcShort( 0x0 ),	/* 0 */
/* 308 */	NdrFcShort( 0x0 ),	/* 0 */
/* 310 */	0x12, 0x0,	/* FC_UP */
/* 312 */	NdrFcShort( 0xfeea ),	/* Offset= -278 (34) */
/* 314 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 316 */	0x0,		/* 0 */
			NdrFcShort( 0xff17 ),	/* Offset= -233 (84) */
			0x5b,		/* FC_END */
/* 320 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 322 */	NdrFcShort( 0x8 ),	/* 8 */
/* 324 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 326 */	NdrFcShort( 0xd0 ),	/* 208 */
/* 328 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 330 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 332 */	NdrFcShort( 0xff20 ),	/* Offset= -224 (108) */
/* 334 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 336 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 338 */	NdrFcShort( 0xd8 ),	/* 216 */
/* 340 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 342 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 344 */	NdrFcShort( 0x34 ),	/* 52 */
/* 346 */	NdrFcShort( 0x34 ),	/* 52 */
/* 348 */	0x12, 0x0,	/* FC_UP */
/* 350 */	NdrFcShort( 0xff20 ),	/* Offset= -224 (126) */
/* 352 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 354 */	NdrFcShort( 0x3c ),	/* 60 */
/* 356 */	NdrFcShort( 0x3c ),	/* 60 */
/* 358 */	0x12, 0x0,	/* FC_UP */
/* 360 */	NdrFcShort( 0xff28 ),	/* Offset= -216 (144) */
/* 362 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 364 */	NdrFcShort( 0x44 ),	/* 68 */
/* 366 */	NdrFcShort( 0x44 ),	/* 68 */
/* 368 */	0x12, 0x0,	/* FC_UP */
/* 370 */	NdrFcShort( 0xff30 ),	/* Offset= -208 (162) */
/* 372 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 374 */	NdrFcShort( 0x4c ),	/* 76 */
/* 376 */	NdrFcShort( 0x4c ),	/* 76 */
/* 378 */	0x12, 0x0,	/* FC_UP */
/* 380 */	NdrFcShort( 0xff38 ),	/* Offset= -200 (180) */
/* 382 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 384 */	NdrFcShort( 0x54 ),	/* 84 */
/* 386 */	NdrFcShort( 0x54 ),	/* 84 */
/* 388 */	0x12, 0x0,	/* FC_UP */
/* 390 */	NdrFcShort( 0xff40 ),	/* Offset= -192 (198) */
/* 392 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 394 */	NdrFcShort( 0x5c ),	/* 92 */
/* 396 */	NdrFcShort( 0x5c ),	/* 92 */
/* 398 */	0x12, 0x0,	/* FC_UP */
/* 400 */	NdrFcShort( 0xff48 ),	/* Offset= -184 (216) */
/* 402 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 404 */	NdrFcShort( 0x70 ),	/* 112 */
/* 406 */	NdrFcShort( 0x70 ),	/* 112 */
/* 408 */	0x12, 0x0,	/* FC_UP */
/* 410 */	NdrFcShort( 0xff50 ),	/* Offset= -176 (234) */
/* 412 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 414 */	NdrFcShort( 0x8c ),	/* 140 */
/* 416 */	NdrFcShort( 0x8c ),	/* 140 */
/* 418 */	0x12, 0x0,	/* FC_UP */
/* 420 */	NdrFcShort( 0xff56 ),	/* Offset= -170 (250) */
/* 422 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 424 */	NdrFcShort( 0x94 ),	/* 148 */
/* 426 */	NdrFcShort( 0x94 ),	/* 148 */
/* 428 */	0x12, 0x0,	/* FC_UP */
/* 430 */	NdrFcShort( 0xff5e ),	/* Offset= -162 (268) */
/* 432 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 434 */	NdrFcShort( 0x98 ),	/* 152 */
/* 436 */	NdrFcShort( 0x98 ),	/* 152 */
/* 438 */	0x12, 0x0,	/* FC_UP */
/* 440 */	NdrFcShort( 0xfe6a ),	/* Offset= -406 (34) */
/* 442 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 444 */	NdrFcShort( 0xc8 ),	/* 200 */
/* 446 */	NdrFcShort( 0xc8 ),	/* 200 */
/* 448 */	0x12, 0x0,	/* FC_UP */
/* 450 */	NdrFcShort( 0xff5c ),	/* Offset= -164 (286) */
/* 452 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 454 */	NdrFcShort( 0xcc ),	/* 204 */
/* 456 */	NdrFcShort( 0xcc ),	/* 204 */
/* 458 */	0x12, 0x0,	/* FC_UP */
/* 460 */	NdrFcShort( 0xfe56 ),	/* Offset= -426 (34) */
/* 462 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 464 */	NdrFcShort( 0xd4 ),	/* 212 */
/* 466 */	NdrFcShort( 0xd4 ),	/* 212 */
/* 468 */	0x12, 0x0,	/* FC_UP */
/* 470 */	NdrFcShort( 0xff6a ),	/* Offset= -150 (320) */
/* 472 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 474 */	0x0,		/* 0 */
			NdrFcShort( 0xfe91 ),	/* Offset= -367 (108) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 478 */	0x0,		/* 0 */
			NdrFcShort( 0xfe8d ),	/* Offset= -371 (108) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 482 */	0x0,		/* 0 */
			NdrFcShort( 0xfe89 ),	/* Offset= -375 (108) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 486 */	0x0,		/* 0 */
			NdrFcShort( 0xfe85 ),	/* Offset= -379 (108) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 490 */	0x0,		/* 0 */
			NdrFcShort( 0xfe81 ),	/* Offset= -383 (108) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 494 */	0x0,		/* 0 */
			NdrFcShort( 0xfe7d ),	/* Offset= -387 (108) */
			0x6,		/* FC_SHORT */
/* 498 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 500 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 502 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 504 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 506 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 508 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 510 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 512 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 514 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 516 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 518 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 520 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 522 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 524 */	NdrFcShort( 0xfe3e ),	/* Offset= -450 (74) */
/* 526 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 528 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 530 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 532 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 534 */	0x0,		/* 0 */
			NdrFcShort( 0xfe61 ),	/* Offset= -415 (120) */
			0x8,		/* FC_LONG */
/* 538 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 540 */	0x0,		/* 0 */
			NdrFcShort( 0xfe4f ),	/* Offset= -433 (108) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 544 */	0x0,		/* 0 */
			NdrFcShort( 0xfe4b ),	/* Offset= -437 (108) */
			0x8,		/* FC_LONG */
/* 548 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 550 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 552 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 554 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 556 */	
			0x12, 0x0,	/* FC_UP */
/* 558 */	NdrFcShort( 0xff22 ),	/* Offset= -222 (336) */

			0x0
        }
    };
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif