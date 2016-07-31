#include "kull_m_rpc_ms-pac.h"

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable: 4211)  /* redefine extern to static */
#pragma warning(disable: 4232)  /* dllimport identity*/
#pragma warning(disable: 4024)  /* array to pointer mapping*/

#ifdef _M_X64
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE	339
#elif defined _M_IX86
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE	549
#endif

typedef struct _ms_pac_MIDL_TYPE_FORMAT_STRING
{
	short          Pad;
	unsigned char  Format[_ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE];
} ms_pac_MIDL_TYPE_FORMAT_STRING;

extern const ms_pac_MIDL_TYPE_FORMAT_STRING ms_pac__MIDL_TypeFormatString;
static const RPC_CLIENT_INTERFACE msKrbPac___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0x00000001, 0x0001, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71}}, {1, 0}}, {{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
static const MIDL_TYPE_PICKLING_INFO __MIDL_TypePicklingInfo = {0x33205054, 0x3, 0, 0, 0,};
static RPC_BINDING_HANDLE msKrbPac__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC msKrbPac_StubDesc = {(void *) &msKrbPac___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &msKrbPac__MIDL_AutoBindHandle, 0, 0, 0, 0, ms_pac__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};

size_t PKERB_VALIDATION_INFO_AlignSize(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
{
	return NdrMesTypeAlignSize2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[2], _pType);
}

void PKERB_VALIDATION_INFO_Encode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
{
	NdrMesTypeEncode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[2], _pType);
}

void PKERB_VALIDATION_INFO_Decode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
{
	NdrMesTypeDecode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[2], _pType);
}

void PKERB_VALIDATION_INFO_Free(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType)
{
	NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &msKrbPac_StubDesc, (PFORMAT_STRING) &ms_pac__MIDL_TypeFormatString.Format[2], _pType);
}
#ifdef _M_X64
static const ms_pac_MIDL_TYPE_FORMAT_STRING ms_pac__MIDL_TypeFormatString = {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x0,	/* FC_UP */
/*  4 */	NdrFcShort( 0xd4 ),	/* Offset= 212 (216) */
/*  6 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/*  8 */	NdrFcShort( 0x8 ),	/* 8 */
/* 10 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 12 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 14 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 16 */	NdrFcShort( 0x2 ),	/* 2 */
/* 18 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 20 */	NdrFcShort( 0x2 ),	/* 2 */
/* 22 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 24 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
/* 28 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 30 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 32 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 34 */	NdrFcShort( 0x10 ),	/* 16 */
/* 36 */	NdrFcShort( 0x0 ),	/* 0 */
/* 38 */	NdrFcShort( 0x8 ),	/* Offset= 8 (46) */
/* 40 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 42 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 44 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 46 */	
			0x12, 0x0,	/* FC_UP */
/* 48 */	NdrFcShort( 0xffde ),	/* Offset= -34 (14) */
/* 50 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 52 */	NdrFcShort( 0x8 ),	/* 8 */
/* 54 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 56 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 58 */	NdrFcShort( 0x8 ),	/* 8 */
/* 60 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 62 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (50) */
/* 64 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 66 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 68 */	NdrFcShort( 0x10 ),	/* 16 */
/* 70 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 72 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (56) */
/* 74 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 76 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 78 */	NdrFcShort( 0x10 ),	/* 16 */
/* 80 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 82 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (66) */
/* 84 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 86 */	
			0x1d,		/* FC_SMFARRAY */
			0x3,		/* 3 */
/* 88 */	NdrFcShort( 0x8 ),	/* 8 */
/* 90 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 92 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 94 */	NdrFcShort( 0x0 ),	/* 0 */
/* 96 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 98 */	NdrFcShort( 0x9c ),	/* 156 */
/* 100 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 102 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 106 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 108 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 110 */	NdrFcShort( 0xff98 ),	/* Offset= -104 (6) */
/* 112 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 114 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 116 */	NdrFcShort( 0x6 ),	/* 6 */
/* 118 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 120 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 122 */	NdrFcShort( 0x6 ),	/* 6 */
/* 124 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 126 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (114) */
/* 128 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 130 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 132 */	NdrFcShort( 0x4 ),	/* 4 */
/* 134 */	0x4,		/* Corr desc: FC_USMALL */
			0x0,		/*  */
/* 136 */	NdrFcShort( 0xfff9 ),	/* -7 */
/* 138 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 140 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 142 */	
			0x17,		/* FC_CSTRUCT */
			0x3,		/* 3 */
/* 144 */	NdrFcShort( 0x8 ),	/* 8 */
/* 146 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (130) */
/* 148 */	0x2,		/* FC_CHAR */
			0x2,		/* FC_CHAR */
/* 150 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 152 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (120) */
/* 154 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 156 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 158 */	NdrFcShort( 0x10 ),	/* 16 */
/* 160 */	NdrFcShort( 0x0 ),	/* 0 */
/* 162 */	NdrFcShort( 0x6 ),	/* Offset= 6 (168) */
/* 164 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 166 */	0x40,		/* FC_STRUCTPAD4 */
			0x5b,		/* FC_END */
/* 168 */	
			0x12, 0x0,	/* FC_UP */
/* 170 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (142) */
/* 172 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 174 */	NdrFcShort( 0x0 ),	/* 0 */
/* 176 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 178 */	NdrFcShort( 0x110 ),	/* 272 */
/* 180 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 182 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 186 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 188 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 190 */	NdrFcShort( 0xffde ),	/* Offset= -34 (156) */
/* 192 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 194 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 196 */	NdrFcShort( 0x0 ),	/* 0 */
/* 198 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 200 */	NdrFcShort( 0x128 ),	/* 296 */
/* 202 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 204 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 208 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 210 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 212 */	NdrFcShort( 0xff32 ),	/* Offset= -206 (6) */
/* 214 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 216 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 218 */	NdrFcShort( 0x138 ),	/* 312 */
/* 220 */	NdrFcShort( 0x0 ),	/* 0 */
/* 222 */	NdrFcShort( 0x60 ),	/* Offset= 96 (318) */
/* 224 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 226 */	NdrFcShort( 0xff24 ),	/* Offset= -220 (6) */
/* 228 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 230 */	NdrFcShort( 0xff20 ),	/* Offset= -224 (6) */
/* 232 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 234 */	NdrFcShort( 0xff1c ),	/* Offset= -228 (6) */
/* 236 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 238 */	NdrFcShort( 0xff18 ),	/* Offset= -232 (6) */
/* 240 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 242 */	NdrFcShort( 0xff14 ),	/* Offset= -236 (6) */
/* 244 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 246 */	NdrFcShort( 0xff10 ),	/* Offset= -240 (6) */
/* 248 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 250 */	NdrFcShort( 0xff26 ),	/* Offset= -218 (32) */
/* 252 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 254 */	NdrFcShort( 0xff22 ),	/* Offset= -222 (32) */
/* 256 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 258 */	NdrFcShort( 0xff1e ),	/* Offset= -226 (32) */
/* 260 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 262 */	NdrFcShort( 0xff1a ),	/* Offset= -230 (32) */
/* 264 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 266 */	NdrFcShort( 0xff16 ),	/* Offset= -234 (32) */
/* 268 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 270 */	NdrFcShort( 0xff12 ),	/* Offset= -238 (32) */
/* 272 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 274 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 276 */	0x8,		/* FC_LONG */
			0x36,		/* FC_POINTER */
/* 278 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 280 */	0x0,		/* 0 */
			NdrFcShort( 0xff33 ),	/* Offset= -205 (76) */
			0x40,		/* FC_STRUCTPAD4 */
/* 284 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 286 */	NdrFcShort( 0xff02 ),	/* Offset= -254 (32) */
/* 288 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 290 */	NdrFcShort( 0xfefe ),	/* Offset= -258 (32) */
/* 292 */	0x36,		/* FC_POINTER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 294 */	0x0,		/* 0 */
			NdrFcShort( 0xff2f ),	/* Offset= -209 (86) */
			0x8,		/* FC_LONG */
/* 298 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 300 */	0x0,		/* 0 */
			NdrFcShort( 0xfed9 ),	/* Offset= -295 (6) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 304 */	0x0,		/* 0 */
			NdrFcShort( 0xfed5 ),	/* Offset= -299 (6) */
			0x8,		/* FC_LONG */
/* 308 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 310 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 312 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 314 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 316 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 318 */	
			0x12, 0x0,	/* FC_UP */
/* 320 */	NdrFcShort( 0xff1c ),	/* Offset= -228 (92) */
/* 322 */	
			0x12, 0x0,	/* FC_UP */
/* 324 */	NdrFcShort( 0xff4a ),	/* Offset= -182 (142) */
/* 326 */	
			0x12, 0x0,	/* FC_UP */
/* 328 */	NdrFcShort( 0xff64 ),	/* Offset= -156 (172) */
/* 330 */	
			0x12, 0x0,	/* FC_UP */
/* 332 */	NdrFcShort( 0xff42 ),	/* Offset= -190 (142) */
/* 334 */	
			0x12, 0x0,	/* FC_UP */
/* 336 */	NdrFcShort( 0xff72 ),	/* Offset= -142 (194) */

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
/*  4 */	NdrFcShort( 0x144 ),	/* Offset= 324 (328) */
/*  6 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/*  8 */	NdrFcShort( 0x8 ),	/* 8 */
/* 10 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 12 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 14 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 16 */	NdrFcShort( 0x8 ),	/* 8 */
/* 18 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 20 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 22 */	NdrFcShort( 0x8 ),	/* 8 */
/* 24 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 26 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (14) */
/* 28 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 30 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 32 */	NdrFcShort( 0x10 ),	/* 16 */
/* 34 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 36 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (20) */
/* 38 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 40 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 42 */	NdrFcShort( 0x10 ),	/* 16 */
/* 44 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 46 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (30) */
/* 48 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 50 */	
			0x1d,		/* FC_SMFARRAY */
			0x3,		/* 3 */
/* 52 */	NdrFcShort( 0x8 ),	/* 8 */
/* 54 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 56 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 58 */	NdrFcShort( 0x2 ),	/* 2 */
/* 60 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 62 */	NdrFcShort( 0x32 ),	/* 50 */
/* 64 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 66 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 68 */	NdrFcShort( 0x30 ),	/* 48 */
/* 70 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 72 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 74 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 76 */	NdrFcShort( 0x2 ),	/* 2 */
/* 78 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 80 */	NdrFcShort( 0x3a ),	/* 58 */
/* 82 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 84 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 86 */	NdrFcShort( 0x38 ),	/* 56 */
/* 88 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 90 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 92 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 94 */	NdrFcShort( 0x2 ),	/* 2 */
/* 96 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 98 */	NdrFcShort( 0x42 ),	/* 66 */
/* 100 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 102 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 104 */	NdrFcShort( 0x40 ),	/* 64 */
/* 106 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 108 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 110 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 112 */	NdrFcShort( 0x2 ),	/* 2 */
/* 114 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 116 */	NdrFcShort( 0x4a ),	/* 74 */
/* 118 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 120 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 122 */	NdrFcShort( 0x48 ),	/* 72 */
/* 124 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 126 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 128 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 130 */	NdrFcShort( 0x2 ),	/* 2 */
/* 132 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 134 */	NdrFcShort( 0x52 ),	/* 82 */
/* 136 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 138 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 140 */	NdrFcShort( 0x50 ),	/* 80 */
/* 142 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 144 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 146 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 148 */	NdrFcShort( 0x2 ),	/* 2 */
/* 150 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 152 */	NdrFcShort( 0x5a ),	/* 90 */
/* 154 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 156 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 158 */	NdrFcShort( 0x58 ),	/* 88 */
/* 160 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 162 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 164 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 166 */	NdrFcShort( 0x8 ),	/* 8 */
/* 168 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 170 */	NdrFcShort( 0x6c ),	/* 108 */
/* 172 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 174 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 176 */	NdrFcShort( 0xff56 ),	/* Offset= -170 (6) */
/* 178 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 180 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 182 */	NdrFcShort( 0x2 ),	/* 2 */
/* 184 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 186 */	NdrFcShort( 0x8a ),	/* 138 */
/* 188 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 190 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 192 */	NdrFcShort( 0x88 ),	/* 136 */
/* 194 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 196 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 198 */	
			0x1c,		/* FC_CVARRAY */
			0x1,		/* 1 */
/* 200 */	NdrFcShort( 0x2 ),	/* 2 */
/* 202 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 204 */	NdrFcShort( 0x92 ),	/* 146 */
/* 206 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 208 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x55,		/* FC_DIV_2 */
/* 210 */	NdrFcShort( 0x90 ),	/* 144 */
/* 212 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 214 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 216 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 218 */	NdrFcShort( 0x6 ),	/* 6 */
/* 220 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 222 */	
			0x15,		/* FC_STRUCT */
			0x0,		/* 0 */
/* 224 */	NdrFcShort( 0x6 ),	/* 6 */
/* 226 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 228 */	NdrFcShort( 0xfff4 ),	/* Offset= -12 (216) */
/* 230 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 232 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 234 */	NdrFcShort( 0x4 ),	/* 4 */
/* 236 */	0x4,		/* Corr desc: FC_USMALL */
			0x0,		/*  */
/* 238 */	NdrFcShort( 0xfff9 ),	/* -7 */
/* 240 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 242 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 244 */	
			0x17,		/* FC_CSTRUCT */
			0x3,		/* 3 */
/* 246 */	NdrFcShort( 0x8 ),	/* 8 */
/* 248 */	NdrFcShort( 0xfff0 ),	/* Offset= -16 (232) */
/* 250 */	0x2,		/* FC_CHAR */
			0x2,		/* FC_CHAR */
/* 252 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 254 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (222) */
/* 256 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 258 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 260 */	NdrFcShort( 0x8 ),	/* 8 */
/* 262 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 264 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 266 */	NdrFcShort( 0x0 ),	/* 0 */
/* 268 */	NdrFcShort( 0x0 ),	/* 0 */
/* 270 */	0x12, 0x0,	/* FC_UP */
/* 272 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (244) */
/* 274 */	
			0x5b,		/* FC_END */

			0x8,		/* FC_LONG */
/* 276 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 278 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 280 */	NdrFcShort( 0x8 ),	/* 8 */
/* 282 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 284 */	NdrFcShort( 0xc4 ),	/* 196 */
/* 286 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 288 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 290 */	
			0x48,		/* FC_VARIABLE_REPEAT */
			0x49,		/* FC_FIXED_OFFSET */
/* 292 */	NdrFcShort( 0x8 ),	/* 8 */
/* 294 */	NdrFcShort( 0x0 ),	/* 0 */
/* 296 */	NdrFcShort( 0x1 ),	/* 1 */
/* 298 */	NdrFcShort( 0x0 ),	/* 0 */
/* 300 */	NdrFcShort( 0x0 ),	/* 0 */
/* 302 */	0x12, 0x0,	/* FC_UP */
/* 304 */	NdrFcShort( 0xffc4 ),	/* Offset= -60 (244) */
/* 306 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 308 */	0x0,		/* 0 */
			NdrFcShort( 0xffcd ),	/* Offset= -51 (258) */
			0x5b,		/* FC_END */
/* 312 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 314 */	NdrFcShort( 0x8 ),	/* 8 */
/* 316 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 318 */	NdrFcShort( 0xd0 ),	/* 208 */
/* 320 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 322 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 324 */	NdrFcShort( 0xfec2 ),	/* Offset= -318 (6) */
/* 326 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 328 */	
			0x16,		/* FC_PSTRUCT */
			0x3,		/* 3 */
/* 330 */	NdrFcShort( 0xd8 ),	/* 216 */
/* 332 */	
			0x4b,		/* FC_PP */
			0x5c,		/* FC_PAD */
/* 334 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 336 */	NdrFcShort( 0x34 ),	/* 52 */
/* 338 */	NdrFcShort( 0x34 ),	/* 52 */
/* 340 */	0x12, 0x0,	/* FC_UP */
/* 342 */	NdrFcShort( 0xfee2 ),	/* Offset= -286 (56) */
/* 344 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 346 */	NdrFcShort( 0x3c ),	/* 60 */
/* 348 */	NdrFcShort( 0x3c ),	/* 60 */
/* 350 */	0x12, 0x0,	/* FC_UP */
/* 352 */	NdrFcShort( 0xfeea ),	/* Offset= -278 (74) */
/* 354 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 356 */	NdrFcShort( 0x44 ),	/* 68 */
/* 358 */	NdrFcShort( 0x44 ),	/* 68 */
/* 360 */	0x12, 0x0,	/* FC_UP */
/* 362 */	NdrFcShort( 0xfef2 ),	/* Offset= -270 (92) */
/* 364 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 366 */	NdrFcShort( 0x4c ),	/* 76 */
/* 368 */	NdrFcShort( 0x4c ),	/* 76 */
/* 370 */	0x12, 0x0,	/* FC_UP */
/* 372 */	NdrFcShort( 0xfefa ),	/* Offset= -262 (110) */
/* 374 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 376 */	NdrFcShort( 0x54 ),	/* 84 */
/* 378 */	NdrFcShort( 0x54 ),	/* 84 */
/* 380 */	0x12, 0x0,	/* FC_UP */
/* 382 */	NdrFcShort( 0xff02 ),	/* Offset= -254 (128) */
/* 384 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 386 */	NdrFcShort( 0x5c ),	/* 92 */
/* 388 */	NdrFcShort( 0x5c ),	/* 92 */
/* 390 */	0x12, 0x0,	/* FC_UP */
/* 392 */	NdrFcShort( 0xff0a ),	/* Offset= -246 (146) */
/* 394 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 396 */	NdrFcShort( 0x70 ),	/* 112 */
/* 398 */	NdrFcShort( 0x70 ),	/* 112 */
/* 400 */	0x12, 0x0,	/* FC_UP */
/* 402 */	NdrFcShort( 0xff12 ),	/* Offset= -238 (164) */
/* 404 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 406 */	NdrFcShort( 0x8c ),	/* 140 */
/* 408 */	NdrFcShort( 0x8c ),	/* 140 */
/* 410 */	0x12, 0x0,	/* FC_UP */
/* 412 */	NdrFcShort( 0xff18 ),	/* Offset= -232 (180) */
/* 414 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 416 */	NdrFcShort( 0x94 ),	/* 148 */
/* 418 */	NdrFcShort( 0x94 ),	/* 148 */
/* 420 */	0x12, 0x0,	/* FC_UP */
/* 422 */	NdrFcShort( 0xff20 ),	/* Offset= -224 (198) */
/* 424 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 426 */	NdrFcShort( 0x98 ),	/* 152 */
/* 428 */	NdrFcShort( 0x98 ),	/* 152 */
/* 430 */	0x12, 0x0,	/* FC_UP */
/* 432 */	NdrFcShort( 0xff44 ),	/* Offset= -188 (244) */
/* 434 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 436 */	NdrFcShort( 0xc8 ),	/* 200 */
/* 438 */	NdrFcShort( 0xc8 ),	/* 200 */
/* 440 */	0x12, 0x0,	/* FC_UP */
/* 442 */	NdrFcShort( 0xff5c ),	/* Offset= -164 (278) */
/* 444 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 446 */	NdrFcShort( 0xcc ),	/* 204 */
/* 448 */	NdrFcShort( 0xcc ),	/* 204 */
/* 450 */	0x12, 0x0,	/* FC_UP */
/* 452 */	NdrFcShort( 0xff30 ),	/* Offset= -208 (244) */
/* 454 */	
			0x46,		/* FC_NO_REPEAT */
			0x5c,		/* FC_PAD */
/* 456 */	NdrFcShort( 0xd4 ),	/* 212 */
/* 458 */	NdrFcShort( 0xd4 ),	/* 212 */
/* 460 */	0x12, 0x0,	/* FC_UP */
/* 462 */	NdrFcShort( 0xff6a ),	/* Offset= -150 (312) */
/* 464 */	
			0x5b,		/* FC_END */

			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 466 */	0x0,		/* 0 */
			NdrFcShort( 0xfe33 ),	/* Offset= -461 (6) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 470 */	0x0,		/* 0 */
			NdrFcShort( 0xfe2f ),	/* Offset= -465 (6) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 474 */	0x0,		/* 0 */
			NdrFcShort( 0xfe2b ),	/* Offset= -469 (6) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 478 */	0x0,		/* 0 */
			NdrFcShort( 0xfe27 ),	/* Offset= -473 (6) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 482 */	0x0,		/* 0 */
			NdrFcShort( 0xfe23 ),	/* Offset= -477 (6) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 486 */	0x0,		/* 0 */
			NdrFcShort( 0xfe1f ),	/* Offset= -481 (6) */
			0x6,		/* FC_SHORT */
/* 490 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 492 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 494 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 496 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 498 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 500 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 502 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 504 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 506 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 508 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 510 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 512 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 514 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 516 */	NdrFcShort( 0xfe24 ),	/* Offset= -476 (40) */
/* 518 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 520 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 522 */	0x6,		/* FC_SHORT */
			0x8,		/* FC_LONG */
/* 524 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 526 */	0x0,		/* 0 */
			NdrFcShort( 0xfe23 ),	/* Offset= -477 (50) */
			0x8,		/* FC_LONG */
/* 530 */	0x8,		/* FC_LONG */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 532 */	0x0,		/* 0 */
			NdrFcShort( 0xfdf1 ),	/* Offset= -527 (6) */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 536 */	0x0,		/* 0 */
			NdrFcShort( 0xfded ),	/* Offset= -531 (6) */
			0x8,		/* FC_LONG */
/* 540 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 542 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 544 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 546 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */

			0x0
        }
    };
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif