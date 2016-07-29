#include "kull_m_rpc_ms-credentialkeys.h"

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable: 4211)  /* redefine extern to static */
#pragma warning(disable: 4232)  /* dllimport identity*/
#pragma warning(disable: 4024)  /* array to pointer mapping*/

typedef struct _ms_credentialkeys_MIDL_TYPE_FORMAT_STRING {
	short          Pad;
	unsigned char  Format[70];
} ms_credentialkeys_MIDL_TYPE_FORMAT_STRING;

extern const ms_credentialkeys_MIDL_TYPE_FORMAT_STRING ms_credentialkeys__MIDL_TypeFormatString;
static const RPC_CLIENT_INTERFACE mscredentialkeys___RpcClientInterface = {sizeof(RPC_CLIENT_INTERFACE), {{0xd9ae4745, 0x178e, 0x4561, {0xa5, 0x3f, 0xf0, 0x84, 0xf9, 0x92, 0x13, 0xe5}}, {1, 0}}, {{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}}, {2, 0}}, 0, 0, 0, 0, 0, 0x00000000};
static const MIDL_TYPE_PICKLING_INFO __MIDL_TypePicklingInfo = {0x33205054, 0x3, 0, 0, 0,};
static RPC_BINDING_HANDLE mscredentialkeys__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC mscredentialkeys_StubDesc = {(void *) &mscredentialkeys___RpcClientInterface, MIDL_user_allocate, MIDL_user_free, &mscredentialkeys__MIDL_AutoBindHandle, 0, 0, 0, 0, ms_credentialkeys__MIDL_TypeFormatString.Format, 1, 0x60000, 0, 0x8000253, 0, 0, 0, 0x1, 0, 0, 0};

void CredentialKeys_Decode(handle_t _MidlEsHandle, PKIWI_CREDENTIAL_KEYS * _pType)
{
	NdrMesTypeDecode2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &mscredentialkeys_StubDesc, (PFORMAT_STRING) &ms_credentialkeys__MIDL_TypeFormatString.Format[1], _pType);
}

void CredentialKeys_Free(handle_t _MidlEsHandle, PKIWI_CREDENTIAL_KEYS * _pType)
{
	NdrMesTypeFree2(_MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO) &__MIDL_TypePicklingInfo, &mscredentialkeys_StubDesc, (PFORMAT_STRING) &ms_credentialkeys__MIDL_TypeFormatString.Format[1], _pType);
}

static const ms_credentialkeys_MIDL_TYPE_FORMAT_STRING ms_credentialkeys__MIDL_TypeFormatString = {
	0,
	{
		0x00,
			0x12, 0x01,
			0x36, /* FC_POINTER */
			0x00,
			
			0x1B, /* FC_CARRAY */
				0x00,
				NdrFcShort(0x1), /* 1 */
				0x17, /* Corr desc: FC_CSTRUCT */
				0x00,
				NdrFcShort(0xa),
				NdrFcShort(0x1), /* Corr flags:  early, */
				0x02, /* FC_CHAR */
			0x5B, /* FC_END */

			0x1A, /* FC_BOGUS_STRUCT */
				0x3,
				#ifdef _M_X64
					NdrFcShort(0x14),	// size 20
				#elif defined _M_IX86
					NdrFcShort(0x10),	// size 16
				#endif
				NdrFcShort(0x0),
				NdrFcShort(0x8),
				0x0D, /* FC_ENUM16 */
				0x0D, /* FC_ENUM16 */
				0x06, /* FC_SHORT */
				0x06, /* FC_SHORT */
				0x36, /* FC_POINTER */
			0x5B, /* FC_END */

			0x12, 0x20,
			NdrFcShort(0xffe4), /* Offset= -28 ...*/

			0x21, /* FC_BOGUS_ARRAY */
				0x03, /* 3 */
				NdrFcShort(0x0), /* 0 */
				0x07, /* FC_USHORT */
				0x00,
				NdrFcShort(0xfffc), /* Offset= -4 ...*/
				NdrFcShort(0x1),	/* Corr flags:  early, */
				NdrFcLong(0xffffffff), /* -1 */
				NdrFcShort(0x0), /* Corr flags:  */
				0x4C, /* FC_EMBEDDED_COMPLEX */
				0x00,
				NdrFcShort(0xffdc), 	/* Offset= -36 ...*/
			0x5C, /* FC_PAD */
			0x5B, /* FC_END */

			0x1A, /* FC_BOGUS_STRUCT */
				0x03,
				NdrFcShort(0x4),
				NdrFcShort(0xffe6), 	/* Offset= -26 ...*/
				NdrFcShort(0x0),
				0x06, /* FC_SHORT */
				0x3E, /* FC_STRUCTPAD2 */
			0x5C, /* FC_PAD */
			0x5B, /* FC_END */
		0x00
	}
};

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif