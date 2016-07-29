#pragma once
#include "kull_m_rpc.h"

typedef enum _KIWI_CREDENTIAL_KEY_TYPE {
	CREDENTIALS_KEY_TYPE_NTLM = 1,
	CREDENTIALS_KEY_TYPE_SHA1 = 2,
	CREDENTIALS_KEY_TYPE_ROOTKEY = 3,
	CREDENTIALS_KEY_TYPE_DPAPI_PROTECTION = 4,
} KIWI_CREDENTIAL_KEY_TYPE;

#pragma pack(push, 4) 
typedef struct _KIWI_CREDENTIAL_KEY {
	DWORD unkEnum; // version ?
	KIWI_CREDENTIAL_KEY_TYPE type;
	WORD iterations;
	WORD cbData;
	BYTE *pbData;
} KIWI_CREDENTIAL_KEY, *PKIWI_CREDENTIAL_KEY;

typedef struct _KIWI_CREDENTIAL_KEYS {
	DWORD count;
	KIWI_CREDENTIAL_KEY keys[ANYSIZE_ARRAY];
} KIWI_CREDENTIAL_KEYS, *PKIWI_CREDENTIAL_KEYS;
#pragma pack(pop)

void CredentialKeys_Decode(handle_t _MidlEsHandle, PKIWI_CREDENTIAL_KEYS * _pType);
void CredentialKeys_Free(handle_t _MidlEsHandle, PKIWI_CREDENTIAL_KEYS * _pType);

#define kull_m_rpc_DecodeCredentialKeys(/*PVOID */data, /*DWORD */size, /*PKIWI_CREDENTIAL_KEYS **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) CredentialKeys_Decode)
#define kull_m_rpc_FreeCredentialKeys(/*PKIWI_CREDENTIAL_KEYS **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) CredentialKeys_Free)