/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dpapi.h"
#include "../modules/kull_m_cred.h"
#include "../../sekurlsa/kuhl_m_sekurlsa.h"

typedef struct _KUHL_M_DPAPI_ENCRYPTED_CRED {
	DWORD version;
	DWORD blobSize;
	DWORD unk;
	BYTE blob[ANYSIZE_ARRAY];
} KUHL_M_DPAPI_ENCRYPTED_CRED, *PKUHL_M_DPAPI_ENCRYPTED_CRED;

NTSTATUS kuhl_m_dpapi_cred(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_vault(int argc, wchar_t * argv[]);

void kuhl_m_dpapi_cred_tryEncrypted(LPCWSTR target, LPCBYTE data, DWORD dataLen, int argc, wchar_t * argv[]);
BOOL kuhl_m_dpapi_vault_key_type(PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute, HCRYPTPROV hProv, BYTE aes128[AES_128_KEY_SIZE], BYTE aes256[AES_256_KEY_SIZE], HCRYPTKEY *hKey, BOOL *isAttr);
void kuhl_m_dpapi_vault_basic(PVOID data, DWORD size, GUID *schema);