/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../kuhl_m_dpapi.h"
#include "../modules/kull_m_cred.h"

typedef struct _KUHL_M_DPAPI_ENCRYPTED_CRED {
	DWORD version;
	DWORD blobSize;
	DWORD unk;
	BYTE blob[ANYSIZE_ARRAY];
} KUHL_M_DPAPI_ENCRYPTED_CRED, *PKUHL_M_DPAPI_ENCRYPTED_CRED;

NTSTATUS kuhl_m_dpapi_cred(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_vault(int argc, wchar_t * argv[]);
void kuhl_m_dpapi_vault_basic(PVOID data, DWORD size, GUID *schema);