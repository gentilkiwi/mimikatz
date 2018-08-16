/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dpapi.h"
#include "../../../../modules/kull_m_registry.h"
#include "../../kuhl_m_token.h"

NTSTATUS kuhl_m_dpapi_ssh(int argc, wchar_t * argv[]);

void kuhl_m_dpapi_ssh_keys4user(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hUser, LPCWSTR szSID, int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_dpapi_ssh_impersonate(HANDLE hToken, DWORD ptid, PVOID pvArg);
void kuhl_m_dpapi_ssh_getKey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hEntry, int argc, wchar_t * argv[], HANDLE hToken);
BOOL kuhl_m_dpapi_ssh_getRSAfromRAW(LPCBYTE data, DWORD szData);
void kuhl_m_dpapi_ssh_ParseKeyElement(PBYTE *pRaw, PBYTE *pData, DWORD *pszData);
BOOL kuhl_m_dpapi_ssh_EncodeB64_headers(LPCWSTR type, DATA_BLOB *data, LPWSTR *out);

typedef struct _KUHL_M_DPAPI_SSH_TOKEN{
	PSID pSid;
	HANDLE hToken;
} KUHL_M_DPAPI_SSH_TOKEN, *PKUHL_M_DPAPI_SSH_TOKEN;

/* Key types */
enum sshkey_types {
	KEY_RSA,
	KEY_DSA,
	KEY_ECDSA,
	KEY_ED25519,
	KEY_RSA_CERT,
	KEY_DSA_CERT,
	KEY_ECDSA_CERT,
	KEY_ED25519_CERT,
	KEY_XMSS,
	KEY_XMSS_CERT,
	KEY_UNSPEC
};