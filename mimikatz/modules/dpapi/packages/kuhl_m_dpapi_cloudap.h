/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dpapi.h"

typedef struct _KIWI_POPKEY {
	DWORD version;
	DWORD type; // 1 soft, 2 hard
	BYTE key[ANYSIZE_ARRAY];
} KIWI_POPKEY, *PKIWI_POPKEY;

typedef struct _KIWI_POPKEY_HARD {
	DWORD version;
	DWORD cbName;
	DWORD cbKey;
	BYTE data[ANYSIZE_ARRAY];
} KIWI_POPKEY_HARD, *PKIWI_POPKEY_HARD;

NTSTATUS kuhl_m_dpapi_cloudap_keyvalue_derived(int argc, wchar_t * argv[]);

BOOL kuhl_m_dpapi_cloudap_keyvalue_derived_software(PNCryptBufferDesc bufferDesc, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
typedef SECURITY_STATUS	(WINAPI * PNCRYPTKEYDERIVATION) (NCRYPT_KEY_HANDLE hKey, NCryptBufferDesc *pParameterList, PUCHAR pbDerivedKey, DWORD cbDerivedKey, DWORD *pcbResult, ULONG dwFlags); // tofix
BOOL kuhl_m_dpapi_cloudap_keyvalue_derived_hardware(PNCryptBufferDesc bufferDesc, LPCWSTR TransportKeyName, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);