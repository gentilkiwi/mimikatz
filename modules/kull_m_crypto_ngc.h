/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_crypto_sk.h"

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

typedef SECURITY_STATUS	(WINAPI * PNCRYPTKEYDERIVATION) (NCRYPT_KEY_HANDLE hKey, NCryptBufferDesc *pParameterList, PUCHAR pbDerivedKey, DWORD cbDerivedKey, DWORD *pcbResult, ULONG dwFlags); // tofix
typedef NTSTATUS (WINAPI * PNGCSIGNWITHSYMMETRICPOPKEY) (PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput); // tofix

BOOL kull_m_crypto_ngc_keyvalue_derived_software(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
BOOL kull_m_crypto_ngc_keyvalue_derived_hardware(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCWSTR TransportKeyName, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
BOOL kull_m_crypto_ngc_signature_derived(LPCBYTE pcbKey, DWORD cbKey, LPCBYTE pcbData, DWORD cbData, LPBYTE pbHash, DWORD cbHash);
BOOL kull_m_crypto_ngc_signature_pop(PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput);