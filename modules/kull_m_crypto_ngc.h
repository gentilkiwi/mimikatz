/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_crypto.h"
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

typedef struct _KIWI_NGC_CREDENTIAL {
	DWORD dwVersion;
	DWORD cbEncryptedKey;
	DWORD cbIV;
	DWORD cbEncryptedPassword;
	DWORD cbUnk;
	BYTE Data[ANYSIZE_ARRAY];
	// ...
} KIWI_NGC_CREDENTIAL, *PKIWI_NGC_CREDENTIAL;

typedef struct _UNK_PIN {
	DWORD cbData;
	DWORD unk0;
	PWSTR pData;
} UNK_PIN, *PUNK_PIN;

typedef struct _UNK_PADDING {
	DWORD unk0;
	DWORD unk1;
	PUNK_PIN pin;
} UNK_PADDING, *PUNK_PADDING;

typedef SECURITY_STATUS	(WINAPI * PNCRYPTKEYDERIVATION) (NCRYPT_KEY_HANDLE hKey, NCryptBufferDesc *pParameterList, PUCHAR pbDerivedKey, DWORD cbDerivedKey, DWORD *pcbResult, ULONG dwFlags); // tofix
typedef NTSTATUS (WINAPI * PNGCSIGNWITHSYMMETRICPOPKEY) (PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput); // tofix

BOOL kull_m_crypto_ngc_keyvalue_derived_software(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
BOOL kull_m_crypto_ngc_keyvalue_derived_hardware(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCWSTR TransportKeyName, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
BOOL kull_m_crypto_ngc_signature_derived(LPCBYTE pcbKey, DWORD cbKey, LPCBYTE pcbData, DWORD cbData, LPBYTE pbHash, DWORD cbHash);
BOOL kull_m_crypto_ngc_signature_pop(PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput);

PBYTE kull_m_crypto_ngc_pin_BinaryPinToPinProperty(LPCBYTE pbBinary, DWORD cbBinary, DWORD *pcbResult);
SECURITY_STATUS kull_m_crypto_ngc_hardware_unseal(NCRYPT_PROV_HANDLE hProv, LPCBYTE pbPin, DWORD cbPin, LPCBYTE pbInput, DWORD cbInput, PBYTE *ppOutput, DWORD *pcbOutput);
SECURITY_STATUS kull_m_crypto_ngc_software_decrypt(NCRYPT_PROV_HANDLE hProv, LPCWSTR szKeyName, LPCBYTE pbPin, DWORD cbPin, LPCBYTE pbInput, DWORD cbInput, PBYTE *ppOutput, DWORD *pcbOutput);