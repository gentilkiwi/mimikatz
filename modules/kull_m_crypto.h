/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"

#define AES_256_KEY_SIZE	(256/8)
#define AES_128_KEY_SIZE	(128/8)
#define AES_BLOCK_SIZE		16

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, *PGENERICKEY_BLOB;

BOOL kull_m_crypto_hash(ALG_ID algid, LPCVOID data, DWORD dataLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_hkey(HCRYPTPROV hProv, DWORD calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey, HCRYPTPROV *hSessionProv);
BOOL kull_m_crypto_hmac(DWORD calgid, LPCVOID key, DWORD keyLen, LPCVOID message, DWORD messageLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_pkcs5_pbkdf2_hmac(DWORD calgid, LPCVOID password, DWORD passwordLen, LPCVOID salt, DWORD saltLen, DWORD iterations, BYTE *key, DWORD keyLen);
BOOL kull_m_crypto_aesCTSEncryptDecrypt(DWORD aesCalgId, PVOID data, DWORD szData, PVOID key, DWORD szKey, PVOID pbIV, BOOL encrypt);
BOOL kull_m_crypto_DeriveKeyRaw(ALG_ID hashId, LPVOID hash, DWORD hashLen, LPVOID key, DWORD keyLen);
BOOL kull_m_crypto_close_hprov_delete_container(HCRYPTPROV hProv);
BOOL kull_m_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hSessionKey, HCRYPTPROV *hSessionProv);

typedef struct _KULL_M_CRYPTO_DUAL_STRING_DWORD {
	PCWSTR	name;
	DWORD	id;
} KULL_M_CRYPTO_DUAL_STRING_DWORD, *PKULL_M_CRYPTO_DUAL_STRING_DWORD;

typedef struct _KULL_M_CRYPTO_DUAL_STRING_STRING {
	PCWSTR	name;
	PCWSTR	realname;
} KULL_M_CRYPTO_DUAL_STRING_STRING, *PKULL_M_CRYPTO_DUAL_STRING_STRING;

DWORD kull_m_crypto_system_store_to_dword(PCWSTR name);
DWORD kull_m_crypto_provider_type_to_dword(PCWSTR name);
PCWCHAR kull_m_crypto_provider_to_realname(PCWSTR name);
PCWCHAR kull_m_crypto_keytype_to_str(const DWORD keyType);
PCWCHAR kull_m_crypto_algid_to_name(ALG_ID algid);