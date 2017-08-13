/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"
#include "kull_m_crypto_system.h"
#include "kull_m_file.h"

#define CALG_CRC32	(ALG_CLASS_HASH | ALG_TYPE_ANY | 0)

#define AES_256_KEY_SIZE	(256/8)
#define AES_128_KEY_SIZE	(128/8)
#define AES_BLOCK_SIZE		16

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, *PGENERICKEY_BLOB;

typedef struct _RSA_GENERICKEY_BLOB {
	BLOBHEADER Header;
	RSAPUBKEY RsaKey; // works with RSA2 ;)
} RSA_GENERICKEY_BLOB, *PRSA_GENERICKEY_BLOB;

#define PVK_FILE_VERSION_0				0
#define PVK_MAGIC						0xb0b5f11e // bob's file
#define PVK_NO_ENCRYPT					0
#define PVK_RC4_PASSWORD_ENCRYPT		1
#define PVK_RC2_CBC_PASSWORD_ENCRYPT	2

#ifndef IPSEC_FLAG_CHECK
#define IPSEC_FLAG_CHECK 0xf42a19b6
#endif

typedef struct _PVK_FILE_HDR {
	DWORD	dwMagic;
	DWORD	dwVersion;
	DWORD	dwKeySpec;
	DWORD	dwEncryptType;
	DWORD	cbEncryptData;
	DWORD	cbPvk;
} PVK_FILE_HDR, *PPVK_FILE_HDR;

typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;

typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG bits;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;

BOOL kull_m_crypto_hash(ALG_ID algid, LPCVOID data, DWORD dataLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey, HCRYPTPROV *hSessionProv);
BOOL kull_m_crypto_hmac(DWORD calgid, LPCVOID key, DWORD keyLen, LPCVOID message, DWORD messageLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_pkcs5_pbkdf2_hmac(DWORD calgid, LPCVOID password, DWORD passwordLen, LPCVOID salt, DWORD saltLen, DWORD iterations, BYTE *key, DWORD keyLen, BOOL isDpapiInternal);
BOOL kull_m_crypto_aesCTSEncryptDecrypt(DWORD aesCalgId, PVOID data, DWORD szData, PVOID key, DWORD szKey, PVOID pbIV, BOOL encrypt);
BOOL kull_m_crypto_DeriveKeyRaw(ALG_ID hashId, LPVOID hash, DWORD hashLen, LPVOID key, DWORD keyLen);
BOOL kull_m_crypto_close_hprov_delete_container(HCRYPTPROV hProv);
BOOL kull_m_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hSessionKey, HCRYPTPROV *hSessionProv);
DWORD kull_m_crypto_hash_len(ALG_ID hashId);
DWORD kull_m_crypto_cipher_blocklen(ALG_ID hashId);
DWORD kull_m_crypto_cipher_keylen(ALG_ID hashId);
NTSTATUS kull_m_crypto_get_dcc(PBYTE dcc, PBYTE ntlm, PUNICODE_STRING Username, DWORD realIterations);
BOOL kull_m_crypto_genericAES128Decrypt(LPCVOID pKey, LPCVOID pIV, LPCVOID pData, DWORD dwDataLen, LPVOID *pOut, DWORD *dwOutLen);

BOOL kull_m_crypto_exportPfx(HCERTSTORE hStore, LPCWSTR filename);
BOOL kull_m_crypto_DerAndKeyToPfx(LPCVOID der, DWORD derLen, LPCVOID key, DWORD keyLen, BOOL isPvk, LPCWSTR filename);
BOOL kull_m_crypto_DerAndKeyInfoToPfx(LPCVOID der, DWORD derLen, PCRYPT_KEY_PROV_INFO pInfo, LPCWSTR filename);
BOOL kull_m_crypto_DerAndKeyInfoToStore(LPCVOID der, DWORD derLen, PCRYPT_KEY_PROV_INFO pInfo, DWORD systemStore, LPCWSTR store, BOOL force);

typedef struct _KULL_M_CRYPTO_DUAL_STRING_DWORD {
	PCWSTR	name;
	DWORD	id;
} KULL_M_CRYPTO_DUAL_STRING_DWORD, *PKULL_M_CRYPTO_DUAL_STRING_DWORD;

typedef struct _KULL_M_CRYPTO_DUAL_STRING_STRING {
	PCWSTR	name;
	PCWSTR	realname;
} KULL_M_CRYPTO_DUAL_STRING_STRING, *PKULL_M_CRYPTO_DUAL_STRING_STRING;

#define CERT_cert_file_element	32
#define CERT_crl_file_element	33
#define CERT_ctl_file_element	34
#define CERT_keyid_file_element	35

DWORD kull_m_crypto_system_store_to_dword(PCWSTR name);
DWORD kull_m_crypto_provider_type_to_dword(PCWSTR name);
PCWSTR kull_m_crypto_provider_type_to_name(const DWORD dwProvType);
PCWCHAR kull_m_crypto_provider_to_realname(PCWSTR name);
PCWCHAR kull_m_crypto_keytype_to_str(const DWORD keyType);
PCWCHAR kull_m_crypto_algid_to_name(ALG_ID algid);
ALG_ID kull_m_crypto_name_to_algid(PCWSTR name);
PCWCHAR kull_m_crypto_cert_prop_id_to_name(const DWORD propId);
void kull_m_crypto_kp_permissions_descr(const DWORD keyPermissions);
PCWCHAR kull_m_crypto_kp_mode_to_str(const DWORD keyMode);
PCWCHAR kull_m_crypto_bcrypt_interface_to_str(const DWORD interf);
PCWCHAR kull_m_crypto_bcrypt_cipher_alg_to_str(const DWORD alg);
PCWCHAR kull_m_crypto_bcrypt_asym_alg_to_str(const DWORD alg);
PCWCHAR kull_m_crypto_bcrypt_mode_to_str(const DWORD keyMode);


typedef struct _MIMI_PUBLICKEY
{
	ALG_ID sessionType;
	DWORD cbPublicKey;
	BYTE *pbPublicKey;
} MIMI_PUBLICKEY, *PMIMI_PUBLICKEY;

typedef struct _KIWI_DH {
	HCRYPTPROV hProvParty;
	HCRYPTKEY hPrivateKey;
	MIMI_PUBLICKEY publicKey;
	HCRYPTKEY hSessionKey;
} KIWI_DH, *PKIWI_DH;

PKIWI_DH kull_m_crypto_dh_Delete(PKIWI_DH dh);
PKIWI_DH kull_m_crypto_dh_Create(ALG_ID targetSessionKeyType);
BOOL kull_m_crypto_dh_CreateSessionKey(PKIWI_DH dh, PMIMI_PUBLICKEY publicKey);
BOOL kull_m_crypto_dh_simpleEncrypt(HCRYPTKEY key, LPVOID data, DWORD dataLen, LPVOID *out, DWORD *outLen);
BOOL kull_m_crypto_dh_simpleDecrypt(HCRYPTKEY key, LPVOID data, DWORD dataLen, LPVOID *out, DWORD *outLen);