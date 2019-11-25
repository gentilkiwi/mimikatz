/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_crypto.h"
#include "kull_m_crypto_system.h"
#include "kull_m_string.h"
#include "kull_m_net.h"
#include "rpc/kull_m_rpc_bkrp.h"

const GUID KULL_M_DPAPI_GUID_PROVIDER;

#define	CRYPTPROTECT_SYSTEM	0x20000000

typedef struct _KULL_M_DWORD_TO_DWORD {
	PCWSTR	name;
	DWORD	id;
} KULL_M_DWORD_TO_DWORD, *PKULL_M_DWORD_TO_DWORD;

#pragma pack(push, 4) 
typedef struct _KULL_M_DPAPI_BLOB {
	DWORD	dwVersion;
	GUID	guidProvider;
	DWORD	dwMasterKeyVersion;
	GUID	guidMasterKey;
	DWORD	dwFlags;
	
	DWORD	dwDescriptionLen;
	PWSTR	szDescription;
	
	ALG_ID	algCrypt;
	DWORD	dwAlgCryptLen;
	
	DWORD	dwSaltLen;
	PBYTE	pbSalt;
	
	DWORD	dwHmacKeyLen;
	PBYTE	pbHmackKey;
	
	ALG_ID	algHash;
	DWORD	dwAlgHashLen;

	DWORD	dwHmac2KeyLen;
	PBYTE	pbHmack2Key;
	
	DWORD	dwDataLen;
	PBYTE	pbData;
	
	DWORD	dwSignLen;
	PBYTE	pbSign;
} KULL_M_DPAPI_BLOB, *PKULL_M_DPAPI_BLOB;

typedef struct _KULL_M_DPAPI_MASTERKEY {
	DWORD	dwVersion;
	BYTE	salt[16];
	DWORD	rounds;
	ALG_ID	algHash;
	ALG_ID	algCrypt;
	PBYTE	pbKey;
	DWORD	__dwKeyLen;
} KULL_M_DPAPI_MASTERKEY, *PKULL_M_DPAPI_MASTERKEY;

typedef struct _KULL_M_DPAPI_MASTERKEY_CREDHIST {
	DWORD	dwVersion;
	GUID	guid;
} KULL_M_DPAPI_MASTERKEY_CREDHIST, *PKULL_M_DPAPI_MASTERKEY_CREDHIST;

typedef struct _KULL_M_DPAPI_MASTERKEY_DOMAINKEY {
	DWORD	dwVersion;
	DWORD	dwSecretLen;
	DWORD	dwAccesscheckLen;
	GUID	guidMasterKey;
	PBYTE	pbSecret;
	PBYTE	pbAccesscheck;
} KULL_M_DPAPI_MASTERKEY_DOMAINKEY, *PKULL_M_DPAPI_MASTERKEY_DOMAINKEY;

typedef struct _KULL_M_DPAPI_MASTERKEYS {
	DWORD	dwVersion;
	DWORD	unk0;
	DWORD	unk1;
	WCHAR	szGuid[36];
	DWORD	unk2;
	DWORD	unk3;
	DWORD	dwFlags;
	DWORD64	dwMasterKeyLen;
	DWORD64 dwBackupKeyLen;
	DWORD64 dwCredHistLen;
	DWORD64	dwDomainKeyLen;
	PKULL_M_DPAPI_MASTERKEY	MasterKey;
	PKULL_M_DPAPI_MASTERKEY	BackupKey;
	PKULL_M_DPAPI_MASTERKEY_CREDHIST	CredHist;
	PKULL_M_DPAPI_MASTERKEY_DOMAINKEY	DomainKey;
} KULL_M_DPAPI_MASTERKEYS, *PKULL_M_DPAPI_MASTERKEYS;

typedef struct _KULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY {
    DWORD  cbMasterKey;
    DWORD  cbSuppKey;
    BYTE   buffer[ANYSIZE_ARRAY];
} KULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY, *PKULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY;
 
typedef struct _KULL_M_DPAPI_DOMAIN_ACCESS_CHECK {
    DWORD  dwVersion;
    DWORD  dataLen;
    BYTE   data[ANYSIZE_ARRAY];
    // sid
    // SHA1 (or SHA512)
} KULL_M_DPAPI_DOMAIN_ACCESS_CHECK, *PKULL_M_DPAPI_DOMAIN_ACCESS_CHECK;

typedef struct _KULL_M_DPAPI_CREDHIST_HEADER {
	DWORD	dwVersion;
	GUID	guid;
	DWORD	dwNextLen;
} KULL_M_DPAPI_CREDHIST_HEADER, *PKULL_M_DPAPI_CREDHIST_HEADER;

typedef struct _KULL_M_DPAPI_CREDHIST_ENTRY {
	KULL_M_DPAPI_CREDHIST_HEADER	header;
	DWORD	dwType; // flags ?
	ALG_ID	algHash;
	DWORD	rounds;
	DWORD	sidLen;
	ALG_ID	algCrypt;
	DWORD	sha1Len;
	DWORD	md4Len;
	BYTE	salt[16];

	PSID	pSid;
	PBYTE	pSecret;

	DWORD	__dwSecretLen;
} KULL_M_DPAPI_CREDHIST_ENTRY, *PKULL_M_DPAPI_CREDHIST_ENTRY;

typedef struct _KULL_M_DPAPI_CREDHIST {
	KULL_M_DPAPI_CREDHIST_HEADER current;
	PKULL_M_DPAPI_CREDHIST_ENTRY * entries;
	DWORD __dwCount;
} KULL_M_DPAPI_CREDHIST, *PKULL_M_DPAPI_CREDHIST;
#pragma pack(pop) 

PKULL_M_DPAPI_BLOB kull_m_dpapi_blob_create(LPCVOID data/*, DWORD size*/);
void kull_m_dpapi_blob_delete(PKULL_M_DPAPI_BLOB blob);
void kull_m_dpapi_blob_descr(DWORD level, PKULL_M_DPAPI_BLOB blob);
void kull_m_dpapi_blob_quick_descr(DWORD level, LPCVOID data/*, DWORD size*/);

PKULL_M_DPAPI_MASTERKEYS kull_m_dpapi_masterkeys_create(LPCVOID data/*, DWORD size*/);
void kull_m_dpapi_masterkeys_delete(PKULL_M_DPAPI_MASTERKEYS masterkeys);
void kull_m_dpapi_masterkeys_descr(DWORD level, PKULL_M_DPAPI_MASTERKEYS masterkeys);

PKULL_M_DPAPI_MASTERKEY kull_m_dpapi_masterkey_create(LPCVOID data, DWORD64 size);
void kull_m_dpapi_masterkey_delete(PKULL_M_DPAPI_MASTERKEY masterkey);
void kull_m_dpapi_masterkey_descr(DWORD level, PKULL_M_DPAPI_MASTERKEY masterkey);

PKULL_M_DPAPI_MASTERKEY_CREDHIST kull_m_dpapi_masterkeys_credhist_create(LPCVOID data, DWORD64 size);
void kull_m_dpapi_masterkeys_credhist_delete(PKULL_M_DPAPI_MASTERKEY_CREDHIST credhist);
void kull_m_dpapi_masterkeys_credhist_descr(DWORD level, PKULL_M_DPAPI_MASTERKEY_CREDHIST credhist);

PKULL_M_DPAPI_MASTERKEY_DOMAINKEY kull_m_dpapi_masterkeys_domainkey_create(PVOID LPCVOID, DWORD64 size);
void kull_m_dpapi_masterkeys_domainkey_delete(PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey);
void kull_m_dpapi_masterkeys_domainkey_descr(DWORD level, PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey);

PKULL_M_DPAPI_CREDHIST kull_m_dpapi_credhist_create(LPCVOID data, DWORD size);
void kull_m_dpapi_credhist_delete(PKULL_M_DPAPI_CREDHIST credhist);
void kull_m_dpapi_credhist_descr(DWORD level, PKULL_M_DPAPI_CREDHIST credhist);

PKULL_M_DPAPI_CREDHIST_ENTRY kull_m_dpapi_credhist_entry_create(LPCVOID data, DWORD size);
void kull_m_dpapi_credhist_entry_delete(PKULL_M_DPAPI_CREDHIST_ENTRY entry);
void kull_m_dpapi_credhist_entry_descr(DWORD level, PKULL_M_DPAPI_CREDHIST_ENTRY entry);

BOOL kull_m_dpapi_hmac_sha1_incorrect(LPCVOID key, DWORD keyLen, LPCVOID salt, DWORD saltLen, LPCVOID entropy, DWORD entropyLen, LPCVOID data, DWORD dataLen, LPVOID outKey);
BOOL kull_m_dpapi_sessionkey(LPCVOID masterkey, DWORD masterkeyLen, LPCVOID salt, DWORD saltLen, LPCVOID entropy, DWORD entropyLen, LPCVOID data, DWORD dataLen, ALG_ID hashAlg, LPVOID outKey, DWORD outKeyLen);
BOOL kull_m_dpapi_unprotect_blob(PKULL_M_DPAPI_BLOB blob, LPCVOID masterkey, DWORD masterkeyLen, LPCVOID entropy, DWORD entropyLen, LPCWSTR password, LPVOID *dataOut, DWORD *dataOutLen);
BOOL kull_m_dpapi_unprotect_raw_or_blob(LPCVOID pDataIn, DWORD dwDataInLen, LPWSTR *ppszDataDescr, LPCVOID pOptionalEntropy, DWORD dwOptionalEntropyLen, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, LPVOID *pDataOut, DWORD *dwDataOutLen, LPCVOID pMasterKey, DWORD dwMasterKeyLen, LPCWSTR pPassword);

BOOL kull_m_dpapi_getProtected(PVOID PassHash, DWORD PassLen, PCWSTR sid);
BOOL kull_m_dpapi_unprotect_masterkey_with_password(DWORD flags, PKULL_M_DPAPI_MASTERKEY masterkey, PCWSTR password, PCWSTR sid, BOOL isKeyOfProtectedUser, PVOID *output, DWORD *outputLen);
BOOL kull_m_dpapi_unprotect_masterkey_with_userHash(PKULL_M_DPAPI_MASTERKEY masterkey, LPCVOID userHash, DWORD userHashLen, PCWSTR sid, PVOID *output, DWORD *outputLen);
BOOL kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey(PKULL_M_DPAPI_MASTERKEY masterkey, LPCVOID shaDerivedkey, DWORD shaDerivedkeyLen, PVOID *output, DWORD *outputLen);
//BOOL kull_m_dpapi_unprotect_backupkey_with_secret(DWORD flags, PKULL_M_DPAPI_MASTERKEY masterkey, PCWSTR sid, LPCVOID secret, DWORD secretLen, PVOID *output, DWORD *outputLen);
BOOL kull_m_dpapi_unprotect_domainkey_with_key(PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey, LPCVOID key, DWORD keyLen, PVOID *output, DWORD *outputLen, PSID *sid);
BOOL kull_m_dpapi_unprotect_domainkey_with_rpc(PKULL_M_DPAPI_MASTERKEYS masterkeys, PVOID rawMasterkeys, LPCWSTR server, PVOID *output, DWORD *outputLen);

BOOL kull_m_dpapi_unprotect_credhist_entry_with_shaDerivedkey(PKULL_M_DPAPI_CREDHIST_ENTRY entry, LPCVOID shaDerivedkey, DWORD shaDerivedkeyLen, PVOID md4hash, PVOID sha1hash);

void kull_m_dpapi_displayPromptFlags(DWORD flags);
void kull_m_dpapi_displayProtectionFlags(DWORD flags);
void kull_m_dpapi_displayBlobFlags(DWORD flags);