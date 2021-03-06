/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_dpapi.h"
#include "kull_m_string.h"

const wchar_t KULL_M_CRED_ENTROPY_CRED_DER[37];
const wchar_t KULL_M_CRED_ENTROPYDOM_CRED_DER[37];

#pragma pack(push, 1)
typedef struct _KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE {
	DWORD id;
	DWORD unk0; // maybe flags
	DWORD unk1; // maybe type
	DWORD unk2; // 0a 00 00 00
	//DWORD unkComplex; // only in complex (and 0, avoid it ?)
	DWORD szData; // when parsing, inc bullshit... clean in structure
	PBYTE data;
	DWORD szIV;
	PBYTE IV;
} KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE, *PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE;
#pragma pack(pop)

#pragma pack(push, 4)
typedef struct _KULL_M_CRED_ATTRIBUTE {
	DWORD Flags;

	DWORD dwKeyword;
	LPWSTR Keyword;

	DWORD ValueSize;
	LPBYTE Value;
} KULL_M_CRED_ATTRIBUTE, *PKULL_M_CRED_ATTRIBUTE;

typedef struct _KULL_M_CRED_BLOB {
	DWORD	credFlags;
	DWORD	credSize;
	DWORD	credUnk0;
	
	DWORD Type;
	DWORD Flags;
	FILETIME LastWritten;
	DWORD	unkFlagsOrSize;
	DWORD	Persist;
	DWORD	AttributeCount;
	DWORD	unk0;
	DWORD	unk1;

	DWORD	dwTargetName;
	LPWSTR	TargetName;

	DWORD	dwTargetAlias;
	LPWSTR	TargetAlias;

	DWORD	dwComment;
	LPWSTR	Comment;

	DWORD	dwUnkData;
	LPWSTR	UnkData;

	DWORD	dwUserName;
	LPWSTR	UserName;

	DWORD	CredentialBlobSize;
	LPBYTE	CredentialBlob;

	PKULL_M_CRED_ATTRIBUTE *Attributes;

} KULL_M_CRED_BLOB, *PKULL_M_CRED_BLOB;

typedef struct _KULL_M_CRED_LEGACY_CRED_BLOB {
	DWORD	credSize;
	DWORD	Flags;
	DWORD	Type;

	FILETIME LastWritten;
	DWORD	unkFlagsOrSize;
	DWORD	Persist;
	DWORD	AttributeCount;
	DWORD	unk0;
	DWORD	unk1;

	DWORD	dwTargetName;
	LPWSTR	TargetName;

	DWORD	dwComment;
	LPWSTR	Comment;

	DWORD	dwTargetAlias;
	LPWSTR	TargetAlias;

	DWORD	dwUserName;
	LPWSTR	UserName;

	DWORD	CredentialBlobSize;
	LPBYTE	CredentialBlob;

	PKULL_M_CRED_ATTRIBUTE *Attributes;

} KULL_M_CRED_LEGACY_CRED_BLOB, *PKULL_M_CRED_LEGACY_CRED_BLOB;

typedef struct _KULL_M_CRED_LEGACY_CREDS_BLOB {
	DWORD	dwVersion;
	DWORD	structSize;

	DWORD	__count;
	PKULL_M_CRED_LEGACY_CRED_BLOB *Credentials;
} KULL_M_CRED_LEGACY_CREDS_BLOB, *PKULL_M_CRED_LEGACY_CREDS_BLOB;

typedef struct _KULL_M_CRED_VAULT_POLICY_KEY {
	GUID unk0;
	GUID unk1;
	DWORD dwKeyBlob;
	PVOID KeyBlob;
} KULL_M_CRED_VAULT_POLICY_KEY, *PKULL_M_CRED_VAULT_POLICY_KEY;

typedef struct _KULL_M_CRED_VAULT_POLICY {
	DWORD version;
	GUID vault;

	DWORD dwName;
	LPWSTR Name;

	DWORD unk0;
	DWORD unk1;
	DWORD unk2;

	DWORD dwKey;
	PKULL_M_CRED_VAULT_POLICY_KEY key;
} KULL_M_CRED_VAULT_POLICY, *PKULL_M_CRED_VAULT_POLICY;

typedef struct _KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP {
	DWORD id;
	DWORD offset; //maybe 64
	DWORD unk;
} KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP, *PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP;

typedef struct _KULL_M_CRED_VAULT_CREDENTIAL {
	GUID SchemaId;
	DWORD unk0; // 4
	FILETIME LastWritten;
	DWORD unk1; // ffffffff
	DWORD unk2; // flags ?

	DWORD dwFriendlyName;
	LPWSTR FriendlyName;
	
	DWORD dwAttributesMapSize;
	PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP attributesMap;

	DWORD __cbElements;
	PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE *attributes;
} KULL_M_CRED_VAULT_CREDENTIAL, *PKULL_M_CRED_VAULT_CREDENTIAL;

typedef struct _KULL_M_CRED_VAULT_CLEAR_ENTRY {
	DWORD id;
	DWORD size;
	BYTE data[ANYSIZE_ARRAY];
} KULL_M_CRED_VAULT_CLEAR_ENTRY, *PKULL_M_CRED_VAULT_CLEAR_ENTRY;

typedef struct _KULL_M_CRED_VAULT_CLEAR {
	DWORD version;
	DWORD count;
	DWORD unk;
	PKULL_M_CRED_VAULT_CLEAR_ENTRY *entries;
} KULL_M_CRED_VAULT_CLEAR, *PKULL_M_CRED_VAULT_CLEAR;
#pragma pack(pop)

typedef struct _KULL_M_CRED_APPSENSE_DN {
	char type[12];
	DWORD credBlobSize;
	DWORD unkBlobSize;
	BYTE data[ANYSIZE_ARRAY];
} KULL_M_CRED_APPSENSE_DN, *PKULL_M_CRED_APPSENSE_DN;

PKULL_M_CRED_BLOB kull_m_cred_create(PVOID data/*, DWORD size*/);
void kull_m_cred_delete(PKULL_M_CRED_BLOB cred);
void kull_m_cred_descr(DWORD level, PKULL_M_CRED_BLOB cred);

BOOL kull_m_cred_attributes_create(PVOID data, PKULL_M_CRED_ATTRIBUTE **Attributes, DWORD count);
void kull_m_cred_attributes_delete(PKULL_M_CRED_ATTRIBUTE *Attributes, DWORD count);
void kull_m_cred_attributes_descr(DWORD level, PKULL_M_CRED_ATTRIBUTE *Attributes, DWORD count);

PKULL_M_CRED_ATTRIBUTE kull_m_cred_attribute_create(PVOID data/*, DWORD size*/);
void kull_m_cred_attribute_delete(PKULL_M_CRED_ATTRIBUTE Attribute);
void kull_m_cred_attribute_descr(DWORD level, PKULL_M_CRED_ATTRIBUTE Attribute);

PKULL_M_CRED_LEGACY_CREDS_BLOB kull_m_cred_legacy_creds_create(PVOID data/*, DWORD size*/);
void kull_m_cred_legacy_creds_delete(PKULL_M_CRED_LEGACY_CREDS_BLOB creds);
void kull_m_cred_legacy_creds_descr(DWORD level, PKULL_M_CRED_LEGACY_CREDS_BLOB creds);

PKULL_M_CRED_LEGACY_CRED_BLOB kull_m_cred_legacy_cred_create(PVOID data/*, DWORD size*/);
void kull_m_cred_legacy_cred_delete(PKULL_M_CRED_LEGACY_CRED_BLOB cred);
void kull_m_cred_legacy_cred_descr(DWORD level, PKULL_M_CRED_LEGACY_CRED_BLOB cred);

PCWCHAR kull_m_cred_CredType(DWORD type);
PCWCHAR kull_m_cred_CredPersist(DWORD persist);

PKULL_M_CRED_VAULT_POLICY kull_m_cred_vault_policy_create(PVOID data/*, DWORD size*/);
void kull_m_cred_vault_policy_delete(PKULL_M_CRED_VAULT_POLICY policy);
void kull_m_cred_vault_policy_descr(DWORD level, PKULL_M_CRED_VAULT_POLICY policy);

PKULL_M_CRED_VAULT_POLICY_KEY kull_m_cred_vault_policy_key_create(PVOID data/*, DWORD size*/);
void kull_m_cred_vault_policy_key_delete(PKULL_M_CRED_VAULT_POLICY_KEY key);
void kull_m_cred_vault_policy_key_descr(DWORD level, PKULL_M_CRED_VAULT_POLICY_KEY key);

PKULL_M_CRED_VAULT_CREDENTIAL kull_m_cred_vault_credential_create(PVOID data/*, DWORD size*/);
void kull_m_cred_vault_credential_create_attribute_from_data(PBYTE ptr, PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute);
void kull_m_cred_vault_credential_delete(PKULL_M_CRED_VAULT_CREDENTIAL credential);
void kull_m_cred_vault_credential_descr(DWORD level, PKULL_M_CRED_VAULT_CREDENTIAL credential);
void kull_m_cred_vault_credential_attribute_descr(DWORD level, PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute);

PKULL_M_CRED_VAULT_CLEAR kull_m_cred_vault_clear_create(PVOID data/*, DWORD size*/);
void kull_m_cred_vault_clear_delete(PKULL_M_CRED_VAULT_CLEAR clear);
void kull_m_cred_vault_clear_descr(DWORD level, PKULL_M_CRED_VAULT_CLEAR clear);

/*
24 00 00 00
	01 00 00 00
	02 00 00 00
	4b 44 42 4d KDBM 'MBDK'
	01 00 00 00
	10 00 00 00
		xx xx xx (16)

34 00 00 00
	01 00 00 00
	01 00 00 00
	4b 44 42 4d KDBM 'MBDK'
	01 00 00 00
	20 00 00 00
		xx xx xx (32)
*/

typedef struct _KULL_M_CRED_VAULT_POLICY_KEY_MBDK {
	DWORD keySize;
	DWORD version;
	DWORD type; // ?
	DWORD tag;
	DWORD unk0;
	KIWI_HARD_KEY key;
} KULL_M_CRED_VAULT_POLICY_KEY_MBDK, *PKULL_M_CRED_VAULT_POLICY_KEY_MBDK;

/*
38 02 00 00
	01 00 00 00
	02 00 00 00
	30 02 00 00
		4b 53 53 4d KSSM	'MSSK'
		02 00 01 00
		01 00 00 00
		10 00 00 00
		80 00 00 00 (128)
		
		10 00 00 00
			xx xx xx (16)
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
		xx xx xx (16)
		yy yy yy (..)
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
		a0 00 00 00
		40 01 00 00
		00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00

38 02 00 00
	01 00 00 00
	01 00 00 00
	30 02 00 00
		4b 53 53 4d KSSM	'MSSK'
		02 00 01 00
		01 00 00 00
		10 00 00 00
		00 01 00 00 (256)

		20 00 00 00 (32)
			xx xx xx (32)
		00 00 00 00
		xx xx xx (32)
		yy yy yy (..)
		e0 00 00 00
		c0 01 00 00
		00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00
*/

BOOL kull_m_cred_vault_policy_key(PVOID data, DWORD size, BYTE aes128[AES_128_KEY_SIZE], BYTE aes256[AES_256_KEY_SIZE]);