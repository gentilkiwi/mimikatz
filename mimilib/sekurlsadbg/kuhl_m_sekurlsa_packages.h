/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kwindbg.h"

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN ULONG_PTR reserved, IN PLUID logId, IN PVOID pCredentials);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_kerberos(IN ULONG_PTR pKerbGlobalLogonSessionTable, IN PLUID logId, IN PVOID pCredentials);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_livessp(IN ULONG_PTR pLiveGlobalLogonSessionList, IN PLUID logId, IN PVOID pCredentials);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_tspkg(IN ULONG_PTR pTSGlobalCredTable, IN PLUID logId, IN PVOID pCredentials);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_wdigest(IN ULONG_PTR pl_LogSessList, IN PLUID logId, IN PVOID pCredentials);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_ssp(IN ULONG_PTR pSspCredentialList, IN PLUID logId, IN PVOID pCredentials);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_masterkeys(IN ULONG_PTR pMasterKeyCacheList, IN PLUID logId, IN PVOID pCredentials);

typedef struct _MSV1_0_PRIMARY_CREDENTIAL { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName; 
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	DWORD unknow_01000100;
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL, *PMSV1_0_PRIMARY_CREDENTIAL; 

typedef struct _RPCE_COMMON_TYPE_HEADER {
	UCHAR Version;
	UCHAR Endianness;
	USHORT CommonHeaderLength;
	ULONG Filler;
} RPCE_COMMON_TYPE_HEADER, *PRPCE_COMMON_TYPE_HEADER;

typedef struct _RPCE_PRIVATE_HEADER {
	ULONG ObjectBufferLength;
	ULONG Filler;
} RPCE_PRIVATE_HEADER, *PRPCE_PRIVATE_HEADER;

typedef ULONG32 RPCEID;

typedef struct _MARSHALL_KEY {
	DWORD unkId;
	USHORT unk0;
	USHORT length;
	RPCEID ElementId;
} MARSHALL_KEY, *PMARSHALL_KEY;

typedef struct _RPCE_CREDENTIAL_KEYCREDENTIAL {
	RPCE_COMMON_TYPE_HEADER	typeHeader;
	RPCE_PRIVATE_HEADER	privateHeader;
	RPCEID RootElementId;
	DWORD unk0;
	DWORD unk1;
	MARSHALL_KEY key[ANYSIZE_ARRAY];
} RPCE_CREDENTIAL_KEYCREDENTIAL, *PRPCE_CREDENTIAL_KEYCREDENTIAL;

typedef struct _KIWI_KERBEROS_LOGON_SESSION
{
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk2;	// filetime.1 ?
	ULONG		unk3;	// filetime.2 ?
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
#ifdef _M_IX86
	ULONG		unkAlign;
#endif
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk9;	// filetime.1 ?
	ULONG		unk10;	// filetime.2 ?
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
	KIWI_GENERIC_PRIMARY_CREDENTIAL	credentials;
	ULONG		unk14;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	PVOID		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		unk22;
	PVOID		unk23;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk24;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk25;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk26;
	PUNICODE_STRING pinCode;	// not only PIN (CSP Info)
} KIWI_KERBEROS_LOGON_SESSION, *PKIWI_KERBEROS_LOGON_SESSION;

typedef struct _KIWI_LIVESSP_PRIMARY_CREDENTIAL
{
	ULONG isSupp;
	ULONG unk0;
	KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
} KIWI_LIVESSP_PRIMARY_CREDENTIAL, *PKIWI_LIVESSP_PRIMARY_CREDENTIAL;

typedef struct _KIWI_LIVESSP_LIST_ENTRY
{
	struct _KIWI_LIVESSP_LIST_ENTRY *Flink;
	struct _KIWI_LIVESSP_LIST_ENTRY *Blink;
	PVOID	unk0;
	PVOID	unk1;
	PVOID	unk2;
	PVOID	unk3;
	DWORD	unk4;
	DWORD	unk5;
	PVOID	unk6;
	LUID	LocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	PVOID	unk7;
	PKIWI_LIVESSP_PRIMARY_CREDENTIAL suppCreds;
} KIWI_LIVESSP_LIST_ENTRY, *PKIWI_LIVESSP_LIST_ENTRY;

typedef struct _KIWI_TS_PRIMARY_CREDENTIAL {
	PVOID unk0;	// lock ?
	KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
} KIWI_TS_PRIMARY_CREDENTIAL, *PKIWI_TS_PRIMARY_CREDENTIAL;

typedef struct _KIWI_TS_CREDENTIAL {
#ifdef _M_X64
	BYTE unk0[108];
#elif defined _M_IX86
	BYTE unk0[64];
#endif
	LUID LocallyUniqueIdentifier;
	PVOID unk1;
	PVOID unk2;
	PKIWI_TS_PRIMARY_CREDENTIAL pTsPrimary;
} KIWI_TS_CREDENTIAL, *PKIWI_TS_CREDENTIAL;

#ifdef _M_X64
	#define offsetWDigestPrimary 48
#elif defined _M_IX86
	#define offsetWDigestPrimary 32
#endif
typedef struct _KIWI_WDIGEST_LIST_ENTRY {
	struct _KIWI_WDIGEST_LIST_ENTRY *Flink;
	struct _KIWI_WDIGEST_LIST_ENTRY *Blink;
	ULONG	UsageCount;
	struct _KIWI_WDIGEST_LIST_ENTRY *This;
	LUID LocallyUniqueIdentifier;
} KIWI_WDIGEST_LIST_ENTRY, *PKIWI_WDIGEST_LIST_ENTRY;

typedef struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY {
	struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY *Flink;
	struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY *Blink;
	ULONG References;
	ULONG CredentialReferences;
	LUID LogonId;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
} KIWI_SSP_CREDENTIAL_LIST_ENTRY, *PKIWI_SSP_CREDENTIAL_LIST_ENTRY;

typedef struct _KIWI_MASTERKEY_CACHE_ENTRY {
	struct _KIWI_MATERKEY_CACHE_ENTRY *Flink;
	struct _KIWI_MATERKEY_CACHE_ENTRY *Blink;
	LUID LogonId;
	GUID KeyUid;
	FILETIME insertTime;
	ULONG keySize;
	BYTE  key[ANYSIZE_ARRAY];
} KIWI_MASTERKEY_CACHE_ENTRY, *PKIWI_MASTERKEY_CACHE_ENTRY;