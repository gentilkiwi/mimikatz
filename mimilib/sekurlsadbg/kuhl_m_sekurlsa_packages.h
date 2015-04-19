/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kwindbg.h"

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN ULONG_PTR reserved, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_kerberos(IN ULONG_PTR pKerbGlobalLogonSessionTable, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_livessp(IN ULONG_PTR pLiveGlobalLogonSessionList, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_tspkg(IN ULONG_PTR pTSGlobalCredTable, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_wdigest(IN ULONG_PTR pl_LogSessList, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_ssp(IN ULONG_PTR pSspCredentialList, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_masterkeys(IN ULONG_PTR pMasterKeyCacheList, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_credman(IN ULONG_PTR reserved, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _MSV1_0_PRIMARY_CREDENTIAL { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName; 
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL, *PMSV1_0_PRIMARY_CREDENTIAL;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10 { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	
	BOOLEAN isUnk0;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BOOLEAN isUnk1;
	BOOLEAN isUnk2;
	BOOLEAN isUnk3;
	BOOLEAN isUnk4;

	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	BYTE UnkStruct[128];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10, *PMSV1_0_PRIMARY_CREDENTIAL_10;

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

typedef struct _KERB_HASHPASSWORD_6 {
	LSA_UNICODE_STRING salt;	// http://tools.ietf.org/html/rfc3962
	PVOID stringToKey; // AES Iterations (dword ?)
	DWORD Type;
	SIZE_T Size;
	PBYTE Checksump;
} KERB_HASHPASSWORD_6, *PKERB_HASHPASSWORD_6;

typedef struct _KIWI_KERBEROS_KEYS_LIST_6 {
	DWORD unk0;		// dword_1233EC8 dd 4
	DWORD cbItem;	// debug048:01233ECC dd 5
	PVOID unk1;
	PVOID unk2;
	PVOID unk3;
	PVOID unk4;
	//KERB_HASHPASSWORD_6 KeysEntries[ANYSIZE_ARRAY];
} KIWI_KERBEROS_KEYS_LIST_6, *PKIWI_KERBEROS_KEYS_LIST_6;

typedef struct _KIWI_KERBEROS_CSP_NAMES {
	DWORD offsetToCard;
	DWORD offsetToReader;
	DWORD offsetToSerial;
	DWORD offsetToProvider;
	//...
} KIWI_KERBEROS_CSP_NAMES, *PKIWI_KERBEROS_CSP_NAMES;

typedef struct _KIWI_KERBEROS_CSP_INFOS_51 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
	PVOID unk3;
	DWORD sizeOfNextStruct;
	DWORD sizeOfCurrentStruct;
	PVOID unkCSP; // ?,
	KIWI_KERBEROS_CSP_NAMES names;
} KIWI_KERBEROS_CSP_INFOS_51, *PKIWI_KERBEROS_CSP_INFOS_51;

typedef struct _KIWI_KERBEROS_CSP_INFOS_60 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
#ifdef _M_IX86
	DWORD		unkAlign0;
#endif
	DWORD unk3_size;
	DWORD sizeOfNextStruct;
	DWORD unk4;
	DWORD sizeOfCurrentStruct;
	DWORD unk5;
	PVOID unkCSP; // ?,
#ifdef _M_IX86
	DWORD		unkAlign1;
#endif
	DWORD unk6;
	DWORD unk7;
	KIWI_KERBEROS_CSP_NAMES names;
} KIWI_KERBEROS_CSP_INFOS_60, *PKIWI_KERBEROS_CSP_INFOS_60;

typedef struct _KIWI_KERBEROS_CSP_INFOS_61 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
	DWORD unk3;
	DWORD unk4_size;
	DWORD sizeOfNextStruct;
	DWORD unk5;
	DWORD sizeOfCurrentStruct;
	DWORD unk6;
	PVOID unkCSP;
#ifdef _M_IX86
	DWORD		unkAlign0;
#endif
	DWORD unk7;
	DWORD unk8;
	KIWI_KERBEROS_CSP_NAMES names;
} KIWI_KERBEROS_CSP_INFOS_61, *PKIWI_KERBEROS_CSP_INFOS_61;

typedef struct _KIWI_KERBEROS_CSP_INFOS_62 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
	PVOID unk3;
	DWORD unk4;
	DWORD unk5_size;
	DWORD sizeOfNextStruct;
#ifdef _M_X64
	DWORD		unkAlign0;
#endif
	DWORD sizeOfCurrentStruct;
	DWORD unk7;
	PVOID unkCSP;
#ifdef _M_IX86
	DWORD		unkAlign1;
#endif
	DWORD unk8;
	DWORD unk9;
	KIWI_KERBEROS_CSP_NAMES names;
} KIWI_KERBEROS_CSP_INFOS_62, *PKIWI_KERBEROS_CSP_INFOS_62;

typedef struct _KIWI_KERBEROS_CSP_INFOS_10 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
	PVOID unk3;
	DWORD unk4;
#ifdef _M_X64
	DWORD		unkAlign0;
#endif
	DWORD unk5_size;
	DWORD sizeOfNextStruct;
	DWORD sizeOfCurrentStruct;
	DWORD unk6;
	PVOID unkCSP; // ?,
#ifdef _M_IX86
	DWORD		unkAlign1;
#endif
	DWORD unk7;
	DWORD unk8;
	KIWI_KERBEROS_CSP_NAMES names;
} KIWI_KERBEROS_CSP_INFOS_10, *PKIWI_KERBEROS_CSP_INFOS_10;

typedef struct _KIWI_KERBEROS_LOGON_SESSION {
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
	PVOID		pKeyList;
	PVOID		unk23;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk24;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk25;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk26;
	PVOID		SmartcardInfos;
} KIWI_KERBEROS_LOGON_SESSION, *PKIWI_KERBEROS_LOGON_SESSION;

typedef struct _KIWI_KERBEROS_LOGON_SESSION_10 {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk1b;
	FILETIME	unk2;
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk8b;
	FILETIME	unk9;
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
#ifdef _M_IX86
	ULONG		unkAlign;
#endif
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
	PVOID		unk24;
	PVOID		unk25;
	PVOID		pKeyList;
	PVOID		unk26;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk27;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk28;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk29;
	PVOID		SmartcardInfos;
} KIWI_KERBEROS_LOGON_SESSION_10, *PKIWI_KERBEROS_LOGON_SESSION_10;

typedef struct _KERB_INFOS {
	LONG	offsetLuid;
	LONG	offsetCreds;
	LONG	offsetPin;
	LONG	offsetKeyList;
	SIZE_T	structSize;
	LONG	offsetSizeOfCurrentStruct;
	LONG	offsetNames;
	SIZE_T	structCspInfosSize;
} KERB_INFOS, *PKERB_INFOS;

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

typedef struct _CREDMAN_INFOS {
	ULONG	structSize;
	ULONG	offsetFLink;
	ULONG	offsetUsername;
	ULONG	offsetDomain;
	ULONG	offsetCbPassword;
	ULONG	offsetPassword;
} CREDMAN_INFOS, *PCREDMAN_INFOS;

typedef struct _KIWI_CREDMAN_LIST_ENTRY_60 {
	ULONG cbEncPassword;
	PWSTR encPassword;
	ULONG unk0;
	ULONG unk1;
	PVOID unk2;
	PVOID unk3;
	PWSTR UserName;
	ULONG cbUserName;
	struct _KIWI_CREDMAN_LIST_ENTRY *Flink;
	struct _KIWI_CREDMAN_LIST_ENTRY *Blink;
	UNICODE_STRING type;
	PVOID unk5;
	UNICODE_STRING server1;
	PVOID unk6;
	PVOID unk7;
	PVOID unk8;
	PVOID unk9;
	PVOID unk10;
	UNICODE_STRING user;
	ULONG unk11;
	UNICODE_STRING server2;
} KIWI_CREDMAN_LIST_ENTRY_60, *PKIWI_CREDMAN_LIST_ENTRY_60;

typedef struct _KIWI_CREDMAN_LIST_ENTRY {
	ULONG cbEncPassword;
	PWSTR encPassword;
	ULONG unk0;
	ULONG unk1;
	PVOID unk2;
	PVOID unk3;
	PWSTR UserName;
	ULONG cbUserName;
	struct _KIWI_CREDMAN_LIST_ENTRY *Flink;
	struct _KIWI_CREDMAN_LIST_ENTRY *Blink;
	LIST_ENTRY unk4;
	UNICODE_STRING type;
	PVOID unk5;
	UNICODE_STRING server1;
	PVOID unk6;
	PVOID unk7;
	PVOID unk8;
	PVOID unk9;
	PVOID unk10;
	UNICODE_STRING user;
	ULONG unk11;
	UNICODE_STRING server2;
} KIWI_CREDMAN_LIST_ENTRY, *PKIWI_CREDMAN_LIST_ENTRY;

typedef struct _KIWI_CREDMAN_LIST_STARTER {
	ULONG unk0;
	PKIWI_CREDMAN_LIST_ENTRY start;
	//...
} KIWI_CREDMAN_LIST_STARTER, *PKIWI_CREDMAN_LIST_STARTER;

typedef struct _KIWI_CREDMAN_SET_LIST_ENTRY {
	struct _KIWI_CREDMAN_SET_LIST_ENTRY *Flink;
	struct _KIWI_CREDMAN_SET_LIST_ENTRY *Blink;
	ULONG unk0;
	PKIWI_CREDMAN_LIST_STARTER list1;
	PKIWI_CREDMAN_LIST_STARTER list2;
	// ...
} KIWI_CREDMAN_SET_LIST_ENTRY, *PKIWI_CREDMAN_SET_LIST_ENTRY;

typedef struct _KIWI_KRBTGT_CREDENTIAL_6 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID flags;
	PVOID type;
	PVOID size;
	PVOID key;
} KIWI_KRBTGT_CREDENTIAL_6, *PKIWI_KRBTGT_CREDENTIAL_6;

typedef struct _KIWI_KRBTGT_CREDENTIALS_6 {
	DWORD unk0_ver;
	DWORD cbCred;
	PVOID unk1;
	LSA_UNICODE_STRING salt;
	PVOID unk2;
	KIWI_KRBTGT_CREDENTIAL_6 credentials[ANYSIZE_ARRAY];
} KIWI_KRBTGT_CREDENTIALS_6, *PKIWI_KRBTGT_CREDENTIALS_6;

typedef struct _DUAL_KRBTGT {
	PVOID krbtgt_current;
	PVOID krbtgt_previous;
} DUAL_KRBTGT, *PDUAL_KRBTGT;

typedef struct _KDC_DOMAIN_KEY {
	LONG	type;
	DWORD	size;
	DWORD	offset;
} KDC_DOMAIN_KEY, *PKDC_DOMAIN_KEY;

typedef struct _KDC_DOMAIN_KEYS {
	DWORD		keysSize; //60
	DWORD		unk0;
	DWORD		nbKeys;
	KDC_DOMAIN_KEY keys[ANYSIZE_ARRAY];
} KDC_DOMAIN_KEYS, *PKDC_DOMAIN_KEYS;

typedef struct _KDC_DOMAIN_KEYS_INFO {
	PKDC_DOMAIN_KEYS	keys;
	DWORD				keysSize; //60
	LSA_UNICODE_STRING	password;
} KDC_DOMAIN_KEYS_INFO, *PKDC_DOMAIN_KEYS_INFO;

typedef struct _KDC_DOMAIN_INFO {
	LIST_ENTRY list;
	LSA_UNICODE_STRING	FullDomainName;
	LSA_UNICODE_STRING	NetBiosName;
	PVOID		current;
	DWORD		unk1;	// 4		// 0
	DWORD		unk2;	// 8		// 32
	DWORD		unk3;	// 2		// 0
	DWORD		unk4;	// 1		// 1
	PVOID		unk5;	// 8*0
	DWORD		unk6;	// 3		// 2
	// align
	PSID		DomainSid;
	KDC_DOMAIN_KEYS_INFO	IncomingAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	OutgoingAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	IncomingPreviousAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	OutgoingPreviousAuthenticationKeys;
} KDC_DOMAIN_INFO , *PKDC_DOMAIN_INFO;