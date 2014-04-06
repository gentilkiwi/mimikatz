/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m_sekurlsa_utils.h"
#include "kuhl_m_sekurlsa_nt6.h"
#include "kuhl_m_sekurlsa_packages.h"

USHORT NtBuildNumber;

#define KUHL_SEKURLSA_CREDS_DISPLAY_RAW				0x00000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_LINE			0x00000001
#define KUHL_SEKURLSA_CREDS_DISPLAY_NEWLINE			0x00000002

#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL		0x08000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY			0x01000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY	0x02000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL_MASK	0x07000000

#define KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE			0x00800000

#define KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT		0x10000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_WPASSONLY		0x20000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN			0x40000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_SSP				0x80000000

typedef void (CALLBACK * PKUHL_M_SEKURLSA_PACKAGE_CALLBACK) (IN ULONG_PTR pKerbGlobalLogonSessionTable, IN PLUID logId, IN PVOID pCredentials);

typedef struct _KUHL_M_SEKURLSA_PACKAGE {
	const char * name;
	const char * symbolName;
	ULONG_PTR symbolPtr;
	const PKUHL_M_SEKURLSA_PACKAGE_CALLBACK callback;
} KUHL_M_SEKURLSA_PACKAGE, *PKUHL_M_SEKURLSA_PACKAGE;

typedef struct _KUHL_M_SEKURLSA_ENUM_HELPER {
	ULONG tailleStruct;
	LONG offsetToLuid;
	LONG offsetToLogonType;
	LONG offsetToSession;
	LONG offsetToUsername;
	LONG offsetToDomain;
	LONG offsetToCredentials;
	LONG offsetToPSid;
} KUHL_M_SEKURLSA_ENUM_HELPER, *PKUHL_M_SEKURLSA_ENUM_HELPER;

typedef struct _KIWI_BASIC_SECURITY_LOGON_SESSION_DATA {
	PLUID						LogonId;
	PLSA_UNICODE_STRING			UserName;
	PLSA_UNICODE_STRING			LogonDomain;
	ULONG						LogonType;
	ULONG						Session;
	PVOID						pCredentials;
	PSID						pSid;
} KIWI_BASIC_SECURITY_LOGON_SESSION_DATA, *PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA;

LPEXT_API_VERSION WDBGAPI ExtensionApiVersion (void);
VOID CheckVersion(void);
VOID WDBGAPI WinDbgExtensionDllInit (PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion);
DECLARE_API(mimikatz);

VOID kuhl_m_sekurlsa_genericCredsOutput(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, PLUID luid, ULONG flags);
VOID kuhl_m_sekurlsa_genericKeyOutput(struct _MARSHALL_KEY * key, PVOID * dirtyBase);