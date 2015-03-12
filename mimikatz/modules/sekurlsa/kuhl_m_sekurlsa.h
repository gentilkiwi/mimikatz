/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../kuhl_m.h"
#include "globals_sekurlsa.h"

#include "kuhl_m_sekurlsa_utils.h"
#include "crypto/kuhl_m_sekurlsa_nt5.h"
#include "crypto/kuhl_m_sekurlsa_nt6.h"
#ifdef LSASS_DECRYPT
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

#define KUHL_SEKURLSA_CREDS_DISPLAY_RAW				0x00000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_LINE			0x00000001
#define KUHL_SEKURLSA_CREDS_DISPLAY_NEWLINE			0x00000002

#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL		0x08000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY			0x01000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY_10		0x02000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY	0x03000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL_MASK	0x07000000

#define KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST		0x00200000
#define KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS		0x00400000
#define KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE			0x00800000

#define KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT		0x10000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_WPASSONLY		0x20000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN			0x40000000
#define KUHL_SEKURLSA_CREDS_DISPLAY_SSP				0x80000000

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
VOID kuhl_m_sekurlsa_genericCredsOutput(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, PLUID luid, ULONG flags);
VOID kuhl_m_sekurlsa_genericKeyOutput(struct _MARSHALL_KEY * key, PVOID * dirtyBase);

NTSTATUS kuhl_m_sekurlsa_all(int argc, wchar_t * argv[]);
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