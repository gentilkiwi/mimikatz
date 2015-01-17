/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_memory.h"
#include "../modules/kull_m_patch.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_net.h"
#include "../modules/kull_m_remotelib.h"
#include "../modules/kull_m_crypto_system.h"

const KUHL_M kuhl_m_misc;

NTSTATUS kuhl_m_misc_cmd(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_regedit(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_taskmgr(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_ncroutemon(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_detours(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_wifi(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_addsid(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_memssp(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_skeleton(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_misc_init();
NTSTATUS kuhl_m_misc_clean();

BOOL CALLBACK kuhl_m_misc_detours_callback_process(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_misc_detours_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_misc_detours_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
BOOL CALLBACK kuhl_m_misc_detours_callback_module_name_addr(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);

typedef struct _KUHL_M_MISC_DETOURS_HOOKS {
	DWORD minLevel;
	PBYTE pattern;
	DWORD szPattern;
	DWORD offsetToRead;
	DWORD szToRead;
	BOOL isRelative;
	BOOL isTarget;
} KUHL_M_MISC_DETOURS_HOOKS, *PKUHL_M_MISC_DETOURS_HOOKS;

PBYTE kuhl_m_misc_detours_testHookDestination(PKULL_M_MEMORY_ADDRESS base, WORD machineOfProcess, DWORD level);
BOOL kuhl_m_misc_generic_nogpo_patch(PCWSTR commandLine, PWSTR disableString, SIZE_T szDisableString, PWSTR enableString, SIZE_T szEnableString);

typedef enum _WLAN_INTERFACE_STATE { 
	wlan_interface_state_not_ready				= 0,
	wlan_interface_state_connected				= 1,
	wlan_interface_state_ad_hoc_network_formed	= 2,
	wlan_interface_state_disconnecting			= 3,
	wlan_interface_state_disconnected			= 4,
	wlan_interface_state_associating			= 5,
	wlan_interface_state_discovering			= 6,
	wlan_interface_state_authenticating			= 7
} WLAN_INTERFACE_STATE, *PWLAN_INTERFACE_STATE;

typedef struct _WLAN_INTERFACE_INFO {
	GUID	InterfaceGuid;
	WCHAR	strInterfaceDescription[256];
	WLAN_INTERFACE_STATE isState;
} WLAN_INTERFACE_INFO, *PWLAN_INTERFACE_INFO;

typedef struct _WLAN_INTERFACE_INFO_LIST {
	DWORD	dwNumberOfItems;
	DWORD	dwIndex;
	WLAN_INTERFACE_INFO InterfaceInfo[];
} WLAN_INTERFACE_INFO_LIST, *PWLAN_INTERFACE_INFO_LIST;

typedef struct _WLAN_PROFILE_INFO {
	WCHAR strProfileName[256];
	DWORD dwFlags;
} WLAN_PROFILE_INFO, *PWLAN_PROFILE_INFO;

typedef struct _WLAN_PROFILE_INFO_LIST {
	DWORD	dwNumberOfItems;
	DWORD	dwIndex;
	WLAN_PROFILE_INFO ProfileInfo[1];
} WLAN_PROFILE_INFO_LIST, *PWLAN_PROFILE_INFO_LIST;

#define WLAN_PROFILE_GET_PLAINTEXT_KEY	4

typedef DWORD	(WINAPI * PWLANOPENHANDLE)		(IN DWORD dwClientVersion, IN PVOID pReserved, OUT PDWORD pdwNegotiatedVersion, OUT PHANDLE phClientHandle);
typedef DWORD	(WINAPI * PWLANCLOSEHANDLE)		(IN HANDLE hClientHandle, IN PVOID pReserved);
typedef DWORD	(WINAPI * PWLANENUMINTERFACES)	(IN HANDLE hClientHandle, IN PVOID pReserved, OUT PWLAN_INTERFACE_INFO_LIST *ppInterfaceList);
typedef DWORD	(WINAPI * PWLANGETPROFILELIST)	(IN HANDLE hClientHandle, IN LPCGUID pInterfaceGuid, IN PVOID pReserved, OUT PWLAN_PROFILE_INFO_LIST *ppProfileList);
typedef DWORD	(WINAPI * PWLANGETPROFILE)		(IN HANDLE hClientHandle, IN LPCGUID pInterfaceGuid, IN LPCWSTR strProfileName, IN PVOID pReserved, IN LPWSTR *pstrProfileXml, IN OUT OPTIONAL DWORD *pdwFlags, OUT OPTIONAL PDWORD pdwGrantedAccess);
typedef VOID	(WINAPI * PWLANFREEMEMORY)		(IN PVOID pMemory);

#ifndef NTDSAPI
#define NTDSAPI DECLSPEC_IMPORT
#endif
NTDSAPI DWORD WINAPI DsBindW(IN OPTIONAL LPCWSTR DomainControllerName, IN OPTIONAL LPCWSTR DnsDomainName, OUT HANDLE *phDS);
NTDSAPI DWORD WINAPI DsAddSidHistoryW(IN HANDLE hDS, IN DWORD Flags, IN LPCWSTR SrcDomain, IN LPCWSTR SrcPrincipal, IN OPTIONAL LPCWSTR SrcDomainController, IN OPTIONAL RPC_AUTH_IDENTITY_HANDLE SrcDomainCreds, IN LPCWSTR DstDomain, IN LPCWSTR DstPrincipal);
NTDSAPI DWORD WINAPI DsUnBindW(IN HANDLE *phDS);