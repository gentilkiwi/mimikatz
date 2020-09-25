/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../../modules/kull_m_process.h"
#include "../../modules/kull_m_memory.h"
#include "../../modules/kull_m_patch.h"
#include "../../modules/kull_m_file.h"
#include "../../modules/kull_m_net.h"
#include "../../modules/kull_m_remotelib.h"
#include "../../modules/kull_m_crypto_system.h"
#include "../../modules/kull_m_crypto_ngc.h"
#include "../../modules/rpc/kull_m_rpc_ms-rprn.h"
#include <fltUser.h>

const KUHL_M kuhl_m_misc;

NTSTATUS kuhl_m_misc_cmd(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_regedit(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_taskmgr(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_ncroutemon(int argc, wchar_t * argv[]);
#if !defined(_M_ARM64)
NTSTATUS kuhl_m_misc_detours(int argc, wchar_t * argv[]);
#endif
//NTSTATUS kuhl_m_misc_addsid(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_memssp(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_skeleton(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_compress(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_lock(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_wp(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_mflt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_easyntlmchall(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_clip(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_xor(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_aadcookie(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_aadcookie_NgcSignWithSymmetricPopKey(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_misc_spooler(int argc, wchar_t * argv[]);

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

#if !defined(NTDSAPI)
#define NTDSAPI DECLSPEC_IMPORT
#endif
NTDSAPI DWORD WINAPI DsBindW(IN OPTIONAL LPCWSTR DomainControllerName, IN OPTIONAL LPCWSTR DnsDomainName, OUT HANDLE *phDS);
NTDSAPI DWORD WINAPI DsAddSidHistoryW(IN HANDLE hDS, IN DWORD Flags, IN LPCWSTR SrcDomain, IN LPCWSTR SrcPrincipal, IN OPTIONAL LPCWSTR SrcDomainController, IN OPTIONAL RPC_AUTH_IDENTITY_HANDLE SrcDomainCreds, IN LPCWSTR DstDomain, IN LPCWSTR DstPrincipal);
NTDSAPI DWORD WINAPI DsUnBindW(IN HANDLE *phDS);

typedef BOOL	(WINAPI * PLOCKWORKSTATION) (VOID);
typedef BOOL	(WINAPI * PSYSTEMPARAMETERSINFOW) (__in UINT uiAction, __in UINT uiParam, __inout_opt PVOID pvParam, __in UINT fWinIni);
typedef DWORD	(WINAPI * PGETLASTERROR) (VOID);

typedef struct _KIWI_WP_DATA {
	UNICODE_STRING process;
	PCWCHAR wp;
} KIWI_WP_DATA, *PKIWI_WP_DATA;

BOOL CALLBACK kuhl_m_misc_lock_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
void kuhl_m_misc_lock_for_pid(DWORD pid, PCWCHAR wp);
BOOL CALLBACK kuhl_m_misc_wp_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
void kuhl_m_misc_wp_for_pid(DWORD pid, PCWCHAR wp);
void kuhl_m_misc_mflt_display(PFILTER_AGGREGATE_BASIC_INFORMATION info);

BOOL WINAPI kuhl_misc_clip_WinHandlerRoutine(DWORD dwCtrlType);
LRESULT APIENTRY kuhl_m_misc_clip_MainWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

#ifndef __proofofpossessioncookieinfo_h__
#define __proofofpossessioncookieinfo_h__

#ifndef __IProofOfPossessionCookieInfoManager_FWD_DEFINED__
#define __IProofOfPossessionCookieInfoManager_FWD_DEFINED__
typedef interface IProofOfPossessionCookieInfoManager IProofOfPossessionCookieInfoManager;
#endif

typedef struct ProofOfPossessionCookieInfo {
	LPWSTR name;
	LPWSTR data;
	DWORD flags;
	LPWSTR p3pHeader;
} ProofOfPossessionCookieInfo;

typedef struct IProofOfPossessionCookieInfoManagerVtbl {
	BEGIN_INTERFACE
	HRESULT (STDMETHODCALLTYPE *QueryInterface)(IProofOfPossessionCookieInfoManager * This, REFIID riid, __RPC__deref_out  void **ppvObject);
	ULONG (STDMETHODCALLTYPE *AddRef)(__RPC__in IProofOfPossessionCookieInfoManager * This);
	ULONG (STDMETHODCALLTYPE *Release)(__RPC__in IProofOfPossessionCookieInfoManager * This);
	HRESULT (STDMETHODCALLTYPE *GetCookieInfoForUri)(__RPC__in IProofOfPossessionCookieInfoManager * This, __RPC__in LPCWSTR uri, __RPC__out DWORD *cookieInfoCount, __RPC__deref_out_ecount_full_opt(*cookieInfoCount) ProofOfPossessionCookieInfo **cookieInfo);
	END_INTERFACE
} IProofOfPossessionCookieInfoManagerVtbl;

interface IProofOfPossessionCookieInfoManager {
	CONST_VTBL struct IProofOfPossessionCookieInfoManagerVtbl *lpVtbl;
};

#define IProofOfPossessionCookieInfoManager_QueryInterface(This,riid,ppvObject)							( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) )
#define IProofOfPossessionCookieInfoManager_AddRef(This)												( (This)->lpVtbl -> AddRef(This) )
#define IProofOfPossessionCookieInfoManager_Release(This)												( (This)->lpVtbl -> Release(This) )
#define IProofOfPossessionCookieInfoManager_GetCookieInfoForUri(This,uri,cookieInfoCount,cookieInfo)	( (This)->lpVtbl -> GetCookieInfoForUri(This,uri,cookieInfoCount,cookieInfo) )

#endif