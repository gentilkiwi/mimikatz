/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once

#include "globals.h"
#include "modules/kuhl_m_standard.h"
#include "modules/kuhl_m_crypto.h"
#include "modules/sekurlsa/kuhl_m_sekurlsa.h"
#include "modules/kerberos/kuhl_m_kerberos.h"
#include "modules/kuhl_m_process.h"
#include "modules/kuhl_m_service.h"
#include "modules/kuhl_m_privilege.h"
#include "modules/kuhl_m_lsadump.h"
#include "modules/kuhl_m_ts.h"
#include "modules/kuhl_m_event.h"
#include "modules/kuhl_m_misc.h"
#include "modules/kuhl_m_token.h"
#include "modules/kuhl_m_vault.h"
#include "modules/kuhl_m_minesweeper.h"
#ifdef NET_MODULE
#include "modules/kuhl_m_net.h"
#endif
#include "modules/dpapi/kuhl_m_dpapi.h"
#include "modules/kuhl_m_kernel.h"
#include "modules/kuhl_m_busylight.h"
#include "modules/kuhl_m_sysenvvalue.h"
#include "modules/kuhl_m_sid.h"
#include "modules/kuhl_m_iis.h"
#include "modules/kuhl_m_rpc.h"

#include <io.h>
#include <fcntl.h>
#define DELAYIMP_INSECURE_WRITABLE_HOOKS
#include <delayimp.h>

extern VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

void mimikatz_begin();
void mimikatz_end();

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);

NTSTATUS mimikatz_initOrClean(BOOL Init);

NTSTATUS mimikatz_doLocal(wchar_t * input);
NTSTATUS mimikatz_dispatchCommand(wchar_t * input);

#ifdef _M_X64
#pragma comment(linker, "/export:collect=collectEntries")
#pragma comment(linker, "/export:get=getEntry")
#elif defined _M_IX86
#pragma comment(linker, "/export:collect=_collectEntries@16")
#pragma comment(linker, "/export:get=_getEntry@16")
#endif