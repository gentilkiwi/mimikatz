/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_kernel.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_service.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_string.h"
#include <aclapi.h>
#include <sddl.h>

typedef struct _KUHL_K_C {
	const PKUHL_M_C_FUNC pCommand;
	const DWORD ioctlCode;
	const wchar_t * command;
	const wchar_t * description;
} KUHL_K_C, *PKUHL_K_C;

NTSTATUS kuhl_m_kernel_do(wchar_t * input);

NTSTATUS kuhl_m_kernel_add_mimidrv(int argc, wchar_t * argv[]);
BOOL kuhl_m_kernel_addWorldToMimikatz(SC_HANDLE monHandle);
NTSTATUS kuhl_m_kernel_remove_mimidrv(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_kernel_processProtect(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kernel_processToken(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kernel_processPrivilege(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kernel_notifyProcessRemove(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kernel_notifyObjectRemove(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kernel_notifyGenericRemove(int argc, wchar_t * argv[], DWORD code);