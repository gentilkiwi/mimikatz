/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m_service.h"
#include "../modules/kull_m_remotelib.h"
#include "../modules/kull_m_patch.h"

typedef DWORD (WINAPI * PSCSENDCONTROL) (LPCWSTR lpServiceName, PVOID arg1, PVOID arg2, int arg3, DWORD dwControl, DWORD arg4, PVOID arg5, DWORD arg6, PVOID arg7, DWORD arg8, DWORD arg9, PVOID arg10, PVOID arg11, PVOID arg12);
typedef LPVOID(WINAPI * PVIRTUALALLOC) (__in_opt LPVOID lpAddress, __in     SIZE_T dwSize, __in     DWORD flAllocationType, __in     DWORD flProtect);

typedef struct _KUHL_M_SERVICE_FORCE_INPUT {
	PSCSENDCONTROL pScSendControl;
	DWORD dwControl;
	WCHAR ServiceName[ANYSIZE_ARRAY];
} KUHL_M_SERVICE_FORCE_INPUT, *PKUHL_M_SERVICE_FORCE_INPUT;

typedef struct _KUHL_M_SERVICE_FORCE_OUTPUT {
	DWORD dwStatus;
} KUHL_M_SERVICE_FORCE_OUTPUT, *PKUHL_M_SERVICE_FORCE_OUTPUT;

DWORD WINAPI kuhl_service_sendcontrol_thread(PREMOTE_LIB_FUNC lpParameter);
DWORD kuhl_service_sendcontrol_thread_end();

BOOL kuhl_service_sendcontrol_inprocess(PWSTR ServiceName, DWORD dwControl);