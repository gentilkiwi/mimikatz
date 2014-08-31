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

DWORD WINAPI kuhl_service_sendcontrol_thread(PREMOTE_LIB_DATA lpParameter);
DWORD kuhl_service_sendcontrol_thread_end();

BOOL kuhl_service_sendcontrol_inprocess(PWSTR ServiceName, DWORD dwControl);