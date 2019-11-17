/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m_service.h"
#if defined(SERVICE_INCONTROL)
#include "../modules/kull_m_remotelib.h"
#include "../modules/kull_m_patch.h"

typedef DWORD ( __stdcall * PSCSENDCONTROL_STD)	(LPCWSTR lpServiceName, PVOID arg1, PVOID arg2, int arg3, DWORD dwControl, DWORD arg4, PVOID arg5, DWORD arg6, PVOID arg7, DWORD arg8, DWORD arg9, PVOID arg10, PVOID arg11, PVOID arg12);
typedef DWORD (__fastcall * PSCSENDCONTROL_FAST)(LPCWSTR lpServiceName, PVOID arg1, PVOID arg2, int arg3, DWORD dwControl, DWORD arg4, PVOID arg5, DWORD arg6, PVOID arg7, DWORD arg8, DWORD arg9, PVOID arg10, PVOID arg11, PVOID arg12);

DWORD WINAPI kuhl_service_sendcontrol_std_thread(PREMOTE_LIB_DATA lpParameter);
DWORD kuhl_service_sendcontrol_std_thread_end();
DWORD WINAPI kuhl_service_sendcontrol_fast_thread(PREMOTE_LIB_DATA lpParameter);
DWORD kuhl_service_sendcontrol_fast_thread_end();

BOOL kuhl_service_sendcontrol_inprocess(PWSTR ServiceName, DWORD dwControl);
#endif