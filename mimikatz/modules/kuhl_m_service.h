/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_service.h"
#include "kuhl_m_service_remote.h"

const KUHL_M kuhl_m_service;

typedef BOOL (* KUHL_M_SERVICE_FUNC) (PCWSTR serviceName);
NTSTATUS genericFunction(KUHL_M_SERVICE_FUNC function, wchar_t * text, int argc, wchar_t * argv[], DWORD dwControl);

NTSTATUS kuhl_m_service_start(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_remove(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_stop(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_suspend(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_resume(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_preshutdown(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_shutdown(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_list(int argc, wchar_t * argv[]);