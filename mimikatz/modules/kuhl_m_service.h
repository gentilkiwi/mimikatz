/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_service.h"
#include "../modules/kull_m_file.h"
#include "kuhl_m_service_remote.h"

const KUHL_M kuhl_m_service;

NTSTATUS kuhl_m_c_service_init();
NTSTATUS kuhl_m_c_service_clean();

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
NTSTATUS kuhl_m_service_installme(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_uninstallme(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_service_me(int argc, wchar_t * argv[]);

void WINAPI kuhl_m_service_CtrlHandler(DWORD Opcode);
void WINAPI kuhl_m_service_Main(DWORD argc, LPTSTR *argv);