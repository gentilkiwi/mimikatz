/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"

BOOL kull_m_service_getUniqueForName(PCWSTR serviceName, SERVICE_STATUS_PROCESS * pServiceStatusProcess);

BOOL kull_m_service_start(PCWSTR serviceName);
BOOL kull_m_service_remove(PCWSTR serviceName);
BOOL kull_m_service_stop(PCWSTR serviceName);
BOOL kull_m_service_suspend(PCWSTR serviceName);
BOOL kull_m_service_resume(PCWSTR serviceName);
BOOL kull_m_service_preshutdown(PCWSTR serviceName);
BOOL kull_m_service_shutdown(PCWSTR serviceName);

BOOL kull_m_service_genericControl(PCWSTR serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus);