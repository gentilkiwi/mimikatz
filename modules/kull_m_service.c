/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kull_m_service.h"

BOOL kull_m_service_getUniqueForName(PCWSTR serviceName, SERVICE_STATUS_PROCESS * pServiceStatusProcess)
{
	BOOL status = FALSE;
	SC_HANDLE hSC, hS;
	DWORD szNeeded;

	if(hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT))
	{
		if(hS = OpenService(hSC, serviceName, SERVICE_QUERY_STATUS))
		{
			status = QueryServiceStatusEx(hS, SC_STATUS_PROCESS_INFO, (BYTE *) pServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &szNeeded);
			CloseServiceHandle(hS);
		}
		CloseServiceHandle(hSC);
	}
	return status;	
}

BOOL kull_m_service_start(PCWSTR serviceName)
{
	BOOL status = FALSE;
	SC_HANDLE hSC, hS;

	if(hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT))
	{
		if(hS = OpenService(hSC, serviceName, SERVICE_START))
		{
			status = StartService(hS, 0, NULL);
			CloseServiceHandle(hS);
		}
		CloseServiceHandle(hSC);
	}
	return status;
}

BOOL kull_m_service_remove(PCWSTR serviceName)
{
	BOOL status = FALSE;
	SC_HANDLE hSC, hS;

	if(hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT))
	{
		if(hS = OpenService(hSC, serviceName, DELETE))
		{
			status = DeleteService(hS);
			CloseServiceHandle(hS);
		}
		CloseServiceHandle(hSC);
	}
	return status;
}

BOOL kull_m_service_genericControl(PCWSTR serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus)
{
	BOOL status = FALSE;
	SC_HANDLE hSC, hS;
	SERVICE_STATUS serviceStatus;

	if(hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT))
	{
		if(hS = OpenService(hSC, serviceName, dwDesiredAccess))
		{
			status = ControlService(hS, dwControl, ptrServiceStatus ? ptrServiceStatus : &serviceStatus);
			CloseServiceHandle(hS);
		}
		CloseServiceHandle(hSC);
	}
	return status;
}

BOOL kull_m_service_stop(PCWSTR serviceName)
{
	return(kull_m_service_genericControl(serviceName, SERVICE_STOP, SERVICE_CONTROL_STOP, NULL));
}

BOOL kull_m_service_suspend(PCWSTR serviceName)
{
	return(kull_m_service_genericControl(serviceName, SERVICE_PAUSE_CONTINUE, SERVICE_CONTROL_PAUSE, NULL));
}

BOOL kull_m_service_resume(PCWSTR serviceName)
{
	return(kull_m_service_genericControl(serviceName, SERVICE_PAUSE_CONTINUE, SERVICE_CONTROL_CONTINUE, NULL));
}

BOOL kull_m_service_preshutdown(PCWSTR serviceName)
{
	return(kull_m_service_genericControl(serviceName, SERVICE_ALL_ACCESS, SERVICE_CONTROL_PRESHUTDOWN, NULL));
}

BOOL kull_m_service_shutdown(PCWSTR serviceName)
{
	return(kull_m_service_genericControl(serviceName, SERVICE_ALL_ACCESS, SERVICE_CONTROL_SHUTDOWN, NULL));
}