/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
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

BOOL kull_m_service_addWorldToSD(SC_HANDLE monHandle)
{
	BOOL status = FALSE;
	DWORD dwSizeNeeded;
	PSECURITY_DESCRIPTOR oldSd, newSd;
	SECURITY_DESCRIPTOR dummySdForXP;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	EXPLICIT_ACCESS ForEveryOne = {
		SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_PAUSE_CONTINUE | SERVICE_START | SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL | READ_CONTROL,
		SET_ACCESS,
		NO_INHERITANCE,
		{NULL, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, NULL}
	};
	if(!QueryServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, &dummySdForXP, 0, &dwSizeNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
	{
		if(oldSd = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, dwSizeNeeded))
		{
			if(QueryServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, oldSd, dwSizeNeeded, &dwSizeNeeded))
			{
				if(AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, (PSID *)&ForEveryOne.Trustee.ptstrName))
				{
					if(BuildSecurityDescriptor(NULL, NULL, 1, &ForEveryOne, 0, NULL, oldSd, &dwSizeNeeded, &newSd) == ERROR_SUCCESS)
					{
						status = SetServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, newSd);
						LocalFree(newSd);
					}
					FreeSid(ForEveryOne.Trustee.ptstrName);
				}
			}
			LocalFree(oldSd);
		}
	}
	return status;
}

BOOL kull_m_service_install(PCWSTR serviceName, PCWSTR displayName, PCWSTR binPath, DWORD serviceType, DWORD startType, BOOL startIt)
{
	BOOL status = FALSE;
	SC_HANDLE hSC = NULL, hS = NULL;

	if(hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE))
	{
		if(hS = OpenService(hSC, serviceName, SERVICE_START))
		{
			kprintf(L"[+] \'%s\' service already registered\n", serviceName);
		}
		else
		{
			if(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
			{
				kprintf(L"[*] \'%s\' service not present\n", serviceName);
				if(hS = CreateService(hSC, serviceName, displayName, READ_CONTROL | WRITE_DAC | SERVICE_START, serviceType, startType, SERVICE_ERROR_NORMAL, binPath, NULL, NULL, NULL, NULL, NULL))
				{
					kprintf(L"[+] \'%s\' service successfully registered\n", serviceName);
					if(status = kull_m_service_addWorldToSD(hS))
						kprintf(L"[+] \'%s\' service ACL to everyone\n", serviceName);
					else PRINT_ERROR_AUTO(L"kull_m_service_addWorldToSD");
				}
				else PRINT_ERROR_AUTO(L"CreateService");
			}
			else PRINT_ERROR_AUTO(L"OpenService");
		}
		if(hS)
		{
			if(startIt)
			{
				if(status = StartService(hS, 0, NULL))
					kprintf(L"[+] \'%s\' service started\n", serviceName);
				else if(GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
					kprintf(L"[*] \'%s\' service already started\n", serviceName);
				else PRINT_ERROR_AUTO(L"StartService");
			}
			CloseServiceHandle(hS);
		}
		CloseServiceHandle(hSC);
	}
	else PRINT_ERROR_AUTO(L"OpenSCManager(create)");
	return status;
}

BOOL kull_m_service_uninstall(PCWSTR serviceName)
{
	BOOL status = FALSE, toRemove = TRUE;
	if(kull_m_service_stop(serviceName))
		kprintf(L"[+] \'%s\' service stopped\n", serviceName);
	else if(GetLastError() == ERROR_SERVICE_NOT_ACTIVE)
		kprintf(L"[*] \'%s\' service not running\n", serviceName);
	else
	{
		toRemove = FALSE;
		PRINT_ERROR_AUTO(L"kull_m_service_stop");
	}

	if(toRemove)
	{
		if(status = kull_m_service_remove(serviceName))
			kprintf(L"[+] \'%s\' service removed\n", serviceName);
		else PRINT_ERROR_AUTO(L"kull_m_service_remove");
	}
	return STATUS_SUCCESS;
}