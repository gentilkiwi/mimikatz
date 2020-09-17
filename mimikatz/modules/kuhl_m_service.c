/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_service.h"

const KUHL_M_C kuhl_m_c_service[] = {
	{kuhl_m_service_start,		L"start",		L"Start service"},
	{kuhl_m_service_remove,		L"remove",		L"Remove service"},
	{kuhl_m_service_stop,		L"stop",		L"Stop service"},
	{kuhl_m_service_suspend,	L"suspend",		L"Suspend service"},
	{kuhl_m_service_resume,		L"resume",		L"Resume service"},
	{kuhl_m_service_preshutdown,L"preshutdown",	L"Preshutdown service"},
	{kuhl_m_service_shutdown,	L"shutdown",	L"Shutdown service"},
	{kuhl_m_service_list,		L"list",		L"List services"},
	{kuhl_m_service_installme,	L"+",			L"Install Me!"},
	{kuhl_m_service_uninstallme,L"-",			L"Install Me!"},
	{kuhl_m_service_me,			L"me",			L"Me!"},
};

const KUHL_M kuhl_m_service = {
	L"service", L"Service module", NULL,
	ARRAYSIZE(kuhl_m_c_service), kuhl_m_c_service, kuhl_m_c_service_init, kuhl_m_c_service_clean
};

SERVICE_STATUS m_ServiceStatus = {SERVICE_WIN32_OWN_PROCESS, SERVICE_STOPPED, 0, NO_ERROR, 0, 0, 0};
SERVICE_STATUS_HANDLE m_ServiceStatusHandle;
HANDLE hKiwiEventRunning;

NTSTATUS kuhl_m_c_service_init()
{
	m_ServiceStatusHandle = NULL;
	hKiwiEventRunning = NULL;
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_c_service_clean()
{
	if(m_ServiceStatusHandle)
		kuhl_m_service_CtrlHandler(SERVICE_STOP);
	return STATUS_SUCCESS;
}

NTSTATUS genericFunction(KUHL_M_SERVICE_FUNC function, wchar_t * text, int argc, wchar_t * argv[], DWORD dwControl)
{
	if(argc)
	{
		kprintf(L"%s \'%s\' service : ", text, argv[0]);
		if(argc == 1)
		{
			if(function(argv[0]))
				kprintf(L"OK\n");
			else PRINT_ERROR_AUTO(L"Service operation");
		}
#if defined(SERVICE_INCONTROL)
		else if(dwControl && (MIMIKATZ_NT_BUILD_NUMBER >= KULL_M_WIN_BUILD_7))
		{
			kuhl_service_sendcontrol_inprocess(argv[0], dwControl);
		}
		else PRINT_ERROR(L"Inject not available\n");
#endif
	}
	else PRINT_ERROR(L"Missing service name argument\n");

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_service_start(int argc, wchar_t * argv[])
{
	return genericFunction(kull_m_service_start, L"Starting", argc, argv, 0);
}

NTSTATUS kuhl_m_service_remove(int argc, wchar_t * argv[])
{
	return genericFunction(kull_m_service_remove, L"Removing", argc, argv, 0);
}

NTSTATUS kuhl_m_service_stop(int argc, wchar_t * argv[])
{
	return genericFunction(kull_m_service_stop, L"Stopping", argc, argv, SERVICE_CONTROL_STOP);
}

NTSTATUS kuhl_m_service_suspend(int argc, wchar_t * argv[])
{
	return genericFunction(kull_m_service_suspend, L"Suspending", argc, argv, SERVICE_CONTROL_PAUSE);
}

NTSTATUS kuhl_m_service_resume(int argc, wchar_t * argv[])
{
	return genericFunction(kull_m_service_resume, L"Resuming", argc, argv, SERVICE_CONTROL_CONTINUE);
}

NTSTATUS kuhl_m_service_preshutdown(int argc, wchar_t * argv[])
{
	return genericFunction(kull_m_service_preshutdown, L"Preshutdown", argc, argv, SERVICE_CONTROL_PRESHUTDOWN);
}

NTSTATUS kuhl_m_service_shutdown(int argc, wchar_t * argv[])
{
	return genericFunction(kull_m_service_shutdown, L"Shutdown", argc, argv, SERVICE_CONTROL_SHUTDOWN);
}

NTSTATUS kuhl_m_service_list(int argc, wchar_t * argv[])
{
	return STATUS_SUCCESS;
}

const wchar_t kuhl_m_service_installme_args[] = L"rpc::server service::me exit";
NTSTATUS kuhl_m_service_installme(int argc, wchar_t * argv[])
{
#pragma warning(push)
#pragma warning(disable:4996)	
	wchar_t *fileName = _wpgmptr;
#pragma warning(pop)
	wchar_t *absFile, *buff;
	DWORD size;

	if(kull_m_file_getAbsolutePathOf(fileName, &absFile))
	{
		if(kull_m_file_isFileExist(absFile))
		{
			size = 1 + lstrlen(absFile) + 1 + 1 + lstrlen(kuhl_m_service_installme_args) + 1;
			if(buff = (wchar_t *) LocalAlloc(LPTR, size * sizeof(wchar_t)))
			{
				wcscat_s(buff, size, L"\"");
				wcscat_s(buff, size, absFile);
				wcscat_s(buff, size, L"\" ");
				wcscat_s(buff, size, kuhl_m_service_installme_args);
				kull_m_service_install(MIMIKATZ_SERVICE, MIMIKATZ L" service (" MIMIKATZ_SERVICE L")", buff, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, TRUE);
				LocalFree(buff);
			}
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_isFileExist");
		LocalFree(absFile);
	}
	else PRINT_ERROR_AUTO(L"kull_m_file_getAbsolutePathOf");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_service_uninstallme(int argc, wchar_t * argv[])
{
	kull_m_service_uninstall(MIMIKATZ_SERVICE);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_service_me(int argc, wchar_t * argv[])
{
	const SERVICE_TABLE_ENTRY DispatchTable[]= {{MIMIKATZ_SERVICE, kuhl_m_service_Main}, {NULL, NULL}};
	if(hKiwiEventRunning = CreateEvent(NULL, TRUE, FALSE, NULL))
	{
		StartServiceCtrlDispatcher(DispatchTable);
		CloseHandle(hKiwiEventRunning);
	}
	return STATUS_SUCCESS;
}

void WINAPI kuhl_m_service_CtrlHandler(DWORD Opcode)
{
	BOOL notCoded = FALSE;
	switch(Opcode)
	{
		case SERVICE_CONTROL_PAUSE: 
			m_ServiceStatus.dwCurrentState = SERVICE_PAUSED;
			break;
		case SERVICE_CONTROL_CONTINUE:
			m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
			break;
		case SERVICE_CONTROL_STOP:
		case SERVICE_CONTROL_SHUTDOWN: 
			m_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
			break;
		default:
			notCoded = TRUE;
	}
	if(!notCoded)
	{
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		if(m_ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING)
			SetEvent(hKiwiEventRunning);
	}
	return;
}

void WINAPI kuhl_m_service_Main(DWORD argc, LPTSTR *argv)
{
	if(m_ServiceStatusHandle = RegisterServiceCtrlHandler(MIMIKATZ_SERVICE, kuhl_m_service_CtrlHandler))
	{
		m_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
		m_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		WaitForSingleObject(hKiwiEventRunning, INFINITE);
		m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		m_ServiceStatusHandle = NULL;
	}
}