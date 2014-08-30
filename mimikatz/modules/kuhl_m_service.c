/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
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
};

const KUHL_M kuhl_m_service = {
	L"service", L"Service module", NULL,
	ARRAYSIZE(kuhl_m_c_service), kuhl_m_c_service, NULL, NULL
};

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
		else if(dwControl && (MIMIKATZ_NT_BUILD_NUMBER >= KULL_M_WIN_BUILD_7))
		{
			kuhl_service_sendcontrol_inprocess(argv[0], dwControl);
		}
		else PRINT_ERROR(L"Inject not available\n");
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