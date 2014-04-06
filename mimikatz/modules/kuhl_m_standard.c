/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_standard.h"

const KUHL_M_C kuhl_m_c_standard[] = {
	//{kuhl_m_standard_test,		L"test",	L"Test routine (you don\'t want to see this !)"},
	{kuhl_m_standard_exit,		L"exit",	L"Quit mimikatz"},
	{kuhl_m_standard_cls,		L"cls",		L"Clear screen (doesn\'t work with redirections, like PsExec)"},
	{kuhl_m_standard_answer,	L"answer",	L"Answer to the Ultimate Question of Life, the Universe, and Everything"},
	{kuhl_m_standard_sleep,		L"sleep",	L"Sleep an amount of milliseconds"},
	{kuhl_m_standard_log,		L"log",		L"Log mimikatz input/output to file"},
	{kuhl_m_standard_version,	L"version",	L"Display some version informations"},
};
const KUHL_M kuhl_m_standard = {
	L"standard",	L"Standard module",	L"Basic commands (does not require module name)",
	sizeof(kuhl_m_c_standard) / sizeof(KUHL_M_C), kuhl_m_c_standard, NULL, NULL
};
/*
NTSTATUS kuhl_m_standard_test(int argc, wchar_t * argv[])
{
	SC_HANDLE hSC, hS;
	DWORD i, szRoot, szNeeded, cbServices;
	LPWSTR systemRoot;
	LPENUM_SERVICE_STATUS_PROCESSW pEnumServiceBuffer;
	LPQUERY_SERVICE_CONFIG pServiceConfigBuffer;

	if(szRoot = GetEnvironmentVariable(L"SystemRoot", NULL, 0))
	{
		if(systemRoot = (LPWSTR) LocalAlloc(LPTR, szRoot * sizeof(wchar_t)))
		{
			if(GetEnvironmentVariable(L"SystemRoot", systemRoot, szRoot))
			{
				if(hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE))
				{
					if(!EnumServicesStatusEx(hSC, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL, NULL, 0, &szNeeded, &cbServices, NULL, NULL) && (GetLastError() == ERROR_MORE_DATA))
					{
						if(pEnumServiceBuffer = (LPENUM_SERVICE_STATUS_PROCESSW) LocalAlloc(LPTR, szNeeded))
						{
							if(EnumServicesStatusEx(hSC, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL, (PBYTE) pEnumServiceBuffer, szNeeded, &szNeeded, &cbServices, NULL, NULL))
							{
								for(i = 0; i < cbServices; i ++)
								{
									if(hS = OpenService(hSC, pEnumServiceBuffer[i].lpServiceName, SERVICE_QUERY_CONFIG))
									{
										if(!QueryServiceConfig(hS, NULL, 0, &szNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
										{
											if(pServiceConfigBuffer = (LPQUERY_SERVICE_CONFIG) LocalAlloc(LPTR, szNeeded))
											{
												if(QueryServiceConfig(hS, pServiceConfigBuffer, szNeeded, &szNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
												{
													if(
														(_wcsnicmp(pServiceConfigBuffer->lpBinaryPathName, systemRoot, szRoot - 1) != 0) &&
														(_wcsnicmp(pServiceConfigBuffer->lpBinaryPathName, L"system32\\", 9) != 0) &&
														(_wcsnicmp(pServiceConfigBuffer->lpBinaryPathName, L"\\SystemRoot\\system32\\", 21) != 0) &&
														(_wcsnicmp(pServiceConfigBuffer->lpBinaryPathName, L"\\??\\", 4) != 0)
														)
														kprintf(L"%s\t%s\n", pEnumServiceBuffer[i].lpServiceName, pServiceConfigBuffer->lpBinaryPathName);
												}
												LocalFree(pServiceConfigBuffer);
											}
										} else PRINT_ERROR_AUTO(L"QueryServiceConfig");
										CloseServiceHandle(hS);
									} else PRINT_ERROR_AUTO(L"OpenService");
								}
							} else PRINT_ERROR_AUTO(L"EnumServicesStatusEx");
							LocalFree(pEnumServiceBuffer);
						}
					} else PRINT_ERROR_AUTO(L"EnumServicesStatusEx");
					CloseServiceHandle(hSC);
				}
			}
			LocalFree(systemRoot);
		}
	}
	return STATUS_SUCCESS;
}
*/
NTSTATUS kuhl_m_standard_exit(int argc, wchar_t * argv[])
{
	kprintf(L"Bye!\n");
	return STATUS_FATAL_APP_EXIT;
}

NTSTATUS kuhl_m_standard_cls(int argc, wchar_t * argv[])
{
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD coord = {0, 0};
	DWORD count;
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	GetConsoleScreenBufferInfo(hStdOut, &csbi);
	FillConsoleOutputCharacter(hStdOut, L' ', csbi.dwSize.X * csbi.dwSize.Y, coord, &count);
	SetConsoleCursorPosition(hStdOut, coord);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_answer(int argc, wchar_t * argv[])
{
	kprintf(L"42.\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_sleep(int argc, wchar_t * argv[])
{
	DWORD dwMilliseconds = argc ? wcstoul(argv[0], NULL, 0) : 1000;
	kprintf(L"Sleep : %u ms... ", dwMilliseconds);
	Sleep(dwMilliseconds);
	kprintf(L"End !\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_log(int argc, wchar_t * argv[])
{
	PCWCHAR filename = (kull_m_string_args_byName(argc, argv, L"stop", NULL, NULL) ? NULL : (argc ? argv[0] : MIMIKATZ_DEFAULT_LOG));
	kprintf(L"Using \'%s\' for logfile : %s\n", filename, kull_m_output_file(filename) ? L"OK" : L"KO");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_version(int argc, wchar_t * argv[])
{
	BOOL isWow64;
	#ifdef _M_X64
	isWow64 = TRUE;
	#else
	if(IsWow64Process(GetCurrentProcess(), &isWow64))
	#endif
	{
		kprintf(
			L"\n" MIMIKATZ L" " MIMIKATZ_VERSION L" (arch " MIMIKATZ_ARCH L")\n"
			L"NT     -  Windows NT %u.%u build %u (arch x%s)\n",
			MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER, isWow64 ? L"64" : L"86"
			);
	}
	return STATUS_SUCCESS;
}