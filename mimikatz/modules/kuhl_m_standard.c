/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_standard.h"

const KUHL_M_C kuhl_m_c_standard[] = {
	//{kuhl_m_standard_test,		L"test",	L"Test routine (you don\'t want to see this !)"},
	{kuhl_m_standard_exit,		L"exit",		L"Quit mimikatz"},
	{kuhl_m_standard_cls,		L"cls",			L"Clear screen (doesn\'t work with redirections, like PsExec)"},
	{kuhl_m_standard_answer,	L"answer",		L"Answer to the Ultimate Question of Life, the Universe, and Everything"},
	{kuhl_m_standard_coffee,	L"coffee",		L"Please, make me a coffee!"},
	{kuhl_m_standard_sleep,		L"sleep",		L"Sleep an amount of milliseconds"},
	{kuhl_m_standard_log,		L"log",			L"Log mimikatz input/output to file"},
	{kuhl_m_standard_base64,	L"base64",		L"Switch file input/output base64"},
	{kuhl_m_standard_version,	L"version",		L"Display some version informations"},
	{kuhl_m_standard_cd,		L"cd",			L"Change or display current directory"},
	{kuhl_m_standard_localtime,	L"localtime",	L"Displays system local date and time (OJ command)"},
	{kuhl_m_standard_hostname,	L"hostname",	L"Displays system local hostname"},
};
const KUHL_M kuhl_m_standard = {
	L"standard",	L"Standard module",	L"Basic commands (does not require module name)",
	ARRAYSIZE(kuhl_m_c_standard), kuhl_m_c_standard, NULL, NULL
};
/*
NTSTATUS kuhl_m_standard_test(int argc, wchar_t * argv[])
{
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

NTSTATUS kuhl_m_standard_coffee(int argc, wchar_t * argv[])
{
	kprintf(L"\n    ( (\n     ) )\n  .______.\n  |      |]\n  \\      /\n   `----'\n");
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

NTSTATUS kuhl_m_standard_base64(int argc, wchar_t * argv[])
{
	if(!kull_m_string_args_bool_byName(argc, argv, L"in", &isBase64InterceptInput))
		kull_m_string_args_bool_byName(argc, argv, L"input", &isBase64InterceptInput);

	if(!kull_m_string_args_bool_byName(argc, argv, L"out", &isBase64InterceptOutput))
		kull_m_string_args_bool_byName(argc, argv, L"output", &isBase64InterceptOutput);

	kprintf(L"isBase64InterceptInput  is %s\nisBase64InterceptOutput is %s\n", isBase64InterceptInput ? L"true" : L"false", isBase64InterceptOutput ? L"true" : L"false");
	return STATUS_SUCCESS;
}

const wchar_t *version_libs[] = {
	L"lsasrv.dll", L"msv1_0.dll", L"tspkg.dll", L"wdigest.dll", L"kerberos.dll", L"livessp.dll", L"dpapisrv.dll",
	L"kdcsvc.dll", L"cryptdll.dll", L"lsadb.dll", L"samsrv.dll", L"rsaenh.dll", L"ncrypt.dll", L"ncryptprov.dll",
	L"eventlog.dll", L"wevtsvc.dll", L"termsrv.dll",
};
NTSTATUS kuhl_m_standard_version(int argc, wchar_t * argv[])
{
	DWORD i, len;
	PVOID buffer;
	UINT lenVer;
	VS_FIXEDFILEINFO *verInfo;
	PKIWI_CABINET pCab;
	wchar_t *system, *cabname, pathc[MAX_PATH];
	DWORD dwSystem;
	char *pFile, *acabname;
	BOOL isWow64
	#ifdef _M_X64
	 = TRUE;
	NTSTATUS status;
	HMODULE hModule;
	PNTQUERYSYSTEMINFORMATIONEX pNtQuerySystemInformationEx;
	SYSTEM_ISOLATED_USER_MODE_INFORMATION iumi = {TRUE, FALSE /* 0 */};
	#else
	;
	if(IsWow64Process(GetCurrentProcess(), &isWow64))
	#endif
	{
		kprintf(
			L"\n" MIMIKATZ L" " MIMIKATZ_VERSION L" (arch " MIMIKATZ_ARCH L")\n"
			L"Windows NT %u.%u build %u (arch x%s)\n"
			L"msvc %u %u\n",
			MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER, isWow64 ? L"64" : L"86", _MSC_FULL_VER, _MSC_BUILD
			);
	}
	#ifdef _M_X64
	if((MIMIKATZ_NT_BUILD_NUMBER >= KULL_M_WIN_MIN_BUILD_10) && (hModule = GetModuleHandle(L"ntdll")))
	{
		if(pNtQuerySystemInformationEx = (PNTQUERYSYSTEMINFORMATIONEX) GetProcAddress(hModule, "NtQuerySystemInformationEx"))
		{
			status = pNtQuerySystemInformationEx(SystemIsolatedUserModeInformation, &iumi, 8, &iumi, sizeof(iumi), NULL);
			if(NT_SUCCESS(status))
			{
				if(iumi.SecureKernelRunning)
					kprintf(L"\n> SecureKernel is running\n");
				if(iumi.Spare0[0] & 1)
					kprintf(L"> Credential Guard may be running\n");
			}
			else PRINT_ERROR(L"NtQuerySystemInformationEx: %08x\n", status);
		}
	}
	#endif
	if(kull_m_string_args_byName(argc, argv, L"full", NULL, NULL))
	{
		kprintf(L"\n");
		for(i = 0; i < ARRAYSIZE(version_libs); i++)
		{
			if(len = GetFileVersionInfoSize(version_libs[i], NULL))
			{
				kprintf(L"%s\t: ", version_libs[i]);
				if(buffer = LocalAlloc(LPTR, len))
				{
					if(GetFileVersionInfo(version_libs[i], 0, len, buffer))
					{
						if(VerQueryValue(buffer, L"\\", (LPVOID *) &verInfo, &lenVer) && (verInfo->dwSignature == VS_FFI_SIGNATURE))
							kprintf(L"%hu.%hu.%hu.%hu\n", verInfo->dwFileVersionMS >> 16, verInfo->dwFileVersionMS, verInfo->dwFileVersionLS >> 16, verInfo->dwFileVersionLS);
						else PRINT_ERROR_AUTO(L"VerQueryValue");
					}
					else PRINT_ERROR_AUTO(L"GetFileVersionInfoEx");
					LocalFree(buffer);
				}
			}
		}
	}

	if(kull_m_string_args_byName(argc, argv, L"cab", NULL, NULL))
	{
		kprintf(L"\n");
		if(dwSystem = GetSystemDirectory(NULL, 0))
		{
			if(system = (wchar_t *) LocalAlloc(LPTR, dwSystem * sizeof(wchar_t)))
			{
				if(GetSystemDirectory(system, dwSystem) == (dwSystem - 1))
				{
					if(kull_m_string_sprintf(&cabname, MIMIKATZ L"_" MIMIKATZ_ARCH L"_sysfiles_%u", MIMIKATZ_NT_BUILD_NUMBER))
					{
						if(acabname = kull_m_string_unicode_to_ansi(cabname))
						{
							kprintf(L"CAB: %S\n", acabname);
							if(pCab = kull_m_cabinet_create(acabname))
							{
								for(i = 0; i < ARRAYSIZE(version_libs); i++)
								{
									if(PathCombine(pathc, system, version_libs[i]))
									{
										if(kull_m_file_isFileExist(pathc))
										{
											if(pFile = kull_m_string_unicode_to_ansi(pathc))
											{
												kprintf(L" -> %s\n", version_libs[i]);
												kull_m_cabinet_add(pCab, pFile, NULL);
												LocalFree(pFile);
											}
										}
									}
									else PRINT_ERROR_AUTO(L"PathCombine");
								}
								kull_m_cabinet_close(pCab);
							}
							LocalFree(acabname);
						}
						LocalFree(cabname);
					}
				}
				else PRINT_ERROR_AUTO(L"GetSystemDirectory(data)");
				LocalFree(system);
			}
		}
		else PRINT_ERROR_AUTO(L"GetSystemDirectory(init)");	
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_cd(int argc, wchar_t * argv[])
{
	wchar_t * buffer;
	if(kull_m_file_getCurrentDirectory(&buffer))
	{
		if(argc)
			kprintf(L"Cur: ");
		kprintf(L"%s\n", buffer);
		LocalFree(buffer);
	}
	else PRINT_ERROR_AUTO(L"kull_m_file_getCurrentDirectory");

	if(argc)
	{
		if(SetCurrentDirectory(argv[0]))
		{
			if(kull_m_file_getCurrentDirectory(&buffer))
			{
				kprintf(L"New: %s\n", buffer);
				LocalFree(buffer);
			}
			else PRINT_ERROR_AUTO(L"kull_m_file_getCurrentDirectory");
		}
		else PRINT_ERROR_AUTO(L"SetCurrentDirectory");
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_localtime(int argc, wchar_t * argv[])
{
	FILETIME ft;
	TIME_ZONE_INFORMATION tzi;
	DWORD dwTzi;
	GetSystemTimeAsFileTime(&ft);
	dwTzi = GetTimeZoneInformation(&tzi);
	kprintf(L"Local: "); kull_m_string_displayLocalFileTime(&ft); kprintf(L"\n");
	if(dwTzi != TIME_ZONE_ID_INVALID && dwTzi != TIME_ZONE_ID_UNKNOWN)
		kprintf(L"Zone : %.32s\n", (dwTzi == TIME_ZONE_ID_STANDARD) ? tzi.StandardName : tzi.DaylightName);
	kprintf(L"UTC  : "); kull_m_string_displayFileTime(&ft); kprintf(L"\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_hostname(int argc, wchar_t * argv[])
{
	wchar_t *buffer;
	if(kull_m_net_getComputerName(TRUE, &buffer))
	{
		kprintf(L"%s", buffer);
		LocalFree(buffer);
	}
	if(kull_m_net_getComputerName(FALSE, &buffer))
	{
		kprintf(L" (%s)", buffer);
		LocalFree(buffer);
	}
	kprintf(L"\n");
	return STATUS_SUCCESS;
}