/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_remotelib.h"

PREMOTE_LIB_INPUT_DATA kull_m_remotelib_CreateInput(PVOID inputVoid, DWORD inputDword, DWORD inputSize, LPCVOID inputData)
{
	PREMOTE_LIB_INPUT_DATA iData;
	if(iData = (PREMOTE_LIB_INPUT_DATA) LocalAlloc(LPTR, FIELD_OFFSET(REMOTE_LIB_INPUT_DATA, inputData) + inputSize))
	{
		iData->inputVoid = inputVoid;
		iData->inputDword = inputDword;
		if(inputSize && inputData)
		{
			iData->inputSize = inputSize;
			RtlCopyMemory(iData->inputData, inputData, inputSize);
		}
	}
	return iData;
}

BOOL kull_m_remotelib_create(PKULL_M_MEMORY_ADDRESS aRemoteFunc, PREMOTE_LIB_INPUT_DATA input, PREMOTE_LIB_OUTPUT_DATA output)
{
	BOOL success = FALSE;
	NTSTATUS status;
	HANDLE hThread;
	KULL_M_MEMORY_ADDRESS aRemoteData = {NULL, aRemoteFunc->hMemory}, aSuppData = {NULL, aRemoteFunc->hMemory}, aLocalAddr = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	PREMOTE_LIB_DATA data;
	REMOTE_LIB_OUTPUT_DATA oData;
	MIMIDRV_THREAD_INFO drvInfo = {(PTHREAD_START_ROUTINE) aRemoteFunc->address, NULL};
	DWORD size = FIELD_OFFSET(REMOTE_LIB_DATA, input.inputData) + input->inputSize;

	if(!output)
		output = &oData;
	//kprintf(L"\ninput\n"
	//	L".void   = 0x%p\n"
	//	L".dword  = 0x%08x - %u\n"
	//	L".size   = %u\n"
	//	L".data[] = [ ",
	//	input->inputVoid, input->inputDword, input->inputDword, input->inputSize);
	//kull_m_string_wprintf_hex(input->inputData, input->inputSize, 1);
	//kprintf(L"]\n");
	if(data = (PREMOTE_LIB_DATA) LocalAlloc(LPTR, size))
	{
		RtlCopyMemory(&data->input, input, FIELD_OFFSET(REMOTE_LIB_INPUT_DATA, inputData) + input->inputSize);
		if(kull_m_memory_alloc(&aRemoteData, size, PAGE_READWRITE))
		{
			aLocalAddr.address = data;
			if(kull_m_memory_copy(&aRemoteData, &aLocalAddr, size))
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
					aLocalAddr.address = output;
					if(success = kull_m_memory_copy(&aLocalAddr, &aRemoteData, sizeof(REMOTE_LIB_OUTPUT_DATA)))
					{
						//kprintf(L"\noutput\n"
						//	L".void   = 0x%p\n"
						//	L".dword  = 0x%08x - %u\n"
						//	L".status = 0x%08x - %u\n"
						//	L".size   = %u\n"
						//	L".data   = 0x%p\n",
						//	output->outputVoid, output->outputDword, output->outputDword, output->outputStatus, output->outputStatus, output->outputSize, output->outputData);
						if(aSuppData.address = output->outputData)
						{
							if(output != &oData)
							{
								success = FALSE;
								output->outputData = NULL;
								if(output->outputSize)
								{
									if(aLocalAddr.address = LocalAlloc(LPTR, output->outputSize))
									{
										if(success = kull_m_memory_copy(&aLocalAddr, &aSuppData, output->outputSize))
										{
											output->outputData = aLocalAddr.address;
											//kprintf(L"\t[ "); kull_m_string_wprintf_hex(output->outputData, output->outputSize, 1); kprintf(L"]\n");
										}
										else
											LocalFree(aLocalAddr.address);
									}
								}
								if(!success)
									output->outputSize = 0;
							}
							kull_m_memory_free(&aSuppData);
						}
					}
				}
			}
			kull_m_memory_free(&aRemoteData);
		}
		LocalFree(data);
	}
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
	KULL_M_MEMORY_ADDRESS aLocalAddr = {(LPVOID) Buffer, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	
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
				kull_m_memory_free(DestAddress);
			}
		}
		else PRINT_ERROR_AUTO(L"kull_m_memory_alloc / VirtualAlloc(Ex)");

		if(RemoteExt)
			LocalFree(aLocalAddr.address);
	}
	else PRINT_ERROR(L"No buffer ?\n");
	return success;
}