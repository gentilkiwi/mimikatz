/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_handle.h"

NTSTATUS kull_m_handle_getHandles(PKULL_M_SYSTEM_HANDLE_ENUM_CALLBACK callBack, PVOID pvArg)
{
	NTSTATUS status;
	ULONG i;
	PSYSTEM_HANDLE_INFORMATION buffer = NULL;

	status = kull_m_process_NtQuerySystemInformation(SystemHandleInformation, &buffer, 0);
	if(NT_SUCCESS(status))
	{
		for(i = 0; (i < buffer->HandleCount) && callBack(&buffer->Handles[i], pvArg); i++);
		LocalFree(buffer);
	}
	return status;
}

NTSTATUS kull_m_handle_getHandlesOfType(PKULL_M_HANDLE_ENUM_CALLBACK callBack, LPCTSTR type, DWORD dwDesiredAccess, DWORD dwOptions, PVOID pvArg)
{
	UNICODE_STRING uStr;
	HANDLE_ENUM_DATA data = {NULL, dwDesiredAccess, dwOptions, callBack, pvArg};
	if(type)
	{
		RtlInitUnicodeString(&uStr, type);
		data.type = &uStr;
	}
	return kull_m_handle_getHandles(kull_m_handle_getHandlesOfType_callback, &data);
}

BOOL CALLBACK kull_m_handle_getHandlesOfType_callback(PSYSTEM_HANDLE pSystemHandle, PVOID pvArg)
{
	PHANDLE_ENUM_DATA pData = (PHANDLE_ENUM_DATA) pvArg;
	BOOL status = TRUE;
	HANDLE hProcess, hRemoteHandle;
	POBJECT_TYPE_INFORMATION pInfos;
	ULONG szNeeded;

	if(hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pSystemHandle->ProcessId))
	{
		if(DuplicateHandle(hProcess, (HANDLE) pSystemHandle->Handle, GetCurrentProcess(), &hRemoteHandle, pData->dwDesiredAccess, TRUE, pData->dwOptions))
		{
			if(NtQueryObject(hRemoteHandle, ObjectTypeInformation, NULL, 0, &szNeeded) == STATUS_INFO_LENGTH_MISMATCH)
			{
				if(pInfos = (POBJECT_TYPE_INFORMATION) LocalAlloc(LPTR, szNeeded))
				{
					if(NT_SUCCESS(NtQueryObject(hRemoteHandle, ObjectTypeInformation, pInfos, szNeeded, &szNeeded)))
					{
						if(!pData->type || RtlEqualUnicodeString(&pInfos->TypeName, pData->type, TRUE))
							status = pData->callBack(hRemoteHandle, pSystemHandle, pData->pvArg);
					}
					LocalFree(pInfos);
				}
			}
			CloseHandle(hRemoteHandle);
		}
		CloseHandle(hProcess);
	}
	return status;
}

BOOL kull_m_handle_GetUserObjectInformation(HANDLE hObj, int nIndex, PVOID *pvInfo, PDWORD nLength)
{
	BOOL status = FALSE;
	DWORD szNeeded;

	if(!GetUserObjectInformation(hObj, nIndex, NULL, 0, &szNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER) && szNeeded)
	{
		if(*pvInfo = LocalAlloc(LPTR, szNeeded))
		{
			if(nLength)
				*nLength = szNeeded;
			if(!(status = GetUserObjectInformation(hObj, nIndex, *pvInfo, szNeeded, &szNeeded)))
				LocalFree(*pvInfo);
		}
	}
	return status;
}