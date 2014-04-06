/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kull_m_kernel.h"

BOOL kull_m_kernel_ioctl(PCWSTR driver, DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut)
{
	BOOL status = FALSE;
	HANDLE hDriver;
	DWORD lStatus = ERROR_MORE_DATA, returned;

	hDriver = CreateFile(driver, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if(hDriver && hDriver != INVALID_HANDLE_VALUE)
	{
		for(*pSzBufferOut = 0x10000; (lStatus == ERROR_MORE_DATA) && (*pBufferOut = LocalAlloc(LPTR, *pSzBufferOut)) ; *pSzBufferOut <<= 1)
		{
			if(status = DeviceIoControl(hDriver, ioctlCode, bufferIn, szBufferIn, *pBufferOut, *pSzBufferOut, &returned, NULL))
				lStatus = ERROR_SUCCESS;
			else
			{
				lStatus = GetLastError();
				LocalFree(*pBufferOut);
			}
		}
		if(lStatus)
		{
			PRINT_ERROR(L"DeviceIoControl (0x%08x) : 0x%08x\n", ioctlCode, lStatus);
			SetLastError(lStatus);
		}
		else *pSzBufferOut = returned;
		CloseHandle(hDriver);
	}
	else PRINT_ERROR_AUTO(L"CreateFile");
	return status;
}

BOOL kull_m_kernel_mimidrv_ioctl(DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut)
{
	return kull_m_kernel_ioctl(L"\\\\.\\" MIMIKATZ_DRIVER, ioctlCode, bufferIn, szBufferIn, pBufferOut, pSzBufferOut);
}

BOOL kull_m_kernel_mimidrv_simple_output(DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn)
{
	BOOL status = FALSE;
	PVOID buffer;
	DWORD i, szBuffer;

	if(status = kull_m_kernel_ioctl(L"\\\\.\\" MIMIKATZ_DRIVER, ioctlCode, bufferIn, szBufferIn, &buffer, &szBuffer))
	{
		for(i = 0; i < szBuffer / sizeof(wchar_t); i++)
			kprintf(L"%c", ((wchar_t *) buffer)[i]);
		LocalFree(buffer);
	}
	return status;
}

BOOL kull_m_kernel_mimidrv_raw(DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID pBufferOut, DWORD pSzBufferOut)
{
	BOOL status = FALSE;
	HANDLE hDriver;
	DWORD szOut;

	hDriver = CreateFile(L"\\\\.\\" MIMIKATZ_DRIVER, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if(hDriver && hDriver != INVALID_HANDLE_VALUE)
	{
		status = DeviceIoControl(hDriver, ioctlCode, bufferIn, szBufferIn, pBufferOut, pSzBufferOut, &szOut, NULL);
		CloseHandle(hDriver);
	}
	return status;
}