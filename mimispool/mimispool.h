/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include <windows.h>
#include <stdio.h>

#if defined(_M_X64) || defined(_M_ARM64) // to do, for real one day
#define PLATFORM L"x64"
#elif defined(_M_IX86)
#define PLATFORM L"x86"
#endif

typedef LONG_PTR (APIENTRY *PFN)();

typedef struct  _DRVFN {
	ULONG iFunc;
	PFN pfn;
} DRVFN, *PDRVFN;

typedef struct  tagDRVENABLEDATA {
	ULONG iDriverVersion;
	ULONG c;
	DRVFN *pdrvfn;
} DRVENABLEDATA, *PDRVENABLEDATA;

#define DRVQUERY_USERMODE 1

BOOL APIENTRY APIENTRY DrvQueryDriverInfo(DWORD   dwMode, __out_bcount(cbBuf) PVOID   pBuffer, DWORD   cbBuf, __out_ecount(1) PDWORD  pcbNeeded);
__control_entrypoint(DeviceDriver) BOOL APIENTRY DrvEnableDriver(ULONG iEngineVersion, ULONG cj, __in_bcount(cj) DRVENABLEDATA *pded);
VOID APIENTRY  DrvDisableDriver();

void kspool(LPCWSTR szFrom);
void klog(FILE * logfile, PCWCHAR format, ...);

DWORD WINAPI GenerateCopyFilePaths(LPCWSTR pszPrinterName, LPCWSTR pszDirectory, LPBYTE  pSplClientInfo, DWORD   dwLevel, LPWSTR  pszSourceDir, LPDWORD pcchSourceDirSize, LPWSTR  pszTargetDir, LPDWORD pcchTargetDirSize, DWORD dwFlags);
BOOL WINAPI SpoolerCopyFileEvent(LPWSTR pszPrinterName, LPWSTR pszKey, DWORD  dwCopyFileEvent);