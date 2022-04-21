#pragma once
#include "kull_m_rpc.h"
/*
#define PRINTER_CHANGE_ADD_JOB	0x00000100
#define PRINTER_CHANGE_ALL		0x7777FFFF
*/
#define PRINTER_NOTIFY_CATEGORY_ALL	0x00010000
#define APD_INSTALL_WARNED_DRIVER	0x00008000

typedef void *PRINTER_HANDLE;

typedef wchar_t *STRING_HANDLE;

typedef struct _DEVMODE_CONTAINER {
	DWORD cbBuf;
	BYTE *pDevMode;
} DEVMODE_CONTAINER;

typedef struct __DRIVER_INFO_2 {
	DWORD cVersion;
	DWORD NameOffset;
	DWORD EnvironmentOffset;
	DWORD DriverPathOffset;
	DWORD DataFileOffset;
	DWORD ConfigFileOffset;
} _DRIVER_INFO_2, *_PDRIVER_INFO_2;

typedef struct _RPC_DRIVER_INFO_3 {
	DWORD cVersion;
	wchar_t *pName;
	wchar_t *pEnvironment;
	wchar_t *pDriverPath;
	wchar_t *pDataFile;
	wchar_t *pConfigFile;
	wchar_t *pHelpFile;
	wchar_t *pMonitorName;
	wchar_t *pDefaultDataType;
	DWORD cchDependentFiles;
	wchar_t *pDependentFiles;
} RPC_DRIVER_INFO_3;

typedef struct _RPC_DRIVER_INFO_4 {
    DWORD cVersion;
	wchar_t *pName;
	wchar_t *pEnvironment;
	wchar_t *pDriverPath;
	wchar_t *pDataFile;
	wchar_t *pConfigFile;
	wchar_t *pHelpFile;
	wchar_t *pMonitorName;
	wchar_t *pDefaultDataType;
	DWORD cchDependentFiles;
	wchar_t *pDependentFiles;
	DWORD cchPreviousNames;
	wchar_t *pszzPreviousNames;
} RPC_DRIVER_INFO_4;

typedef struct _RPC_DRIVER_INFO_6 {
	DWORD cVersion;
	wchar_t *pName;
	wchar_t *pEnvironment;
	wchar_t *pDriverPath;
	wchar_t *pDataFile;
	wchar_t *pConfigFile;
	wchar_t *pHelpFile;
	wchar_t *pMonitorName;
	wchar_t *pDefaultDataType;
	DWORD cchDependentFiles;
	wchar_t *pDependentFiles;
	DWORD cchPreviousNames;
	wchar_t *pszzPreviousNames;
	FILETIME ftDriverDate;
	DWORDLONG dwlDriverVersion;
	wchar_t *pMfgName;
	wchar_t *pOEMUrl;
	wchar_t *pHardwareID;
	wchar_t *pProvider;
} RPC_DRIVER_INFO_6;

typedef struct _RPC_DRIVER_INFO_8 {
	DWORD cVersion;
	wchar_t *pName;
	wchar_t *pEnvironment;
	wchar_t *pDriverPath;
	wchar_t *pDataFile;
	wchar_t *pConfigFile;
	wchar_t *pHelpFile;
	wchar_t *pMonitorName;
	wchar_t *pDefaultDataType;
	DWORD cchDependentFiles;
	wchar_t *pDependentFiles;
	DWORD cchPreviousNames;
	wchar_t *pszzPreviousNames;
	FILETIME ftDriverDate;
	DWORDLONG dwlDriverVersion;
	wchar_t *pMfgName;
	wchar_t *pOEMUrl;
	wchar_t *pHardwareID;
	wchar_t *pProvider;
	wchar_t *pPrintProcessor;
	wchar_t *pVendorSetup;
	DWORD cchColorProfiles;
	wchar_t *pszzColorProfiles;
	wchar_t *pInfPath;
	DWORD dwPrinterDriverAttributes;
	DWORD cchCoreDependencies;
	wchar_t *pszzCoreDriverDependencies;
	FILETIME ftMinInboxDriverVerDate;
	DWORDLONG dwlMinInboxDriverVerVersion;
} RPC_DRIVER_INFO_8;

typedef struct _DRIVER_CONTAINER {
	DWORD Level;
	union {
		DRIVER_INFO_1 *pNotUsed;
		DRIVER_INFO_2 *Level2;
		RPC_DRIVER_INFO_3 *Level3;
		RPC_DRIVER_INFO_4 *Level4;
		RPC_DRIVER_INFO_6 *Level6;
		RPC_DRIVER_INFO_8 *Level8;
	} DriverInfo;
} DRIVER_CONTAINER;

DWORD RpcOpenPrinter(STRING_HANDLE pPrinterName, PRINTER_HANDLE *pHandle,wchar_t *pDatatype, DEVMODE_CONTAINER *pDevModeContainer, DWORD AccessRequired);
DWORD RpcEnumPrinterDrivers(STRING_HANDLE pName,wchar_t *pEnvironment, DWORD Level, BYTE *pDrivers, DWORD cbBuf, DWORD *pcbNeeded, DWORD *pcReturned);
DWORD RpcGetPrinterDriverDirectory(STRING_HANDLE pName, wchar_t *pEnvironment, DWORD Level, BYTE *pDriverDirectory, DWORD cbBuf, DWORD *pcbNeeded);
DWORD RpcClosePrinter(PRINTER_HANDLE *phPrinter);
DWORD RpcFindClosePrinterChangeNotification(PRINTER_HANDLE hPrinter);
DWORD RpcRemoteFindFirstPrinterChangeNotification(PRINTER_HANDLE hPrinter, DWORD fdwFlags, DWORD fdwOptions, wchar_t *pszLocalMachine, DWORD dwPrinterLocal, DWORD cbBuffer, BYTE *pBuffer);
DWORD RpcDeletePrinterDriverEx(STRING_HANDLE pName, wchar_t *pEnvironment, wchar_t *pDriverName, DWORD dwDeleteFlag, DWORD dwVersionNum);
DWORD RpcAddPrinterDriverEx(STRING_HANDLE pName, DRIVER_CONTAINER *pDriverContainer, DWORD dwFileCopyFlags);

extern RPC_IF_HANDLE winspool_v1_0_c_ifspec;

handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE);
void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE, handle_t);