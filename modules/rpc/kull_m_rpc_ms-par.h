#pragma once
#include "kull_m_rpc.h"
#include "kull_m_rpc_ms-rprn.h"

const UUID PAR_ObjectUUID;

typedef struct _SPLCLIENT_INFO_1 {
	DWORD dwSize;
	DWORD dwBuildNum;
	DWORD dwMajorVersion;
	DWORD dwMinorVersion;
	unsigned short wProcessorArchitecture;
} SPLCLIENT_INFO_1;

typedef struct _SPLCLIENT_INFO_2 {
	LONG_PTR notUsed;
} SPLCLIENT_INFO_2;

typedef struct _SPLCLIENT_INFO_3 {
	unsigned int cbSize;
	DWORD dwFlags;
	DWORD dwSize;
	wchar_t *pMachineName;
	wchar_t *pUserName;
	DWORD dwBuildNum;
	DWORD dwMajorVersion;
	DWORD dwMinorVersion;
	unsigned short wProcessorArchitecture;
	unsigned __int64 hSplPrinter;
} SPLCLIENT_INFO_3;

typedef struct _SPLCLIENT_CONTAINER {
	DWORD Level;
	union  {
		SPLCLIENT_INFO_1 *pClientInfo1;
		SPLCLIENT_INFO_2 *pNotUsed;
		SPLCLIENT_INFO_3 *pClientInfo3;
	} 	ClientInfo;
} SPLCLIENT_CONTAINER;

DWORD RpcAsyncOpenPrinter(handle_t hRemoteBinding, wchar_t *pPrinterName, PRINTER_HANDLE *pHandle, wchar_t *pDatatype, DEVMODE_CONTAINER *pDevModeContainer, DWORD AccessRequired, SPLCLIENT_CONTAINER *pClientInfo);
DWORD RpcAsyncClosePrinter(PRINTER_HANDLE *phPrinter);
DWORD RpcAsyncAddPrinterDriver(handle_t hRemoteBinding, wchar_t *pName, DRIVER_CONTAINER *pDriverContainer, DWORD dwFileCopyFlags);
DWORD RpcAsyncEnumPrinterDrivers(handle_t hRemoteBinding, wchar_t *pName, wchar_t *pEnvironment, DWORD Level, unsigned char *pDrivers, DWORD cbBuf, DWORD *pcbNeeded, DWORD *pcReturned);
DWORD RpcAsyncGetPrinterDriverDirectory(handle_t hRemoteBinding, wchar_t *pName, wchar_t *pEnvironment, DWORD Level, unsigned char *pDriverDirectory, DWORD cbBuf, DWORD *pcbNeeded);
DWORD RpcAsyncDeletePrinterDriverEx(handle_t hRemoteBinding, wchar_t *pName, wchar_t *pEnvironment, wchar_t *pDriverName, DWORD dwDeleteFlag, DWORD dwVersionNum);