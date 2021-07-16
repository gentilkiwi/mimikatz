#pragma once
#include "kull_m_rpc.h"
/*
#define PRINTER_CHANGE_ADD_JOB	0x00000100
#define PRINTER_CHANGE_ALL		0x7777FFFF
*/
#define PRINTER_NOTIFY_CATEGORY_ALL	0x00010000

typedef void *PRINTER_HANDLE;

typedef wchar_t *STRING_HANDLE;

typedef struct _DEVMODE_CONTAINER {
	DWORD cbBuf;
	BYTE *pDevMode;
} DEVMODE_CONTAINER;

DWORD RpcOpenPrinter(STRING_HANDLE pPrinterName, PRINTER_HANDLE *pHandle, wchar_t *pDatatype, DEVMODE_CONTAINER *pDevModeContainer, DWORD AccessRequired);
DWORD RpcClosePrinter(PRINTER_HANDLE *phPrinter);
DWORD RpcFindClosePrinterChangeNotification(PRINTER_HANDLE hPrinter);
DWORD RpcRemoteFindFirstPrinterChangeNotification(PRINTER_HANDLE hPrinter, DWORD fdwFlags, DWORD fdwOptions, wchar_t *pszLocalMachine, DWORD dwPrinterLocal, DWORD cbBuffer, BYTE *pBuffer);

extern RPC_IF_HANDLE winspool_v1_0_c_ifspec;

handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE);
void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE, handle_t);