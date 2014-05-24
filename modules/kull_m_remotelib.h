/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_file.h"

typedef struct _REMOTE_LIB_FUNC {
	DWORD	outputSize;
	PVOID	outputData;
	DWORD	inputSize;
	BYTE	inputData[ANYSIZE_ARRAY];
} REMOTE_LIB_FUNC, *PREMOTE_LIB_FUNC;

typedef struct _REMOTE_LIB_GETPROC {
	LPCSTR lpProcName;
	FARPROC addr;
} REMOTE_LIB_GETPROC, *PREMOTE_LIB_GETPROC;

BOOL CALLBACK kull_m_remotelib_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);

HMODULE kull_m_remotelib_LoadLibrary(PKULL_M_MEMORY_HANDLE hProcess, LPCWSTR lpFileName);
BOOL kull_m_remotelib_FreeLibrary(PKULL_M_MEMORY_HANDLE hProcess, HMODULE hModule);
FARPROC kull_m_remotelib_GetProcAddress(PKULL_M_MEMORY_HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName);
BOOL kull_m_remotelib_create(PKULL_M_MEMORY_ADDRESS aRemoteFunc, LPVOID inputData, DWORD inputDataSize, LPVOID *outputData, DWORD *outputDataSize, BOOL isRaw);