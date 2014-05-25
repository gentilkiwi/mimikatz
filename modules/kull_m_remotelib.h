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

typedef struct _REMOTE_EXT {
	PCWCHAR	Module;
	PCHAR	Function;
	PVOID	ToReplace;
	PVOID	Pointer;
} REMOTE_EXT, *PREMOTE_EXT;

typedef struct _MULTIPLE_REMOTE_EXT {
	DWORD count;
	PREMOTE_EXT extensions;
} MULTIPLE_REMOTE_EXT, *PMULTIPLE_REMOTE_EXT;

BOOL CALLBACK kull_m_remotelib_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);

HMODULE kull_m_remotelib_LoadLibrary(PKULL_M_MEMORY_HANDLE hProcess, LPCWSTR lpFileName);
BOOL kull_m_remotelib_FreeLibrary(PKULL_M_MEMORY_HANDLE hProcess, HMODULE hModule);
FARPROC kull_m_remotelib_GetProcAddress(PKULL_M_MEMORY_HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName);
BOOL kull_m_remotelib_create(PKULL_M_MEMORY_ADDRESS aRemoteFunc, LPVOID inputData, DWORD inputDataSize, LPVOID *outputData, DWORD *outputDataSize, BOOL isRaw);

BOOL CALLBACK kull_m_remotelib_exports_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);
BOOL CALLBACK kull_m_remotelib_exports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL kull_m_remotelib_GetProcAddressMultipleModules(PKULL_M_MEMORY_HANDLE hProcess, PMULTIPLE_REMOTE_EXT extForCb);
BOOL kull_m_remotelib_CreateRemoteCodeWitthPatternReplace(PKULL_M_MEMORY_HANDLE hProcess, LPCVOID Buffer, DWORD BufferSize, PMULTIPLE_REMOTE_EXT RemoteExt, PKULL_M_MEMORY_ADDRESS DestAddress);