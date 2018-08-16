/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_process.h"
#include "kuhl_m_token.h"

const KUHL_M kuhl_m_process;

typedef BOOL	(WINAPI * PINITIALIZEPROCTHREADATTRIBUTELIST) (__out_xcount_opt(*lpSize) LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, __in DWORD dwAttributeCount, __reserved DWORD dwFlags, __inout PSIZE_T lpSize);
typedef VOID	(WINAPI * PDELETEPROCTHREADATTRIBUTELIST) (__inout LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);
typedef BOOL	(WINAPI * PUPDATEPROCTHREADATTRIBUTE) (__inout LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, __in DWORD dwFlags, __in DWORD_PTR Attribute, __in_bcount_opt(cbSize) PVOID lpValue, __in SIZE_T cbSize, __out_bcount_opt(cbSize) PVOID lpPreviousValue, __in_opt PSIZE_T lpReturnSize);

typedef enum _KUHL_M_PROCESS_GENERICOPERATION {
	KUHL_M_PROCESS_GENERICOPERATION_TERMINATE,
	KUHL_M_PROCESS_GENERICOPERATION_SUSPEND,
	KUHL_M_PROCESS_GENERICOPERATION_RESUME,
} KUHL_M_PROCESS_GENERICOPERATION, *PKUHL_M_PROCESS_GENERICOPERATION;

NTSTATUS kuhl_m_process_genericOperation(int argc, wchar_t * argv[], KUHL_M_PROCESS_GENERICOPERATION operation);

NTSTATUS kuhl_m_process_list(int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_process_list_callback_process(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);

NTSTATUS kuhl_m_process_callbackProcess(int argc, wchar_t * argv[], PKULL_M_MODULE_ENUM_CALLBACK callback);

NTSTATUS kuhl_m_process_exports(int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_process_exports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_process_exports_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);

NTSTATUS kuhl_m_process_imports(int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_process_imports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_process_imports_callback_module_importedEntry(PKULL_M_PROCESS_IMPORTED_ENTRY pImportedEntryInformations, PVOID pvArg);

NTSTATUS kuhl_m_process_start(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_process_stop(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_process_suspend(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_process_resume(int argc, wchar_t * argv[]);

BOOL kull_m_process_run_data(LPCWSTR commandLine, HANDLE hToken);
NTSTATUS kuhl_m_process_run(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_process_runParent(int argc, wchar_t * argv[]);