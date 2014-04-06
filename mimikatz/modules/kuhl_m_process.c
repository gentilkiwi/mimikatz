/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_process.h"

const KUHL_M_C kuhl_m_c_process[] = {
	{kuhl_m_process_list,		L"list",		L"List process"},
	{kuhl_m_process_exports,	L"exports",		L"List exports"},
	{kuhl_m_process_imports,	L"imports",		L"List imports"},
	{kuhl_m_process_start,		L"start",		L"Start a process"},
	{kuhl_m_process_stop,		L"stop",		L"Terminate a process"},
	{kuhl_m_process_suspend,	L"suspend",		L"Suspend a process"},
	{kuhl_m_process_resume,		L"resume",		L"Resume a process"},
};

const KUHL_M kuhl_m_process = {
	L"process", L"Process module", NULL,
	sizeof(kuhl_m_c_process) / sizeof(KUHL_M_C), kuhl_m_c_process, NULL, NULL
};

NTSTATUS kuhl_m_process_list(int argc, wchar_t * argv[])
{
	return kull_m_process_getProcessInformation(kuhl_m_process_list_callback_process, NULL);
}

NTSTATUS kuhl_m_process_start(int argc, wchar_t * argv[])
{
	PCWCHAR commandLine;
	PROCESS_INFORMATION informations;
	if(argc)
	{
		commandLine = argv[argc - 1];
		kprintf(L"Trying to start \"%s\" : ", commandLine);
		if(kull_m_process_create(KULL_M_PROCESS_CREATE_NORMAL, commandLine, 0, NULL, 0, NULL, NULL, NULL, &informations, TRUE))
			kprintf(L"OK ! (PID %u)\n", informations.dwProcessId);
		else PRINT_ERROR_AUTO(L"kull_m_process_create");
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_process_stop(int argc, wchar_t * argv[])
{
	return kuhl_m_process_genericOperation(argc, argv, KUHL_M_PROCESS_GENERICOPERATION_TERMINATE);
}

NTSTATUS kuhl_m_process_suspend(int argc, wchar_t * argv[])
{
	return kuhl_m_process_genericOperation(argc, argv, KUHL_M_PROCESS_GENERICOPERATION_SUSPEND);
}

NTSTATUS kuhl_m_process_resume(int argc, wchar_t * argv[])
{
	return kuhl_m_process_genericOperation(argc, argv, KUHL_M_PROCESS_GENERICOPERATION_RESUME);
}

NTSTATUS kuhl_m_process_genericOperation(int argc, wchar_t * argv[], KUHL_M_PROCESS_GENERICOPERATION operation)
{
	HANDLE hProcess;
	NTSTATUS status = STATUS_NOT_FOUND;
	DWORD pid, access;
	PCWCHAR szPid, szText;

	switch(operation)
	{
	case KUHL_M_PROCESS_GENERICOPERATION_TERMINATE:
		access = PROCESS_TERMINATE;
		szText = L"NtTerminateProcess";
		break;
	case KUHL_M_PROCESS_GENERICOPERATION_SUSPEND:
		access = PROCESS_SUSPEND_RESUME;
		szText = L"NtSuspendProcess";
		break;
	case KUHL_M_PROCESS_GENERICOPERATION_RESUME:
		access = PROCESS_SUSPEND_RESUME;
		szText = L"NtResumeProcess";
		break;
	default:
		return status;
	}

	if(kull_m_string_args_byName(argc, argv, L"pid", &szPid, NULL))
		pid = wcstoul(szPid, NULL, 0);
	
	if(pid)
	{
		if(hProcess = OpenProcess(access, FALSE, pid))
		{
			switch(operation)
			{
			case KUHL_M_PROCESS_GENERICOPERATION_TERMINATE:
				status = NtTerminateProcess(hProcess, STATUS_SUCCESS);
				break;
			case KUHL_M_PROCESS_GENERICOPERATION_SUSPEND:
				status = NtSuspendProcess(hProcess);
				break;
			case KUHL_M_PROCESS_GENERICOPERATION_RESUME:
				status = NtResumeProcess(hProcess);
				break;
			}
			
			if(NT_SUCCESS(status))
				kprintf(L"%s of %u PID : OK !\n", szText, pid);
			else PRINT_ERROR(L"%s 0x%08x\n", szText, status);
			CloseHandle(hProcess);
		}
		else PRINT_ERROR_AUTO(L"OpenProcess");
	}
	else PRINT_ERROR(L"pid (/pid:123) is missing");
	return status;
}

BOOL CALLBACK kuhl_m_process_list_callback_process(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg)
{
	kprintf(L"%u\t%wZ\n", pSystemProcessInformation->UniqueProcessId, &pSystemProcessInformation->ImageName);
	return TRUE;
}

NTSTATUS kuhl_m_process_exports(int argc, wchar_t * argv[])
{
	return kuhl_m_process_callbackProcess(argc, argv, kuhl_m_process_exports_callback_module);
}

NTSTATUS kuhl_m_process_imports(int argc, wchar_t * argv[])
{
	return kuhl_m_process_callbackProcess(argc, argv, kuhl_m_process_imports_callback_module);
}

NTSTATUS kuhl_m_process_callbackProcess(int argc, wchar_t * argv[], PKULL_M_MODULE_ENUM_CALLBACK callback)
{
	HANDLE hProcess = NULL;
	DWORD pid = 0;
	KULL_M_MEMORY_TYPE type = KULL_M_MEMORY_TYPE_OWN;
	PKULL_M_MEMORY_HANDLE hMemoryProcess;
	PCWCHAR szPid;

	if(kull_m_string_args_byName(argc, argv, L"pid", &szPid, NULL))
	{
		type = KULL_M_MEMORY_TYPE_PROCESS;
		pid = wcstoul(szPid, NULL, 0);
		if(!(hProcess = OpenProcess(GENERIC_READ, FALSE, pid)))
			PRINT_ERROR_AUTO(L"OpenProcess");
	}

	if((type == KULL_M_MEMORY_TYPE_OWN) || hProcess)
	{
		if(kull_m_memory_open(type, hProcess, &hMemoryProcess))
		{
			kull_m_process_getVeryBasicModuleInformations(hMemoryProcess, callback, NULL);
			kull_m_memory_close(hMemoryProcess);
		}
		else PRINT_ERROR_AUTO(L"kull_m_memory_open");
		
		if(type = KULL_M_MEMORY_TYPE_PROCESS)
			CloseHandle(hProcess);
	}
	return STATUS_SUCCESS;
}

BOOL CALLBACK kuhl_m_process_exports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	kprintf(L"\n%wZ", pModuleInformation->NameDontUseOutsideCallback);
	kull_m_process_getExportedEntryInformations(&pModuleInformation->DllBase, kuhl_m_process_exports_callback_module_exportedEntry, pvArg);
	return TRUE;
}

BOOL CALLBACK kuhl_m_process_exports_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg)
{
	kprintf(L"\n\t%p -> %u", pExportedEntryInformations->pRva.address, pExportedEntryInformations->ordinal);
	if(pExportedEntryInformations->name)
		kprintf(L"\t%u", pExportedEntryInformations->hint);
	else
		kprintf(L"\t ");

	if((pExportedEntryInformations->function.address))
		kprintf(L"\t%p", pExportedEntryInformations->function.address);
	else
		kprintf(L"\t ");

	if(pExportedEntryInformations->name)
		kprintf(L"\t%S", pExportedEntryInformations->name);
	else
		kprintf(L"\t ");

	if(pExportedEntryInformations->redirect)
		kprintf(L"\t-> %S", pExportedEntryInformations->redirect);
	return TRUE;
}

BOOL CALLBACK kuhl_m_process_imports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	kprintf(L"\n%wZ", pModuleInformation->NameDontUseOutsideCallback);
	kull_m_process_getImportedEntryInformations(&pModuleInformation->DllBase, kuhl_m_process_imports_callback_module_importedEntry, pvArg);
	return TRUE;
}

BOOL CALLBACK kuhl_m_process_imports_callback_module_importedEntry(PKULL_M_PROCESS_IMPORTED_ENTRY pImportedEntryInformations, PVOID pvArg)
{
	kprintf(L"\n\t%p -> %p\t%S ! ", pImportedEntryInformations->pFunction.address, pImportedEntryInformations->function.address, pImportedEntryInformations->libname);
	if(pImportedEntryInformations->name)
		kprintf(L"%S", pImportedEntryInformations->name);
	else
		kprintf(L"#%u", pImportedEntryInformations->ordinal);
	return TRUE;
}