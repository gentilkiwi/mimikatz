/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kkll_m_modules.h"

NTSTATUS kkll_m_modules_enum(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PKKLL_M_MODULE_CALLBACK callback, PVOID pvArg)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG i, modulesSize, numberOfModules;
	PAUX_MODULE_EXTENDED_INFO pModules;
	BOOLEAN mustContinue = TRUE;

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);		
	if(NT_SUCCESS(status) && modulesSize)
	{
		if(pModules = (PAUX_MODULE_EXTENDED_INFO) ExAllocatePoolWithTag(PagedPool, modulesSize, POOL_TAG))
		{
			numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
			status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), pModules);
			for(i = 0; NT_SUCCESS(status) && mustContinue && (i < numberOfModules); i++)
				status = callback(szBufferIn, bufferIn, outBuffer, pModules + i, pvArg, &mustContinue);	
			ExFreePoolWithTag(pModules, POOL_TAG);
		}
	}
	return status;	
}

NTSTATUS kkll_m_modules_list_callback(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue)
{
	return kprintf(outBuffer, L"0x%p - %u\t%S\n", pModule->BasicInfo.ImageBase, pModule->ImageSize, pModule->FullPathName + pModule->FileNameOffset);
}

NTSTATUS kkll_m_modules_fromAddr(PKIWI_BUFFER outBuffer, PVOID addr)
{
	KKLL_M_MODULE_FROM_ADDR structAddr = {FALSE, (ULONG_PTR) addr};
	NTSTATUS status = kkll_m_modules_enum(0, NULL, outBuffer, kkll_m_modules_fromAddr_callback, &structAddr);

	if(NT_SUCCESS(status) && !structAddr.isFound)
		status = kprintf(outBuffer, L"0x%p [ ? ]\n", addr);

	return status;
}

NTSTATUS kkll_m_modules_fromAddr_callback(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue)
{
	NTSTATUS status = STATUS_SUCCESS;
	PKKLL_M_MODULE_FROM_ADDR pStructAddr = (PKKLL_M_MODULE_FROM_ADDR) pvArg;

	if((pStructAddr->addr >= (ULONG_PTR) pModule->BasicInfo.ImageBase) && (pStructAddr->addr < ((ULONG_PTR) pModule->BasicInfo.ImageBase + pModule->ImageSize)))
	{
		*mustContinue = FALSE;
		pStructAddr->isFound = TRUE;
		status = kprintf(outBuffer, L"0x%p [%S + 0x%x]\n", (PVOID) pStructAddr->addr, pModule->FullPathName + pModule->FileNameOffset, pStructAddr->addr - (ULONG_PTR) pModule->BasicInfo.ImageBase);
	}
	return status;
}

NTSTATUS kkll_m_modules_first_callback(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue)
{
	*mustContinue = FALSE;
	((PKKLL_M_MODULE_BASIC_INFOS) pvArg)->addr = (PUCHAR) pModule->BasicInfo.ImageBase;
	((PKKLL_M_MODULE_BASIC_INFOS) pvArg)->size = pModule->ImageSize;
	return STATUS_SUCCESS;
}