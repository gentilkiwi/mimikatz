/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kkll_m_ssdt.h"

#ifdef _M_X64
PSERVICE_DESCRIPTOR_TABLE			KeServiceDescriptorTable = NULL;
#endif

NTSTATUS kkll_m_ssdt_list(PKIWI_BUFFER outBuffer)
{
	NTSTATUS status;
	USHORT idxFunction;
	ULONG_PTR funcAddr;

#ifdef _M_X64
	status = kkll_m_ssdt_getKeServiceDescriptorTable();
	if(NT_SUCCESS(status))
	{
#endif
		status = kprintf(outBuffer, L"KeServiceDescriptorTable : 0x%p (%u)\n", KeServiceDescriptorTable, KeServiceDescriptorTable->TableSize);
		for(idxFunction = 0; (idxFunction < KeServiceDescriptorTable->TableSize) && NT_SUCCESS(status) ; idxFunction++)
		{
#ifdef _M_IX86
			funcAddr = (ULONG_PTR) KeServiceDescriptorTable->ServiceTable[idxFunction];
#else
			funcAddr = (ULONG_PTR) KeServiceDescriptorTable->OffsetToService;
			if(KiwiOsIndex < KiwiOsIndex_VISTA)
				funcAddr += KeServiceDescriptorTable->OffsetToService[idxFunction] & ~EX_FAST_REF_MASK;
			else
				funcAddr += KeServiceDescriptorTable->OffsetToService[idxFunction] >> 4;
#endif
			status = kprintf(outBuffer, L"[%5u] ", idxFunction);
			if(NT_SUCCESS(status))
				status = kkll_m_modules_fromAddr(outBuffer, (PVOID) funcAddr);
		}
#ifdef _M_X64
	}
#endif
	return status;
}

#ifdef _M_X64
NTSTATUS kkll_m_ssdt_getKeServiceDescriptorTable()
{
	NTSTATUS status = STATUS_NOT_FOUND;
	UCHAR PTRN_WALL_Ke[]	= {0x00, 0x00, 0x4d, 0x0f, 0x45, 0xd3, 0x42, 0x3b, 0x44, 0x17, 0x10, 0x0f, 0x83};
	LONG OFFS_WNO8_Ke		= -19;
	LONG OFFS_WIN8_Ke		= -16;

	if(KeServiceDescriptorTable)
		status = STATUS_SUCCESS;
	else
		status = kkll_m_memory_genericPointerSearch((PUCHAR *) &KeServiceDescriptorTable, ((PUCHAR) ZwUnloadKey) - (21 * PAGE_SIZE), ((PUCHAR) ZwUnloadKey) + (16 * PAGE_SIZE), PTRN_WALL_Ke, sizeof(PTRN_WALL_Ke), (KiwiOsIndex < KiwiOsIndex_8) ? OFFS_WNO8_Ke : OFFS_WIN8_Ke);
	return status;
}
#endif