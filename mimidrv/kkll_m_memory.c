/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kkll_m_memory.h"

NTSTATUS kkll_m_memory_search(const PUCHAR adresseBase, const PUCHAR adresseMaxMin, const UCHAR *pattern, PUCHAR *addressePattern, SIZE_T longueur)
{
	for(*addressePattern = adresseBase; (adresseMaxMin > adresseBase) ? (*addressePattern <= adresseMaxMin) : (*addressePattern >= adresseMaxMin); *addressePattern += (adresseMaxMin > adresseBase) ? 1 : -1)
		if(RtlEqualMemory(pattern, *addressePattern, longueur))
			return STATUS_SUCCESS;
	*addressePattern = NULL;
	return STATUS_NOT_FOUND;
}

NTSTATUS kkll_m_memory_genericPointerSearch(PUCHAR *addressePointeur, const PUCHAR adresseBase, const PUCHAR adresseMaxMin, const UCHAR *pattern, SIZE_T longueur, LONG offsetTo)
{
	NTSTATUS status = kkll_m_memory_search(adresseBase, adresseMaxMin, pattern, addressePointeur, longueur);
	if(NT_SUCCESS(status))
	{
		*addressePointeur += offsetTo;
		#if defined(_M_X64)
			*addressePointeur += sizeof(LONG) + *(PLONG)(*addressePointeur);
		#elif defined(_M_IX86)
			*addressePointeur = *(PUCHAR *)(*addressePointeur);
		#endif
		
		if(!*addressePointeur)
			status = STATUS_INVALID_HANDLE;
	}
	return status;
}

PKKLL_M_MEMORY_GENERIC kkll_m_memory_getGenericFromBuild(PKKLL_M_MEMORY_GENERIC generics, SIZE_T cbGenerics)
{
	SIZE_T i;
	for(i = 0; i < cbGenerics; i++)
		if(generics[i].OsIndex == KiwiOsIndex)
			return generics + i;
	return NULL;
}

NTSTATUS kkll_m_memory_vm_read(PVOID Dest, PVOID From, DWORD Size)
{
	NTSTATUS status = STATUS_MEMORY_NOT_ALLOCATED;
	PMDL pMdl;
	if(pMdl = IoAllocateMdl(From, Size, FALSE, FALSE, NULL))
	{
		__try
		{
			MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
			RtlCopyMemory(Dest, From, Size);
			status = STATUS_SUCCESS;
			MmUnlockPages(pMdl);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			status = GetExceptionCode();
		}
		IoFreeMdl(pMdl);
	}
	return status;
}

NTSTATUS kkll_m_memory_vm_write(PVOID Dest, PVOID From, DWORD Size)
{
	NTSTATUS status = STATUS_MEMORY_NOT_ALLOCATED;
	PMDL pMdl;
	if(pMdl = IoAllocateMdl(Dest, Size, FALSE, FALSE, NULL))
	{
		__try
		{
			MmProbeAndLockPages(pMdl, KernelMode, IoWriteAccess);
			RtlCopyMemory(Dest, From, Size);
			status = STATUS_SUCCESS;
			MmUnlockPages(pMdl);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			status = GetExceptionCode();
		}
		IoFreeMdl(pMdl);
	}
	return status;
}

NTSTATUS kkll_m_memory_vm_alloc(DWORD Size, PVOID *Addr)
{
	NTSTATUS status = STATUS_DATA_NOT_ACCEPTED;
	if(Addr)
	{
		if(*Addr = ExAllocatePoolWithTag(NonPagedPool, Size, POOL_TAG))
			status = STATUS_SUCCESS;
		else
			status = STATUS_MEMORY_NOT_ALLOCATED;
	}
	return status;
}

NTSTATUS kkll_m_memory_vm_free(PVOID Addr)
{
	NTSTATUS status = STATUS_DATA_NOT_ACCEPTED;
	if(Addr)
	{
		ExFreePoolWithTag(Addr, POOL_TAG);
		status = STATUS_SUCCESS;
	}
	return status;
}