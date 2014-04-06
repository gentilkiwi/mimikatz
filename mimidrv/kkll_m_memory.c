/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kkll_m_memory.h"

NTSTATUS kkll_m_memory_search(const PUCHAR adresseBase, const PUCHAR adresseMaxMin, const PUCHAR pattern, PUCHAR *addressePattern, SIZE_T longueur)
{
	for(*addressePattern = adresseBase; (adresseMaxMin > adresseBase) ? (*addressePattern <= adresseMaxMin) : (*addressePattern >= adresseMaxMin); *addressePattern += (adresseMaxMin > adresseBase) ? 1 : -1)
		if(RtlEqualMemory(pattern, *addressePattern, longueur))
			return STATUS_SUCCESS;
	*addressePattern = NULL;
	return STATUS_NOT_FOUND;
}

NTSTATUS kkll_m_memory_genericPointerSearch(PUCHAR *addressePointeur, const PUCHAR adresseBase, const PUCHAR adresseMaxMin, const PUCHAR pattern, SIZE_T longueur, LONG offsetTo)
{
	NTSTATUS status = kkll_m_memory_search(adresseBase, adresseMaxMin, pattern, addressePointeur, longueur);
	if(NT_SUCCESS(status))
	{
		*addressePointeur += offsetTo;
		#ifdef _M_X64
			*addressePointeur += sizeof(LONG) + *(PLONG)(*addressePointeur);
		#elif defined _M_IX86
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